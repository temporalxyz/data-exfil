//! Bounded shape statistics. Estimates are never used as validation gates.
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

use arrow_array::RecordBatch;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::validation::hex;
use crate::abort::{Result, abort};

const SAMPLE: usize = 256;

#[derive(Default)]
struct Sketch(BTreeSet<u64>);
impl Sketch {
    fn add(&mut self, hash: u64) {
        if self.0.len() == SAMPLE && self.0.last().is_some_and(|largest| hash >= *largest) {
            return;
        }
        self.0.insert(hash);
        if self.0.len() > SAMPLE {
            self.0.pop_last();
        }
    }
    fn estimate(&self) -> u64 {
        if self.0.len() < SAMPLE {
            self.0.len() as u64
        } else {
            (((SAMPLE - 1) as f64 * u64::MAX as f64) / (*self.0.last().unwrap()).max(1) as f64)
                as u64
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnSummary {
    pub name: String,
    pub nulls: u64,
    pub min_display_bytes: usize,
    pub max_display_bytes: usize,
    pub distinct_estimate: u64,
    /// Bounded escaped samples; counts have the Space Saving overestimate error bound.
    pub frequent: Vec<(String, u64, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub rows: u64,
    pub duplicate_rows_estimate: u64,
    pub method: String,
    pub columns: Vec<ColumnSummary>,
}

pub struct Profile {
    rows: u64,
    rows_seen: Sketch,
    columns: Vec<ColumnSummary>,
    seen: Vec<Sketch>,
    top: Vec<Frequent>,
}

// Sorted by hash to preserve the reference's tie-breaking and report ordering.
// Sixteen reusable sample buffers: no tree-node or sample allocation on eviction.
struct Frequent(Vec<(u64, (String, u64, u64))>);
impl Frequent {
    fn add(&mut self, key: u64, bytes: &[u8]) {
        if let Ok(at) = self.0.binary_search_by_key(&key, |(hash, _)| *hash) {
            self.0[at].1.1 += 1;
            return;
        }
        let (mut sample, floor) = if self.0.len() == 16 {
            let victim = self
                .0
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, (_, count, _)))| *count)
                .unwrap()
                .0;
            let (_, (sample, count, _)) = self.0.remove(victim);
            (sample, count)
        } else {
            (String::with_capacity(128), 0)
        };
        sample.clear();
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &byte in &bytes[..bytes.len().min(64)] {
            sample.push(HEX[(byte >> 4) as usize] as char);
            sample.push(HEX[(byte & 15) as usize] as char);
        }
        let at = self
            .0
            .binary_search_by_key(&key, |(hash, _)| *hash)
            .unwrap_err();
        self.0.insert(at, (key, (sample, floor + 1, floor)));
    }
}

fn hash(bytes: &[u8]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

impl Profile {
    pub fn new(names: impl Iterator<Item = String>) -> Self {
        let columns: Vec<_> = names
            .map(|name| ColumnSummary {
                name,
                nulls: 0,
                min_display_bytes: usize::MAX,
                max_display_bytes: 0,
                distinct_estimate: 0,
                frequent: Vec::new(),
            })
            .collect();
        let count = columns.len();
        Self {
            rows: 0,
            rows_seen: Sketch::default(),
            columns,
            seen: (0..count).map(|_| Sketch::default()).collect(),
            top: (0..count)
                .map(|_| Frequent(Vec::with_capacity(16)))
                .collect(),
        }
    }

    pub fn add(&mut self, batch: &RecordBatch, kept: &[usize]) -> Result<()> {
        let options = arrow_cast::display::FormatOptions::default();
        let formatters: Vec<_> = kept
            .iter()
            .map(|index| {
                let array = batch.column(*index);
                if array.null_count() == array.len() {
                    return Ok(None);
                }
                arrow_cast::display::ArrayFormatter::try_new(array.as_ref(), &options)
                    .map(Some)
                    .map_err(|_| profile_error())
            })
            .collect::<Result<_>>()?;
        let mut text = String::new();
        for row in 0..batch.num_rows() {
            self.rows += 1;
            let mut row_hash = std::collections::hash_map::DefaultHasher::new();
            for (slot, index) in kept.iter().enumerate() {
                let array = batch.column(*index);
                if array.is_null(row) {
                    self.columns[slot].nulls += 1;
                    0u8.hash(&mut row_hash);
                    continue;
                }
                1u8.hash(&mut row_hash);
                text.clear();
                formatters[slot]
                    .as_ref()
                    .expect("non-null column formatter")
                    .value(row)
                    .write(&mut text)
                    .map_err(|_| profile_error())?;
                text.hash(&mut row_hash);
                let col = &mut self.columns[slot];
                col.min_display_bytes = col.min_display_bytes.min(text.len());
                col.max_display_bytes = col.max_display_bytes.max(text.len());
                let key = hash(text.as_bytes());
                self.seen[slot].add(key);
                self.top[slot].add(key, text.as_bytes());
            }
            self.rows_seen.add(row_hash.finish());
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn add_reference(&mut self, batch: &RecordBatch, kept: &[usize]) -> Result<()> {
        for row in 0..batch.num_rows() {
            self.rows += 1;
            let mut row_hash = std::collections::hash_map::DefaultHasher::new();
            for (slot, index) in kept.iter().enumerate() {
                let array = batch.column(*index);
                if array.is_null(row) {
                    self.columns[slot].nulls += 1;
                    0u8.hash(&mut row_hash);
                    continue;
                }
                1u8.hash(&mut row_hash);
                let text = arrow_cast::display::array_value_to_string(array.as_ref(), row)
                    .map_err(|_| profile_error())?;
                text.hash(&mut row_hash);
                let col = &mut self.columns[slot];
                col.min_display_bytes = col.min_display_bytes.min(text.len());
                col.max_display_bytes = col.max_display_bytes.max(text.len());
                let key = hash(text.as_bytes());
                self.seen[slot].add(key);
                let mut top: BTreeMap<_, _> = self.top[slot].0.iter().cloned().collect();
                if let Some(entry) = top.get_mut(&key) {
                    entry.1 += 1;
                } else {
                    let floor = if top.len() == 16 {
                        let victim = *top.iter().min_by_key(|(_, (_, count, _))| count).unwrap().0;
                        top.remove(&victim).unwrap().1
                    } else {
                        0
                    };
                    top.insert(
                        key,
                        (
                            hex(&text.as_bytes()[..text.len().min(64)]),
                            floor + 1,
                            floor,
                        ),
                    );
                }
                self.top[slot].0 = top.into_iter().collect();
            }
            self.rows_seen.add(row_hash.finish());
        }
        Ok(())
    }

    pub fn finish(mut self) -> Summary {
        for (i, col) in self.columns.iter_mut().enumerate() {
            col.distinct_estimate = self.seen[i].estimate().min(self.rows - col.nulls);
            if col.min_display_bytes == usize::MAX {
                col.min_display_bytes = 0;
            }
            col.frequent = self.top[i]
                .0
                .iter()
                .map(|(_, value)| value.clone())
                .collect();
            col.frequent
                .sort_by_key(|(_, count, _)| std::cmp::Reverse(*count));
        }
        Summary { rows: self.rows, duplicate_rows_estimate: self.rows.saturating_sub(self.rows_seen.estimate()), method: "KMV-256 distinct/duplicate estimates; SpaceSaving-16 frequent values (hex sample, estimated count, maximum overcount); lengths measure display bytes; row/null counts exact".into(), columns: self.columns }
    }
}

fn profile_error() -> crate::abort::SalvageError {
    abort::<()>("native Parquet shape profiling could not format a value").unwrap_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequent_evictions_reuse_buffers_and_match_reference() {
        let mut fast = Frequent(Vec::with_capacity(16));
        let mut reference = BTreeMap::<u64, (String, u64, u64)>::new();
        let mut buffers = BTreeSet::new();
        for i in 0u64..5000 {
            let key = (i.wrapping_mul(73) / 3) % 31;
            let sample = vec![i as u8; (i % 100) as usize];
            fast.add(key, &sample);
            if let Some(entry) = reference.get_mut(&key) {
                entry.1 += 1;
            } else {
                let floor = if reference.len() == 16 {
                    let victim = *reference
                        .iter()
                        .min_by_key(|(_, (_, count, _))| count)
                        .unwrap()
                        .0;
                    reference.remove(&victim).unwrap().1
                } else {
                    0
                };
                reference.insert(
                    key,
                    (hex(&sample[..sample.len().min(64)]), floor + 1, floor),
                );
            }
            assert_eq!(
                fast.0,
                reference
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect::<Vec<_>>()
            );
            if fast.0.len() == 16 {
                let current: BTreeSet<_> = fast
                    .0
                    .iter()
                    .map(|(_, (s, _, _))| s.as_ptr() as usize)
                    .collect();
                if buffers.is_empty() {
                    buffers = current;
                } else {
                    assert_eq!(current, buffers);
                }
            }
        }
    }

    #[test]
    fn sketch_early_rejection_preserves_exact_sample() {
        let mut fast = Sketch::default();
        let mut reference = BTreeSet::new();
        for i in 0u64..10_000 {
            let value = hash(&(i % 1700).to_le_bytes());
            fast.add(value);
            reference.insert(value);
            if reference.len() > SAMPLE {
                reference.pop_last();
            }
            assert_eq!(fast.0, reference);
        }
    }
}

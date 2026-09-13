//! Bounded shape statistics. Estimates are never used as validation gates.
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use arrow_array::RecordBatch;
use serde::{Deserialize, Serialize};

use super::{finding_error, validation::hex};
use crate::abort::Result;

const SAMPLE: usize = 256;

#[derive(Default)]
struct Sketch(BTreeSet<u64>);
impl Sketch {
    fn add(&mut self, hash: u64) {
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
    top: Vec<BTreeMap<u64, (String, u64, u64)>>,
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
            top: vec![BTreeMap::new(); count],
        }
    }

    pub fn add(&mut self, batch: &RecordBatch, kept: &[usize]) -> Result<()> {
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
                    .map_err(finding_error)?;
                text.hash(&mut row_hash);
                let col = &mut self.columns[slot];
                col.min_display_bytes = col.min_display_bytes.min(text.len());
                col.max_display_bytes = col.max_display_bytes.max(text.len());
                let key = hash(text.as_bytes());
                self.seen[slot].add(key);
                let top = &mut self.top[slot];
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
            col.frequent = self.top[i].values().cloned().collect();
            col.frequent
                .sort_by_key(|(_, count, _)| std::cmp::Reverse(*count));
        }
        Summary { rows: self.rows, duplicate_rows_estimate: self.rows.saturating_sub(self.rows_seen.estimate()), method: "KMV-256 distinct/duplicate estimates; SpaceSaving-16 frequent values (hex sample, estimated count, maximum overcount); lengths measure display bytes; row/null counts exact".into(), columns: self.columns }
    }
}

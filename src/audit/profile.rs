//! Section 9's shape review: the last look before promotion.
//!
//! > Staging is the last point where the data can be examined in isolation -- no consumer
//! > attached, nothing downstream depending on it.
//!
//! Eight measurements, verbatim from the document, and the document is unusually blunt about their
//! worth -- which is why `SHAPE-REVIEW.md` quotes it rather than paraphrasing:
//!
//! > **Catches:** clumsy work -- a column gone constant, timestamps that stop dead, identifiers
//! > that repeat, magnitudes suddenly uniform, counts matching no real day.
//! > **Does not catch:** careful tampering. **A clean profile proves nothing.**
//!
//! # Computed here, not queried
//!
//! Section 9 profiles the staging table with SQL. This computes the same measurements from the
//! values **we** parsed, which is strictly better placed: the dummy database is fed by us and
//! could be lied to by a compromised Q2, whereas these numbers come from the bytes that will
//! actually ship. The equivalent SQL is emitted alongside so a reviewer can run it against staging
//! and compare -- two independent derivations of the same numbers, which is the nearest thing to a
//! second opinion this topology has.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::clickhouse::tsv::Field;

/// One column's measurements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnProfile {
    pub name: String,
    pub rows: u64,
    pub nulls: u64,
    /// `uniqExact`. A spike suggests injected values, a collapse suggests fabrication.
    pub distinct: u64,
    pub min_len: usize,
    pub max_len: usize,
    /// Lexicographic min and max, which for the numeric and temporal export forms is also the
    /// ordering a reviewer wants -- integers are fixed-width decimal and timestamps sort as text.
    pub min_value: Option<String>,
    pub max_value: Option<String>,
    /// The five commonest values and their counts.
    pub top: Vec<(String, u64)>,
}

impl ColumnProfile {
    /// Whether every non-null value is identical. A column gone constant is the single loudest
    /// signal in the whole review.
    #[must_use]
    pub fn is_constant(&self) -> bool {
        self.distinct <= 1 && self.rows > 1
    }

    #[must_use]
    pub fn null_rate(&self) -> f64 {
        if self.rows == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            self.nulls as f64 / self.rows as f64
        }
    }
}

/// The whole page's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub table: String,
    pub batch: String,
    pub rows: u64,
    pub columns: Vec<ColumnProfile>,
    /// Rows whose full field tuple is a duplicate of an earlier row.
    pub duplicate_rows: u64,
}

/// Measure a page.
#[must_use]
pub fn profile(table: &str, batch: &str, header: &[String], rows: &[Vec<Field>]) -> Profile {
    let mut columns: Vec<ColumnProfile> = header
        .iter()
        .map(|name| ColumnProfile {
            name: name.clone(),
            rows: 0,
            nulls: 0,
            distinct: 0,
            min_len: usize::MAX,
            max_len: 0,
            min_value: None,
            max_value: None,
            top: Vec::new(),
        })
        .collect();

    let mut counters: Vec<BTreeMap<String, u64>> = vec![BTreeMap::new(); header.len()];
    let mut seen_rows: BTreeMap<String, u64> = BTreeMap::new();
    let mut duplicate_rows = 0u64;

    for row in rows {
        let mut key = String::new();
        for (i, field) in row.iter().enumerate() {
            let Some(col) = columns.get_mut(i) else {
                continue;
            };
            col.rows = col.rows.saturating_add(1);

            match field {
                Field::Null => {
                    col.nulls = col.nulls.saturating_add(1);
                    key.push_str("\u{0}N\u{1}");
                }
                Field::Value(bytes) => {
                    let text = String::from_utf8_lossy(bytes).into_owned();
                    col.min_len = col.min_len.min(bytes.len());
                    col.max_len = col.max_len.max(bytes.len());
                    match &col.min_value {
                        Some(m) if *m <= text => {}
                        _ => col.min_value = Some(text.clone()),
                    }
                    match &col.max_value {
                        Some(m) if *m >= text => {}
                        _ => col.max_value = Some(text.clone()),
                    }
                    if let Some(c) = counters.get_mut(i) {
                        *c.entry(text.clone()).or_insert(0) += 1;
                    }
                    key.push_str(&text);
                    key.push('\u{1}');
                }
            }
        }
        let entry = seen_rows.entry(key).or_insert(0);
        *entry = entry.saturating_add(1);
        if *entry > 1 {
            duplicate_rows = duplicate_rows.saturating_add(1);
        }
    }

    for (i, col) in columns.iter_mut().enumerate() {
        if col.min_len == usize::MAX {
            col.min_len = 0;
        }
        let Some(counts) = counters.get(i) else {
            continue;
        };
        col.distinct = u64::try_from(counts.len()).unwrap_or(u64::MAX);
        let mut top: Vec<(String, u64)> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        // Descending by count, then by value so the output is stable between runs.
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top.truncate(5);
        col.top = top;
    }

    Profile {
        table: table.to_owned(),
        batch: batch.to_owned(),
        rows: u64::try_from(rows.len()).unwrap_or(u64::MAX),
        columns,
        duplicate_rows,
    }
}

/// Render `SHAPE-REVIEW.md`.
#[must_use]
pub fn render_markdown(p: &Profile) -> String {
    let mut md = String::new();
    let w = &mut md;

    let _ = writeln!(w, "# Shape review -- `{}`, batch `{}`\n", p.table, p.batch);
    let _ = writeln!(
        w,
        "> **This is a smell test, not a check.** Section 9, verbatim: *\"Catches: clumsy work -- a \
         column gone constant, timestamps that stop dead, identifiers that repeat, magnitudes \
         suddenly uniform, counts matching no real day. Does not catch: careful tampering. **A \
         clean profile proves nothing.**\"*\n"
    );
    let _ = writeln!(
        w,
        "> It is *\"a smell test by someone who knows the data, recorded as a reviewed artifact \
         rather than a passed check.\"* Signing it off is a human act; nothing here does it for \
         you.\n"
    );

    let _ = writeln!(w, "- Rows: **{}**", p.rows);
    let _ = writeln!(
        w,
        "- Duplicate rows: **{}**{}\n",
        p.duplicate_rows,
        if p.duplicate_rows > 0 {
            "  <- expected zero on anything unique"
        } else {
            ""
        }
    );

    let constant: Vec<&str> = p
        .columns
        .iter()
        .filter(|c| c.is_constant())
        .map(|c| c.name.as_str())
        .collect();
    if !constant.is_empty() {
        let _ = writeln!(
            w,
            "> **Columns gone constant: {}.** Worth explaining before signing off.\n",
            constant.join(", ")
        );
    }

    let _ = writeln!(
        w,
        "| Column | Rows | Nulls | Null rate | Distinct | Len min/max | Min | Max |"
    );
    let _ = writeln!(w, "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for c in &p.columns {
        let _ = writeln!(
            w,
            "| `{}` | {} | {} | {:.3} | {} | {}/{} | `{}` | `{}` |",
            c.name,
            c.rows,
            c.nulls,
            c.null_rate(),
            c.distinct,
            c.min_len,
            c.max_len,
            truncate(c.min_value.as_deref().unwrap_or("")),
            truncate(c.max_value.as_deref().unwrap_or("")),
        );
    }

    let _ = writeln!(w, "\n## Top values per column\n");
    for c in &p.columns {
        if c.top.is_empty() {
            continue;
        }
        let rendered = c
            .top
            .iter()
            .map(|(v, n)| format!("`{}` x{n}", truncate(v)))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(w, "- `{}`: {rendered}", c.name);
    }

    let _ = writeln!(w, "\n## Equivalent queries against staging\n");
    let _ = writeln!(
        w,
        "The numbers above come from the values we parsed. These produce the same numbers from the \
         staging table, which is the nearest thing to a second opinion this topology has. Cast \
         **inside the query only** -- section 9 is explicit that the staging columns stay text.\n"
    );
    let _ = writeln!(w, "```sql");
    for c in &p.columns {
        let _ = writeln!(
            w,
            "SELECT '{0}' AS column, count() AS rows, countIf(`{0}` IS NULL) AS nulls, \
             uniqExact(`{0}`) AS distinct, min(length(`{0}`)) AS min_len, max(length(`{0}`)) AS max_len \
             FROM staging.<table>;",
            c.name
        );
    }
    let _ = writeln!(w, "```\n");
    let _ = writeln!(
        w,
        "Promotion requires `SHAPE_REVIEW_SIGNOFF`. Section 9: *\"Promote only after every file in \
         the batch succeeds and the shape review is signed off.\"*"
    );

    md
}

fn truncate(s: &str) -> String {
    const MAX: usize = 40;
    if s.chars().count() <= MAX {
        return s.replace('|', "\\|").replace('`', "'");
    }
    let head: String = s.chars().take(MAX).collect();
    format!("{}...", head.replace('|', "\\|").replace('`', "'"))
}

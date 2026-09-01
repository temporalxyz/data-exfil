//! Serde documents: the pinned overrides we read, and the ledgers we write.
//!
//! Every struct is `deny_unknown_fields`. A typo in a pinned override must be a hard error rather
//! than a silently ignored key -- an override file is source control for a one-shot operation, and
//! "the cap you thought you set was never read" is exactly the class of failure this plan exists
//! to prevent.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::limits::Limits;

/// Section 8.5 column freedom class.
///
/// Injection is a property of the sink, not the value: `'; DROP TABLE users;--` is inert in a
/// ClickHouse `String`. So the control is to leave as few columns as possible able to carry a
/// payload at all. The count of [`FreedomClass::Open`] columns is the salvage's actual injection
/// exposure, and it should be small, named, and justified per column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum FreedomClass {
    /// Exact pattern: UUID, IP, enum id, numeric, timestamp, identifier. Payload characters
    /// cannot occur, so injection is structurally impossible.
    Closed,
    /// A per-column restricted character set and length. Structurally impossible within that set.
    Constrained,
    /// Arbitrary UTF-8 within a length cap. Detection is a flag, not a gate.
    Open,
}

impl FreedomClass {
    /// Whether a catalogue match in this class is an escalation as well as an abort.
    ///
    /// In a closed or constrained column a match means the value already failed its allowlist, so
    /// either the schema is wrong or something put a payload where one cannot legitimately be.
    /// Both warrant waking someone up, not just failing the batch.
    #[must_use]
    pub fn escalates_on_match(self) -> bool {
        matches!(self, Self::Closed | Self::Constrained)
    }
}

/// Per-column pinned decisions, overlaid on the type rules derived from the pinned DDL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ColumnOverride {
    pub class: FreedomClass,
    /// Drop the column from scope entirely (section 8.7: the only permitted removal is by column,
    /// decided before the run -- never row by row, and never by editing a value).
    #[serde(default)]
    pub drop: bool,
    /// Exact regex for a closed or constrained column.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Length cap for a string column.
    #[serde(default)]
    pub max_len: Option<u32>,
    /// Permitted enum ids. Ids, never labels -- a label is an arbitrary string from
    /// attacker-controlled DDL.
    #[serde(default)]
    pub enum_ids: Option<Vec<i16>>,
}

/// `overrides/<db>.<table>.toml` -- the pinned, per-table decisions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Overrides {
    /// Column used for the quiesce cutoff predicate.
    ///
    /// Pinned here and never chosen from server data. This, not wall-clock quiet, is what makes
    /// the boundary stable across the two export passes.
    pub cutoff_column: String,
    /// Cutoff value; the predicate is `WHERE <cutoff_column> < '<cutoff_value>'`.
    pub cutoff_value: String,
    /// Optional explicit pagination cursor. Defaults to the table's ORDER BY key tuple.
    #[serde(default)]
    pub cursor_columns: Option<Vec<String>>,
    /// Target uncompressed bytes per page, before the measured correction.
    pub page_byte_budget: u64,
    pub limits: Limits,
    #[serde(default)]
    pub columns: BTreeMap<String, ColumnOverride>,
}

/// One page's entry in the ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageEntry {
    pub index: u32,
    pub object: String,
    pub generation: u64,
    /// SHA-256 of the archive bytes, computed by us. GCS has no SHA-256 upload checksum
    /// (deviation D5), so this travels in custom metadata and every consumer recomputes it from
    /// the bytes. A GCS-reported hash is never the authority.
    pub sha256: String,
    pub rows: u64,
    pub bytes: u64,
    /// Both export passes' hashes, so the completeness signal has page granularity.
    pub pass1_sha256: String,
    pub pass2_sha256: String,
    /// The cursor key tuple this page ended on, rendered from our own parsed values.
    pub cursor_end: Vec<String>,
}

/// `PAGES.json` -- written LAST, after every page has landed.
///
/// This is the completion sentinel at the bucket layer: the same trick as `.partial` plus atomic
/// rename, one level up. **A prefix without this file is an incomplete run and a consumer must
/// treat it as absent.**
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PagesJson {
    pub table: String,
    pub batch: String,
    pub contract_version: String,
    pub git_commit: String,
    pub cutoff_predicate: String,
    pub total_rows: u64,
    /// `count()` under the cutoff, from the compromised server.
    pub server_count: u64,
    /// `sum(rows) FROM system.parts WHERE active`, from the compromised server.
    pub server_parts_rows: u64,
    pub pages: Vec<PageEntry>,
}

impl PagesJson {
    /// The three-number agreement that is the actual completeness signal.
    ///
    /// Ours, versus two the compromised server supplied. Agreement is a cross-check and not a
    /// proof -- a root attacker can lie consistently -- but any inconsistency, and every
    /// accidental gap, shows up here.
    #[must_use]
    pub fn reconciles(&self) -> bool {
        self.total_rows == self.server_count && self.total_rows == self.server_parts_rows
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_key_in_overrides_is_a_hard_error() {
        let toml_src = r#"
            cutoff_column = "ts"
            cutoff_value = "2026-08-25 00:00:00"
            page_byte_budget = 1024
            tpyo = 1
            [limits]
            max_compressed_bytes = 1
        "#;
        assert!(toml::from_str::<Overrides>(toml_src).is_err());
    }

    #[test]
    fn an_unknown_key_in_a_column_override_is_a_hard_error() {
        let json = r#"{"class":"open","not_a_field":true}"#;
        assert!(serde_json::from_str::<ColumnOverride>(json).is_err());
    }

    #[test]
    fn freedom_class_parses_lowercase_and_rejects_anything_else() {
        assert_eq!(
            serde_json::from_str::<FreedomClass>(r#""closed""#).unwrap(),
            FreedomClass::Closed
        );
        assert!(serde_json::from_str::<FreedomClass>(r#""Closed""#).is_err());
        assert!(serde_json::from_str::<FreedomClass>(r#""wide-open""#).is_err());
    }

    #[test]
    fn closed_and_constrained_escalate_but_open_does_not() {
        assert!(FreedomClass::Closed.escalates_on_match());
        assert!(FreedomClass::Constrained.escalates_on_match());
        assert!(!FreedomClass::Open.escalates_on_match());
    }

    #[test]
    fn reconciliation_needs_all_three_numbers_to_agree() {
        let mut p = PagesJson {
            table: "events.hits".into(),
            batch: "b1".into(),
            contract_version: "1".into(),
            git_commit: "deadbeef".into(),
            cutoff_predicate: "ts < '2026-08-25'".into(),
            total_rows: 100,
            server_count: 100,
            server_parts_rows: 100,
            pages: Vec::new(),
        };
        assert!(p.reconciles());
        // A dropped page shows up as a disagreement, which is the whole point.
        p.total_rows = 99;
        assert!(!p.reconciles());
    }
}

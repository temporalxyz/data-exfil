//! Serde documents: the pinned overrides we read, and the ledgers we write.
//!
//! Every struct is `deny_unknown_fields`. A typo in a pinned override must be a hard error rather
//! than a silently ignored key -- an override file is source control for a one-shot operation, and
//! "the cap you thought you set was never read" is exactly the class of failure this plan exists
//! to prevent.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::abort::{Result, SalvageError, abort};
use crate::clickhouse::types::TypeRules;
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
    /// Export this column as `hex(c)` rather than as-is.
    ///
    /// Section 8.2: *"Prefer hex for arbitrary strings and blobs -- it removes delimiter,
    /// control-byte and escape ambiguity entirely, and is the default choice wherever a column
    /// allows it."* It is off by default here rather than on, because hex-encoding an identifier
    /// column would defeat the exact per-column regex that makes it Closed. The trade is decided
    /// per column, in source control, before the run.
    #[serde(default)]
    pub hex: bool,
    /// Who rotates this column's secret, if it holds one (addition A3).
    ///
    /// Optional because `salvage secrets` runs at incident time, potentially before anyone has
    /// written an override file. Absent renders as **UNASSIGNED** in `SECRETS-ROTATION.md`, which
    /// is a gap to close rather than a default to accept.
    #[serde(default)]
    pub rotation_owner: Option<String>,
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

    /// Section 4 requires these recorded per file: *"Record per file: SHA-256, rows, bytes, table,
    /// shard, replica, partition, generated name."*
    ///
    /// They come from the compromised server, so each passes [`far_side_name`] on the way in.
    /// Recorded, never interpolated -- object names and filenames still come from a local counter,
    /// which is the other half of section 4's rule.
    pub shard: String,
    pub replica: String,
    pub partition: String,
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

// -- part 2: the documents the pipeline writes -------------------------------------------------

/// A field that is always `true` on the wire and refuses to deserialize as anything else.
///
/// Used for deviation D2's `consumer_must_revalidate`. A plain `bool` would let a future edit --
/// or a hand-patched manifest -- quietly revoke the transfer of the single most important control
/// in the source plan. Making the wrong value a parse error costs nothing and closes that door.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AlwaysTrue;

impl Serialize for AlwaysTrue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for AlwaysTrue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        if bool::deserialize(d)? {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "consumer_must_revalidate is fixed at true and cannot be turned off",
            ))
        }
    }
}

/// The mirror of [`AlwaysTrue`], for `independent_revalidation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AlwaysFalse;

impl Serialize for AlwaysFalse {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bool(false)
    }
}

impl<'de> Deserialize<'de> for AlwaysFalse {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        if bool::deserialize(d)? {
            Err(serde::de::Error::custom(
                "independent_revalidation is fixed at false; there is no Q3 in this topology",
            ))
        } else {
            Ok(Self)
        }
    }
}

/// Deviations D1-D7, machine-readable so a consumer does not have to read a markdown file to learn
/// what was given up.
///
/// D2 is the one that matters. Section 9 calls the independent importer *"the single most important
/// control in the plan -- it removes Q2 as a point of trust"*, and this topology does not have one.
/// The two flags below are the written transfer of that control to the consumer, which is why
/// neither is a plain `bool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deviations {
    /// D2. Always true. The consumer must independently repeat every structural, escape, length,
    /// type, range and payload-class check in section 8 before anything reaches a database.
    #[serde(default)]
    pub consumer_must_revalidate: AlwaysTrue,
    /// D2. Always false. Nothing between Q2 and the clean bucket re-validated Q2's output.
    #[serde(default)]
    pub independent_revalidation: AlwaysFalse,
    /// D1: Q2a and Q2b are one host.
    pub combined_quarantine_hosts: bool,
    /// D3: one validator implementation, run once.
    pub single_validator: bool,
    /// D4: no intermediate bucket.
    pub intermediate_bucket_dropped: bool,
    /// D5: the object store has no SHA-256 upload checksum; the ledger is the authority.
    pub producer_computed_sha256: bool,
    /// D6: tarballs are not in the source plan and add a framing surface.
    pub archives_added: bool,
    /// D7: the shape review happens on Q2.
    pub shape_review_on_quarantine_host: bool,
}

impl Default for Deviations {
    /// The deviations this topology actually carries. There is no configuration that produces a
    /// different set, because the topology is a build-time decision and not a run-time one.
    fn default() -> Self {
        Self {
            consumer_must_revalidate: AlwaysTrue,
            independent_revalidation: AlwaysFalse,
            combined_quarantine_hosts: true,
            single_validator: true,
            intermediate_bucket_dropped: true,
            producer_computed_sha256: true,
            archives_added: true,
            shape_review_on_quarantine_host: true,
        }
    }
}

/// One column's complete, reviewed contract.
///
/// [`TypeRules`] is embedded verbatim rather than summarised. That is the whole payoff of section
/// 8.3's rules being data: the exact bound applied to every column is legible on a page **before a
/// 100 GB export is attempted**, and a change between runs shows up in a diff rather than in
/// behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnPlan {
    pub name: String,
    /// The type exactly as the pinned DDL declares it.
    pub declared_type: String,
    pub class: FreedomClass,
    /// Section 8.7: removal is only ever by column, decided before the run.
    pub dropped: bool,
    pub rules: TypeRules,
    /// The rendered projection, one entry per output column. Present so a reviewer sees the actual
    /// SQL rather than having to reconstruct it from [`ColumnPlan::rules`].
    pub export_sql: Vec<String>,
}

/// `plan.json` -- what `salvage plan` emits. Reads no table data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanJson {
    pub table: String,
    pub contract_version: String,
    pub git_commit: String,
    /// Cross-checked against the approved MergeTree allowlist, never trusted from the server.
    pub engine: String,
    pub columns: Vec<ColumnPlan>,
    /// The NOT NULL key tuple the keyset cursor walks. Never contains a nullable column:
    /// `(a, b) > (x, NULL)` is NULL, the row is excluded, and rows vanish with no check firing.
    pub cursor_columns: Vec<String>,
    /// The total order -- key tuple first, then every remaining exported column -- without which
    /// two passes of the same page need not come back byte-identical.
    pub order_by: Vec<String>,
    pub rows_per_page: u64,
    pub cutoff_predicate: String,
}

/// One finding. The batch is dead the moment one of these exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub phase: String,
    pub column: Option<String>,
    pub page: Option<u32>,
    pub row: Option<u64>,
    pub reason: String,
    /// Section 8.5: a match in a Closed or Constrained column means the value already failed its
    /// allowlist, so either the schema is wrong or something put a payload where one cannot
    /// legitimately be. Both warrant waking someone up.
    pub escalate: bool,
    /// A hex-encoded sample of the rejected bytes, and **only** hex.
    ///
    /// Section 8.0 forbids re-emitting a rejected value forward. Typing this as a hex string rather
    /// than as `Vec<u8>` or `String` means there is no variant of this struct that can carry the
    /// original bytes, so the rule is structural instead of a review item.
    pub sample_hex: String,
}

/// One phase's outcome, appended to `report.json` as it completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseRecord {
    pub phase: String,
    pub ok: bool,
    pub detail: String,
}

/// `report.json` -- the phase-by-phase record both pipelines write to the work dir.
///
/// Flushed as `report.json.partial` after every phase so a crash leaves a truthful "we got as far
/// as bounds" record, and **never renamed unless the run completes**, so a partial record cannot be
/// mistaken for a passing audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub table: String,
    pub batch: String,
    pub mode: String,
    pub contract_version: String,
    pub git_commit: String,
    pub phases: Vec<PhaseRecord>,
    pub findings: Vec<Finding>,
}

impl Report {
    /// Whether this run may deliver anything.
    ///
    /// Survey mode accumulates findings and keeps going, but it still fails: survey means "collect
    /// them all", not "tolerate them". The rejection threshold is zero in both modes.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty() && self.phases.iter().all(|p| p.ok)
    }
}

/// `MANIFEST.json` -- written LAST, after every page of the table has passed.
///
/// Unsigned by design: integrity comes from the generation plus the checksum approved by the
/// Controller out of band, because a producer-held signature would only restate what the producer
/// already claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEnvelope {
    pub table: String,
    pub batch: String,
    pub contract_version: String,
    pub git_commit: String,
    pub cutoff_predicate: String,
    pub deviations: Deviations,
    pub pages: Vec<PageEntry>,
    pub total_rows: u64,
    pub total_bytes: u64,
    /// `count()` and `sum(rows) FROM system.parts` as the compromised server reported them, before
    /// and after. Server-supplied, so a cross-check and never a proof.
    pub quiesce_before: Vec<String>,
    pub quiesce_after: Vec<String>,
    /// Rejection counts by reason and by column. Zero in any batch that ships, by construction --
    /// carried so the survey pass has somewhere to put its inventory.
    pub rejections_by_reason: BTreeMap<String, u64>,
    pub rejections_by_column: BTreeMap<String, u64>,
    /// Columns removed from scope before the run (section 8.7).
    pub dropped_columns: Vec<String>,
}

/// Validate a name that came back from the compromised server.
///
/// Section 4, verbatim: *"Validate any far-side name against `^[A-Za-z0-9_-]{1,64}$` before use"* --
/// and the reason it matters here is the sentence just before it: *"Never interpolate database
/// values into SQL, shell, filenames or paths… includes anything that looks like metadata:
/// partition IDs, table and column names returned by the server are attacker-influenced."*
///
/// Both rules hold at once, and the distinction is easy to get backwards. A partition id is
/// **recorded** in the ledger, because section 4 also requires it recorded per file. It is
/// **never interpolated** into anything. This function is the gate on the recording path; the
/// no-interpolation rule is upheld by callers generating filenames from a local counter.
pub fn far_side_name(what: &'static str, value: &str) -> Result<String> {
    let ok = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        return Ok(value.to_owned());
    }
    // An Abort rather than a Usage: this value came from the far side, so a malformed one is a
    // finding about the data, not a mistake in our invocation.
    abort("far-side name failed its charset check")
        .map_err(|e: SalvageError| e.with("field", what).with("value", value.escape_debug()))
}

/// Section 8.6's payload inventory for one column.
///
/// Distinct from [`Finding`] and from the rejection counts on [`ManifestEnvelope`]: those record
/// *what killed a run*, this records *what a survey saw*. Section 8.6 names the fields --
/// *"Records per table and column: which pattern classes matched, how many rows, hex-encoded
/// samples."*
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnInventory {
    pub column: String,
    /// The column's declared class. A match in Closed or Constrained is the escalating case --
    /// the value already failed its allowlist, so either the schema is wrong or something put a
    /// payload where one cannot legitimately be.
    pub class: FreedomClass,
    /// Catalogue class names that matched, e.g. `sql`, `shell`, `jndi`, `unicode`.
    pub classes_matched: Vec<String>,
    pub rows_matched: u64,
    /// Hex, and only hex. Same structural reason as [`Finding::sample_hex`]: section 8.0 forbids
    /// re-emitting a rejected value forward, so no field here can carry the original bytes.
    pub samples_hex: Vec<String>,
}

/// A mode field that is always `"survey"` and refuses to deserialize as anything else.
///
/// Section 8.6: *"The payload inventory comes from the survey pass (8.0.1), not a production run
/// -- a production run that got far enough to build an inventory has already failed."* An
/// inventory stamped `enforce` is therefore not a document with a wrong field; it is a
/// contradiction, and it fails to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SurveyOnly;

impl Serialize for SurveyOnly {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str("survey")
    }
}

impl<'de> Deserialize<'de> for SurveyOnly {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        if raw == "survey" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "a payload inventory can only come from a survey pass; \
                 an enforce run that built one had already failed",
            ))
        }
    }
}

/// `PAYLOAD-INVENTORY.json` -- the survey pass's output, and the input to the next run's scope
/// decision.
///
/// Section 8.6 is specific about what this is for, and it is not a log: *"Scope decisions are made
/// from it between runs: drop the column, reclassify it, or remove the table. Zero survey matches
/// → column proceeds. Matches → column is changed before the production run, not argued about
/// during it."* So it has to read as a worklist.
///
/// It is also section 11's input. *"The payload inventory from 8.6 says which of these are
/// mandatory for which columns. A consumer of a column with HTML matches must encode; a consumer
/// of a column with URL matches must not fetch."* `CONSUMER-CONTRACT.md` is generated from this
/// document rather than written by hand, so the obligations name columns instead of describing
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadInventory {
    pub table: String,
    pub batch: String,
    pub contract_version: String,
    pub git_commit: String,
    /// Fixed at `"survey"`; see [`SurveyOnly`].
    #[serde(default)]
    pub mode: SurveyOnly,
    /// One entry per column that matched anything. A column absent from this list saw zero
    /// matches and proceeds.
    pub columns: Vec<ColumnInventory>,
}

impl PayloadInventory {
    /// Columns that must be dealt with before a production run: dropped, reclassified, or the
    /// table removed from scope.
    #[must_use]
    pub fn worklist(&self) -> Vec<&ColumnInventory> {
        self.columns.iter().filter(|c| c.rows_matched > 0).collect()
    }

    /// Whether every column came back clean, which is the only state in which a production run
    /// should be attempted.
    #[must_use]
    pub fn is_clear(&self) -> bool {
        self.worklist().is_empty()
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

    #[test]
    fn a_far_side_name_that_could_reach_sql_is_refused() {
        // Section 4: partition ids and table names returned by the server are attacker-influenced.
        // These are recorded, so they must be screened; nothing here is ever interpolated.
        assert_eq!(far_side_name("partition", "202608").unwrap(), "202608");
        assert_eq!(
            far_side_name("replica", "replica-02_a").unwrap(),
            "replica-02_a"
        );

        for hostile in [
            "2026'; DROP TABLE users;--",
            "../../etc/passwd",
            "a b",
            "a\nb",
            "",
            &"x".repeat(65),
        ] {
            let err = far_side_name("partition", hostile).unwrap_err();
            assert_eq!(
                err.exit_code(),
                crate::abort::ExitCode::Abort,
                "a malformed far-side name is a finding about the data, not a usage error"
            );
        }
    }

    fn a_page_entry() -> PageEntry {
        PageEntry {
            index: 0,
            object: "events.hits/b1/page-0000.tar.gz".into(),
            generation: 1_700_000_000_000_001,
            sha256: "aa".repeat(32),
            rows: 1000,
            bytes: 4096,
            pass1_sha256: "bb".repeat(32),
            pass2_sha256: "bb".repeat(32),
            cursor_end: vec!["2026-08-24 23:59:59".into(), "42".into()],
            shard: "shard-01".into(),
            replica: "replica-02".into(),
            partition: "202608".into(),
        }
    }

    #[test]
    fn a_page_entry_records_everything_section_4_names() {
        let json = serde_json::to_value(a_page_entry()).unwrap();
        // Section 4's per-file record, in full. `table` lives on the enclosing PagesJson and the
        // generated name is `object`.
        for field in [
            "sha256",
            "rows",
            "bytes",
            "shard",
            "replica",
            "partition",
            "object",
        ] {
            assert!(json.get(field).is_some(), "section 4 requires `{field}`");
        }
        assert_eq!(
            serde_json::from_value::<PageEntry>(json).unwrap(),
            a_page_entry()
        );
    }

    fn an_inventory() -> PayloadInventory {
        PayloadInventory {
            table: "events.hits".into(),
            batch: "b1".into(),
            contract_version: "1".into(),
            git_commit: "deadbeef".into(),
            mode: SurveyOnly,
            columns: vec![ColumnInventory {
                column: "body".into(),
                class: FreedomClass::Open,
                classes_matched: vec!["html".into(), "url".into()],
                rows_matched: 17,
                samples_hex: vec!["3c7363726970743e".into()],
            }],
        }
    }

    #[test]
    fn a_payload_inventory_round_trips() {
        let json = serde_json::to_string(&an_inventory()).unwrap();
        assert_eq!(
            serde_json::from_str::<PayloadInventory>(&json).unwrap(),
            an_inventory()
        );
        assert!(json.contains("\"mode\":\"survey\""), "{json}");
    }

    #[test]
    fn an_inventory_stamped_enforce_is_a_parse_error_not_a_wrong_field() {
        // Section 8.6: the inventory comes from the survey pass, never a production run -- "a
        // production run that got far enough to build an inventory has already failed". So this
        // document cannot exist, and it does not parse.
        let mut json = serde_json::to_value(an_inventory()).unwrap();
        json["mode"] = serde_json::Value::String("enforce".into());
        let err = serde_json::from_value::<PayloadInventory>(json).unwrap_err();
        assert!(err.to_string().contains("survey"), "{err}");
    }

    #[test]
    fn an_unknown_key_in_an_inventory_is_a_hard_error() {
        let mut json = serde_json::to_value(an_inventory()).unwrap();
        json["extra"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<PayloadInventory>(json).is_err());
    }

    #[test]
    fn the_worklist_is_what_scope_gets_fixed_from() {
        let inv = an_inventory();
        assert!(!inv.is_clear());
        assert_eq!(inv.worklist().len(), 1);
        assert_eq!(inv.worklist()[0].column, "body");

        // Zero matches means the column proceeds -- section 8.6's own rule.
        let clear = PayloadInventory {
            columns: Vec::new(),
            ..an_inventory()
        };
        assert!(clear.is_clear());
    }

    #[test]
    fn a_match_in_a_closed_column_is_the_escalating_case() {
        // Not a property of the inventory itself, but the reason the class travels with it: a
        // payload in a column whose allowlist forbids payload characters means the schema is wrong
        // or something put it there deliberately.
        let inv = PayloadInventory {
            columns: vec![ColumnInventory {
                column: "ident".into(),
                class: FreedomClass::Closed,
                classes_matched: vec!["sql".into()],
                rows_matched: 1,
                samples_hex: vec!["27".into()],
            }],
            ..an_inventory()
        };
        assert!(inv.columns[0].class.escalates_on_match());
    }
}

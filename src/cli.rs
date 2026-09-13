//! The command line surface. The doc comments here *are* the `--help`.
//!
//! Each subcommand carries the source plan's section 2 framing -- PROVES / DOES NOT PROVE /
//! ABORTS ON -- so that what a control does and does not establish lives in the binary rather than
//! only in a document that can go stale.
//!
//! Two deliberate choices:
//!
//! - `--table` and `--batch` are **non-optional fields on the subcommands that need them**, rather
//!   than optional globals. clap then enforces required-ness itself, and the five runtime
//!   `is_none()` checks that would otherwise be needed disappear.
//! - [`TableRef`] and [`BatchId`] are newtypes that validate in `FromStr`. Both reach object names
//!   and staging table names, so this is the same discipline section 4 demands for far-side names:
//!   validate once at the boundary, and let every downstream function take the parsed type. It is
//!   a security boundary, not ergonomics.

use std::path::PathBuf;
use std::str::FromStr;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_verbosity_flag::Verbosity;

/// A validated `db.table` reference.
///
/// Splitting `db.table` in one reviewed place is also how `staging.<tbl>__<batch>__<seq>` stays
/// constructible without string surgery at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRef {
    database: String,
    table: String,
}

impl TableRef {
    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }

    /// `db.table`, the form used in SQL and in object prefixes.
    #[must_use]
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.database, self.table)
    }
}

fn valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl FromStr for TableRef {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, '.');
        let (Some(database), Some(table)) = (parts.next(), parts.next()) else {
            return Err(format!("expected `db.table`, got `{s}`"));
        };
        if !valid_identifier(database) || !valid_identifier(table) {
            return Err(format!(
                "`{s}` is not `db.table` with both parts matching ^[A-Za-z0-9_-]{{1,64}}$"
            ));
        }
        Ok(Self {
            database: database.to_owned(),
            table: table.to_owned(),
        })
    }
}

/// A validated batch id: `^[A-Za-z0-9-]{1,32}$`.
///
/// Validated, not trusted. It reaches object names and staging table names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchId(String);

impl BatchId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for BatchId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 32 {
            return Err(format!("batch id must be 1-32 characters, got {}", s.len()));
        }
        if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!("batch id `{s}` must match ^[A-Za-z0-9-]{{1,32}}$"));
        }
        Ok(Self(s.to_owned()))
    }
}

/// A validated GCS bucket name.
///
/// Pinned configuration, never derived from data -- but it reaches a URL, so it is validated at
/// the boundary like every other name that does. GCS's own rules are narrower than this; what
/// matters here is that nothing outside `[a-z0-9._-]` can reach a request path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketName(String);

impl BucketName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for BucketName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 3 || s.len() > 63 {
            return Err(format!(
                "bucket name must be 3-63 characters, got {}",
                s.len()
            ));
        }
        if !s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        }) {
            return Err(format!(
                "bucket name `{s}` must match ^[a-z0-9._-]{{3,63}}$"
            ));
        }
        if !s.starts_with(|c: char| c.is_ascii_alphanumeric())
            || !s.ends_with(|c: char| c.is_ascii_alphanumeric())
        {
            return Err(format!(
                "bucket name `{s}` must start and end with a letter or digit"
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

#[derive(Debug, Parser)]
#[command(name = "salvage", version, propagate_version = true)]
#[command(about = "Fail-closed ClickHouse salvage from a compromised cluster")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    #[command(flatten)]
    pub common: Common,
}

/// Options that genuinely apply to every subcommand.
#[derive(Debug, Args)]
pub struct Common {
    /// Work dir holding the batch's files and report.json
    #[arg(long, global = true, default_value = "./work")]
    pub work: PathBuf,

    /// Directory of pinned `CREATE TABLE` statements. This, not the server, is the authority for
    /// what a table is (section 4).
    #[arg(long, global = true, default_value = "./ddl")]
    pub ddl_dir: PathBuf,

    /// Directory of pinned per-table override files.
    #[arg(long, global = true, default_value = "./overrides")]
    pub overrides_dir: PathBuf,

    /// ClickHouse HTTP endpoint of the compromised cluster, e.g. `http://10.0.0.5:8123`.
    ///
    /// Optional for `plan`: without it the contract is derived from pinned source control alone
    /// and `plan.json` records that the cluster was not cross-checked.
    #[arg(long, global = true)]
    pub clickhouse_url: Option<String>,

    /// Read-only user on the compromised cluster. Assumed compromised from creation; see
    /// `SECRETS-ROTATION.md`.
    #[arg(long, global = true, default_value = "salvage_ro")]
    pub clickhouse_user: String,

    /// Disposable ClickHouse for the pre-flight insert test, **pinned by digest**.
    ///
    /// Section 3 wants independently built and verified images; a tag is mutable, so a tag is not
    /// a pin. Choose from section 3's supported list -- 26.7, 26.6, 26.5, 26.3 or 25.8 -- and never
    /// 25.3, which is the compromised cluster's own end-of-support build.
    /// There is deliberately **no default**. A default would have to be a tag -- which is exactly
    /// what this flag exists to forbid -- and the previous one sat directly beneath the sentence
    /// above saying a tag is not a pin, while nothing read the field at all.
    #[arg(long, global = true)]
    pub clickhouse_image: Option<String>,

    /// Host the disposable ClickHouse answers on.
    #[arg(long, global = true, default_value = "127.0.0.1")]
    pub insert_host: String,

    /// The raw bucket: where `export` writes and where `audit` reads from.
    ///
    /// Required by `export` and `audit`; `plan`, `secrets` and `teardown` touch no bucket, so it
    /// is optional here and checked in the dispatcher rather than by clap.
    #[arg(long, global = true)]
    pub bucket: Option<BucketName>,

    /// The clean bucket: where `audit` writes the regenerated batch.
    ///
    /// Required by `audit`, and it must be a **different** bucket from `--bucket`. Section 5 puts
    /// clean in a separate account precisely so that the credential which wrote the raw side
    /// cannot reach it; sharing one bucket also breaks the consumer contract's escalation rule,
    /// which says to re-run from raw and never re-derive from clean.
    #[arg(long, global = true)]
    pub clean_bucket: Option<BucketName>,

    /// Days of Unlocked object retention to set on every object this run creates.
    ///
    /// Addition A5: **Unlocked (governance) retention, never Locked.** Locked retention would make
    /// the raw bucket hold the attacker's data immutably and leave the bucket undeletable until
    /// every retain-until passed, which is a liability rather than a control. Unlocked lets an
    /// authorized identity remove it at teardown, which is what `teardown`'s checklist assumes.
    ///
    /// Zero means no retention, and that is a real choice rather than the accidental default it
    /// used to be: every call site passed `None`, so the retention code was correct, tested and
    /// unreachable, and a temporary hold released at teardown was the only protection applied.
    #[arg(long, global = true, default_value_t = 0)]
    pub retain_days: u32,

    /// The exact generation of `PAGES.json` to read, as pinned by the Controller out of band.
    ///
    /// Section 5: readers address an exact object version, never "latest under prefix", and the
    /// Controller -- not the producer -- approves what moves forward. Without this the audit
    /// resolves the live generation, which makes the producer's own ledger the root of trust for
    /// every page generation and hash in the run.
    #[arg(long, global = true)]
    pub pages_generation: Option<u64>,

    /// Proceed without a Controller-pinned `PAGES.json` generation, reading the live one instead.
    ///
    /// A single-operator convenience and a recorded deviation, not a default. It is a flag rather
    /// than a fallback so that the weaker mode appears in the shell history and in `report.json`.
    #[arg(long, global = true)]
    pub unpinned_ledger: bool,

    /// Directory holding resumable-upload sessions, so an interrupted multi-GB page push resumes
    /// rather than restarting. Defaults to a subdirectory of `--work`.
    #[arg(long, global = true)]
    pub session_dir: Option<PathBuf>,

    /// Machine-readable result on stdout; the human log always goes to stderr
    #[arg(long, global = true)]
    pub json: bool,

    /// Print what would run and touch nothing.
    ///
    /// A dry run still builds every SQL string and every object name, and runs every validator;
    /// only the effectful leaf is stubbed. A dry run that skipped the code path would prove
    /// nothing.
    #[arg(long, global = true)]
    pub dry_run: bool,

    #[command(flatten)]
    pub verbosity: Verbosity,
}

/// The table argument, flattened into the four subcommands that operate on one.
#[derive(Debug, Args)]
pub struct TableArg {
    /// Table to operate on, `db.table`. One table per invocation.
    #[arg(long)]
    pub table: TableRef,
}

/// The batch argument, flattened into the three subcommands that address a batch.
#[derive(Debug, Args)]
pub struct BatchArg {
    /// Batch id. Validated, not trusted: ^[A-Za-z0-9-]{1,32}$
    #[arg(long)]
    pub batch: BatchId,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Choose this table's pagination cursor and page size. Reads no table data.
    ///
    /// PROVES: the cursor is a NOT NULL prefix of the ORDER BY key, so the seek is a range scan
    /// and no page boundary can drop a row to a NULL comparison.
    /// DOES NOT PROVE: that the page size is right first time. It is seeded from the compromised
    /// server's estimate and then corrected from our own measured output.
    /// ABORTS ON: no NOT NULL key prefix available, or a cursor that is not a key prefix.
    Plan(PlanArgs),

    /// Pull each page twice, diff, tar, push to the raw bucket.
    ///
    /// Does not freeze the source: stopping legitimate writers is an operational step handled out
    /// of band, never by logging in to the compromised host.
    ///
    /// PROVES: the export errored rather than truncating, and both passes of every page agree
    /// byte for byte.
    /// DOES NOT PROVE: that the rows are true, or that they are all of what existed.
    /// ABORTS ON: a pinned setting the server does not know, a settings constraint, a row-count
    /// disagreement, a page longer than its own LIMIT, or any difference between two passes.
    Export(ExportArgs),

    /// Stream the batch down, audit it, insert-test it against a dummy DB, re-tar, push to clean.
    ///
    /// PROVES: every delivered byte framed, escaped, typed and bounded as declared, and loaded
    /// under a real ClickHouse parser with zero skipped, malformed or defaulted rows.
    /// DOES NOT PROVE: that any value is true, or that free text is benign.
    /// ABORTS ON: any framing error, any non-canonical escape, any out-of-bound value, any
    /// payload-catalogue match, or any insert that does not load cleanly.
    Audit(AuditArgs),

    /// Audit native Parquet from S3, processing independent days concurrently.
    /// Applies pinned schema, field bounds and injection/payload checks. Regenerates Parquet;
    /// does not perform a ClickHouse insert test. A finding rejects the entire day.
    AuditParquet(Box<ParquetArgs>),

    #[command(hide = true)]
    ParquetWorker { job: PathBuf },

    /// Inventory which columns can hold a credential. Run at incident time; touches no data.
    ///
    /// PROVES: nothing about the data. It is an inventory, not a check.
    /// DOES NOT PROVE: that the listed secrets are all of them.
    /// REFUSES (exit 2, usage): pinned DDL that cannot be parsed -- a source-control problem,
    /// not a finding about the data.
    Secrets,

    /// Release holds, destroy the estate, record the source disposition.
    ///
    /// PROVES: the source's fate is written down rather than defaulted, and the temporary holds
    /// this tool set are released so the estate *can* be destroyed.
    /// DOES NOT PROVE: that the estate is gone. Deleting instances, disks, keys, service accounts
    /// and buckets needs credentials this tool deliberately never holds; the checklist it emits is
    /// a list of things nobody has done yet.
    /// DOES NOT PROVE: that no copy was taken while the batch existed.
    /// ABORTS ON: acceptance or rotation not signed off.
    Teardown(TeardownArgs),
}

#[derive(Debug, Args)]
pub struct PlanArgs {
    #[command(flatten)]
    pub table: TableArg,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    #[command(flatten)]
    pub table: TableArg,
    #[command(flatten)]
    pub batch: BatchArg,

    /// Resume an interrupted run. Honoured only after exit 3; refuses to continue past a finding.
    ///
    /// The refusal is enforced, not documented: a resume that could skip past a finding would
    /// silently deliver the subset section 8.0 forbids.
    #[arg(long)]
    pub resume: bool,
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Section 9's shape review has been done and signed off by a person.
    ///
    /// Never set by this tool. It is a smell test by someone who knows the data, recorded as a
    /// reviewed artifact rather than a passed check.
    #[arg(long)]
    pub shape_review_signoff: bool,

    /// Addition A3's rotation inventory has been worked through.
    ///
    /// Rotation proceeds regardless of whether the batch ships; promotion waits on it because a
    /// live credential in salvaged data is a live credential in the consumer's systems.
    #[arg(long)]
    pub rotation_signoff: bool,

    #[command(flatten)]
    pub table: TableArg,
    #[command(flatten)]
    pub batch: BatchArg,

    /// survey enumerates every finding and writes nothing forward;
    /// enforce is the production run and is expected to find nothing.
    #[arg(long, value_enum)]
    pub mode: Mode,

    /// Container runtime for the dummy ClickHouse used by the insert test.
    #[arg(long, value_enum, default_value_t = Runner::Docker)]
    pub runner: Runner,
}

#[derive(Debug, Args)]
pub struct ParquetArgs {
    #[command(flatten)]
    pub table: TableArg,
    #[command(flatten)]
    pub batch: BatchArg,
    /// Root before YYYY/MM/DD/table/. Must be s3://bucket/prefix.
    #[arg(long)]
    pub source: String,
    /// Clean root. Batch/YYYY/MM/DD/table/ is appended. A separate bucket is required.
    #[arg(long)]
    pub destination: String,
    /// Inclusive YYYY-MM-DD.
    #[arg(long)]
    pub from: String,
    /// Inclusive YYYY-MM-DD.
    #[arg(long)]
    pub through: String,
    #[arg(long, value_enum)]
    pub mode: Mode,
    #[arg(long, default_value_t = 4)]
    pub day_concurrency: usize,
    #[arg(long, default_value_t = 8)]
    pub download_concurrency: usize,
    /// Defaults to the number of available CPU cores.
    #[arg(long)]
    pub check_concurrency: Option<usize>,
    #[arg(long, default_value_t = 4)]
    pub upload_concurrency: usize,
    /// Total pipeline memory budget, in bytes; includes transfer and check reservations.
    #[arg(long)]
    pub memory_bytes: u64,
    /// Address-space ceiling per isolated validation worker (Linux).
    #[arg(long, default_value_t = 1073741824)]
    pub worker_memory_bytes: u64,
    /// Total scratch reservation, in bytes.
    #[arg(long)]
    pub scratch_bytes: u64,
    /// Maximum scratch used by one admitted day, including raw and regenerated data.
    #[arg(long)]
    pub max_day_scratch_bytes: u64,
    #[arg(long, default_value_t = 8192)]
    pub batch_rows: usize,
    #[arg(long, default_value_t = 67108864)]
    pub row_group_bytes: u64,
    #[arg(long, default_value_t = 536870912)]
    pub output_chunk_bytes: u64,
    #[arg(long)]
    pub source_profile: Option<String>,
    #[arg(long)]
    pub destination_profile: Option<String>,
    #[arg(long)]
    pub resume: bool,
    #[arg(long)]
    pub shape_review_signoff: bool,
    #[arg(long)]
    pub rotation_signoff: bool,
}

#[derive(Debug, Args)]
pub struct TeardownArgs {
    #[command(flatten)]
    pub table: TableArg,
    #[command(flatten)]
    pub batch: BatchArg,

    /// What happens to the compromised source. There is no default: the source plan never says,
    /// and with no evidence preserved every option is irreversible.
    #[arg(long, value_enum)]
    pub disposition: Disposition,

    /// The named person who owns that decision. Not a team and not a rota.
    #[arg(long)]
    pub owner: String,

    /// The consumer has accepted the batch. The source is kept until then precisely so there is a
    /// second attempt if the chain fails.
    #[arg(long)]
    pub accepted: bool,

    /// Every row of `SECRETS-ROTATION.md` is done.
    #[arg(long)]
    pub rotation_complete: bool,
}

/// The source disposition, per addition A6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Disposition {
    Wipe,
    SnapshotThenWipe,
    Retain,
}

/// Survey means "collect every finding", never "tolerate them" -- a survey with findings still
/// fails, it just fails after enumerating all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Survey,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Runner {
    Docker,
    Podman,
    Local,
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
    use clap::CommandFactory;

    #[test]
    fn the_cli_definition_is_internally_consistent() {
        // clap's own assertions catch conflicting flags, duplicate names and bad defaults.
        Cli::command().debug_assert();
    }

    #[test]
    fn a_table_ref_splits_into_database_and_table() {
        let t: TableRef = "events.hits".parse().unwrap();
        assert_eq!(t.database(), "events");
        assert_eq!(t.table(), "hits");
        assert_eq!(t.qualified(), "events.hits");
    }

    #[test]
    fn a_table_ref_rejects_quoting_and_injection_metacharacters() {
        // These reach SQL and object names; rejecting at the boundary is the control.
        for bad in [
            "events",
            "events.",
            ".hits",
            "events.hits; DROP TABLE x",
            "events.`hits`",
            "events.hits'",
            "ev ents.hits",
            "events..hits",
        ] {
            assert!(bad.parse::<TableRef>().is_err(), "`{bad}` must reject");
        }
    }

    #[test]
    fn a_table_ref_rejects_an_over_long_identifier() {
        let long = "a".repeat(65);
        assert!(format!("db.{long}").parse::<TableRef>().is_err());
    }

    #[test]
    fn a_batch_id_accepts_only_its_charset() {
        assert!("b-2026-08-31".parse::<BatchId>().is_ok());
        for bad in ["", "has space", "has_underscore", "slash/es", "quote'"] {
            assert!(bad.parse::<BatchId>().is_err(), "`{bad}` must reject");
        }
        assert!("a".repeat(33).parse::<BatchId>().is_err());
    }

    #[test]
    fn an_invalid_mode_is_a_parse_error_not_a_default() {
        // There is no "unrecognised mode, assuming enforce" path.
        let parsed = Cli::try_parse_from([
            "salvage",
            "audit",
            "--table",
            "events.hits",
            "--batch",
            "b1",
            "--mode",
            "whatever",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn export_requires_both_table_and_batch() {
        assert!(Cli::try_parse_from(["salvage", "export"]).is_err());
        assert!(Cli::try_parse_from(["salvage", "export", "--table", "events.hits"]).is_err());
        assert!(
            Cli::try_parse_from([
                "salvage",
                "export",
                "--table",
                "events.hits",
                "--batch",
                "b1"
            ])
            .is_ok()
        );
    }

    #[test]
    fn secrets_needs_no_table_because_it_reads_pinned_ddl_only() {
        assert!(Cli::try_parse_from(["salvage", "secrets"]).is_ok());
    }
}

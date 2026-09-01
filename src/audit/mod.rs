//! Q2 phases, invoked in order by `salvage audit`.
//!
//! `pull` -> `unpack` -> `frame` -> `escapes` -> `bounds` -> freedom classes -> `payloads` ->
//! `secrets` -> `insert` -> `profile` -> repack -> push.
//!
//! One page is on disk at a time. Every phase runs per page, and promotion to the clean bucket is
//! all-or-nothing across the table's pages: nothing is pushed until every page has passed audit,
//! the insert test and shape review. That is what preserves "nothing partial is ever delivered,
//! and no subset is assembled from a run that found something" now that the batch is table-scoped.
//!
//! The submodules named in the plan (`frame`, `bounds`, `payloads`, `secrets`, `insert`,
//! `profile`) are split out as their build step lands; see the plan's step 10.

pub mod bounds;
pub mod frame;
pub mod insert;
pub mod payloads;
pub mod profile;
pub mod secrets;

use std::path::{Path, PathBuf};

use crate::abort::{Result, SalvageError, StagingDir, abort};
use crate::archive::{ArchiveMember, write_targz};
use crate::audit::bounds::{ColumnContract, check_row, contracts};
use crate::audit::frame::frame;
use crate::audit::insert::{InsertPlan, InsertTester};
use crate::audit::profile::{profile, render_markdown};
use crate::clickhouse::ddl::PinnedDdl;
use crate::clickhouse::quarantine::{output_columns, quarantine_ddl, staging_table_name};
use crate::clickhouse::tsv::{Field, encode_field};
use crate::export::diff::sha256_hex;
use crate::gcs::{Created, Generation, ObjectMeta, ObjectName, ObjectStore};
use crate::models::Overrides;
use crate::models::{
    ColumnInventory, Deviations, ManifestEnvelope, PagesJson, PayloadInventory, PhaseRecord,
    Report, SurveyOnly,
};

/// Survey enumerates; enforce delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Section 8.0.1. Parses to enumerate **every** finding across the batch and writes nothing
    /// forward. This is how scope gets fixed between runs -- halting on the first finding means
    /// discovering problems one at a time across many re-runs, which for a large batch is not a
    /// process that terminates.
    Survey,
    /// The production run, expected to find nothing. If it aborts, the survey was incomplete or
    /// the scope decision was wrong; both are worth knowing.
    Enforce,
}

/// Options for one audit run.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub batch: String,
    pub work: PathBuf,
    pub raw_prefix: String,
    pub clean_prefix: String,
    pub mode: Mode,
    pub dry_run: bool,
    pub contract_version: String,
    pub git_commit: String,
    /// Section 9 and addition A3 both gate promotion on a human. Neither is set by this code.
    pub shape_review_signoff: bool,
    pub rotation_signoff: bool,
}

/// `report.json`, flushed after every phase.
///
/// Written as `report.json.partial` and **never renamed unless the run completes**, so it cannot
/// be mistaken for a passing audit.
///
/// # Why this is not a `PartialOutput`
///
/// Every other in-progress file in this tool is guarded by [`PartialOutput`], which unlinks on
/// drop so that section 8.0's *"no partial output"* holds even on a panic. This one deliberately
/// is not, and the distinction is worth being explicit about: **section 8.0 governs salvaged data,
/// not the finding record.** A run that aborts is a run whose entire deliverable is the list of
/// what it found -- unlinking that on the way out would destroy the only artifact the operator
/// needs to decide what to drop, reclassify, or remove from scope.
///
/// So the `.partial` survives a failure on purpose. What stops it being mistaken for success is
/// the name: nothing reads `report.json.partial` as a passing audit, and the rename happens only
/// when the run completes clean.
#[derive(Debug)]
pub struct ReportBuilder {
    partial_path: PathBuf,
    final_path: PathBuf,
    doc: Report,
}

impl ReportBuilder {
    pub fn new(work: &Path, table: &str, batch: &str, mode: Mode) -> Result<Self> {
        Ok(Self {
            partial_path: work.join("report.json.partial"),
            final_path: work.join("report.json"),
            doc: Report {
                table: table.to_owned(),
                batch: batch.to_owned(),
                mode: format!("{mode:?}").to_lowercase(),
                contract_version: String::new(),
                git_commit: String::new(),
                phases: Vec::new(),
                findings: Vec::new(),
            },
        })
    }

    pub fn stamp(&mut self, contract_version: &str, git_commit: &str) {
        self.doc.contract_version = contract_version.to_owned();
        self.doc.git_commit = git_commit.to_owned();
    }

    pub fn phase(&mut self, name: &str, ok: bool, detail: impl Into<String>) -> Result<()> {
        self.doc.phases.push(PhaseRecord {
            phase: name.to_owned(),
            ok,
            detail: detail.into(),
        });
        self.flush()
    }

    pub fn record(&mut self, findings: Vec<crate::models::Finding>) {
        self.doc.findings.extend(findings);
    }

    #[must_use]
    pub fn findings(&self) -> &[crate::models::Finding] {
        &self.doc.findings
    }

    fn flush(&mut self) -> Result<()> {
        let rendered =
            serde_json::to_string_pretty(&self.doc).map_err(|e| SalvageError::Infra {
                reason: format!("could not render report.json: {e}"),
                context: Vec::new(),
            })?;
        std::fs::write(&self.partial_path, rendered).map_err(|e| SalvageError::Infra {
            reason: format!("could not write report.json: {e}"),
            context: Vec::new(),
        })
    }

    /// Rename into place, or abort if anything was found.
    ///
    /// Survey accumulates and keeps going, but it **still fails**: survey means "collect them
    /// all", not "tolerate them". The rejection threshold is zero in both modes.
    pub fn finish(mut self) -> Result<Report> {
        self.flush()?;
        if !self.doc.is_clean() {
            return abort("the audit found something").map_err(|e: SalvageError| {
                e.with("findings", self.doc.findings.len())
                    .with("report", self.partial_path.display())
                    .with(
                        "resolution",
                        "drop the column, reclassify it Closed or Constrained, or remove the \
                         table -- then re-run from the start. Never by lowering the bar.",
                    )
            });
        }
        std::fs::rename(&self.partial_path, &self.final_path).map_err(|e| SalvageError::Infra {
            reason: format!("could not commit report.json: {e}"),
            context: vec![("path", self.final_path.display().to_string())],
        })?;
        Ok(self.doc.clone())
    }
}

/// Run the audit pipeline for one table.
///
/// `pull` -> `frame` -> `bounds` (which carries escapes, classes and payloads) -> `profile` ->
/// `insert` -> repack -> push. One page is on disk at a time.
///
/// **Promotion is all-or-nothing across the table's pages.** Nothing reaches the clean bucket until
/// every page has passed audit, the insert test and shape review -- which is what preserves
/// section 8.0's *"nothing partial is ever delivered, and no subset is assembled from a run that
/// found something"* now that the batch is table-scoped.
#[allow(clippy::too_many_arguments)]
pub fn run_audit(
    ddl: &PinnedDdl,
    overrides: &Overrides,
    store: &dyn ObjectStore,
    inserter: &dyn InsertTester,
    ledger: &PagesJson,
    opts: &AuditOptions,
) -> Result<Report> {
    std::fs::create_dir_all(&opts.work).map_err(|e| SalvageError::Infra {
        reason: format!("could not create the work dir: {e}"),
        context: Vec::new(),
    })?;

    let mut report = ReportBuilder::new(&opts.work, &ddl.qualified(), &opts.batch, opts.mode)?;
    report.stamp(&opts.contract_version, &opts.git_commit);

    let outputs = output_columns(ddl, overrides)?;
    let header: Vec<String> = outputs.iter().map(|c| c.name.clone()).collect();
    let contracts = contracts(ddl, overrides)?;
    report.phase("plan", true, format!("{} output columns", header.len()))?;

    // A prefix without its ledger is an incomplete run and must be treated as absent.
    if ledger.pages.is_empty() {
        return abort("the ledger lists no pages")
            .map_err(|e: SalvageError| e.with("batch", opts.batch.clone()));
    }
    if !ledger.reconciles() {
        return abort("the ledger does not reconcile; the export never completed cleanly")
            .map_err(|e: SalvageError| e.with("streamed", ledger.total_rows));
    }

    // Staged locally. Nothing is pushed until every page has passed.
    let dest = opts.work.join(format!("{}-clean", opts.batch));
    let mut staging = StagingDir::inside(dest)?;

    let mut inventory: Vec<ColumnInventory> = Vec::new();
    let mut total_rows: u64 = 0;
    let mut regenerated: Vec<(String, PathBuf, String, u64, u64)> = Vec::new();

    for entry in &ledger.pages {
        let page_dir = opts.work.join("page");
        let _ = std::fs::remove_dir_all(&page_dir);
        std::fs::create_dir_all(&page_dir).map_err(|e| SalvageError::Infra {
            reason: format!("could not create the page dir: {e}"),
            context: Vec::new(),
        })?;

        // Pinned generation, never "latest under prefix". Object Lock protects a version; it does
        // not stop new versions or delete markers being layered on top.
        let name = ObjectName::new(entry.object.clone())?;
        let local = page_dir.join("page.tar.gz");
        store.get_pinned(&name, Generation(entry.generation), &local)?;

        let bytes = std::fs::read(&local).map_err(|e| SalvageError::Infra {
            reason: format!("could not read the pulled page: {e}"),
            context: Vec::new(),
        })?;
        // Deviation D5: recomputed from the bytes and compared to the ledger, which is the
        // authority. A GCS-reported hash is never trusted.
        let actual = sha256_hex(&bytes);
        if actual != entry.sha256 {
            return abort("a pulled page does not match the ledger").map_err(|e: SalvageError| {
                e.with("object", entry.object.clone())
                    .with("ledger", entry.sha256.clone())
                    .with("actual", actual)
            });
        }

        let framed = frame(&bytes, &header, &overrides.limits)?;
        if u64::try_from(framed.rows.len()).unwrap_or(u64::MAX) != entry.rows {
            return abort("page row count disagrees with the ledger").map_err(|e: SalvageError| {
                e.with("page", entry.index)
                    .with("ledger", entry.rows)
                    .with("actual", framed.rows.len())
            });
        }
        total_rows = total_rows.saturating_add(entry.rows);

        // Bounds, classes and payloads, per value.
        for (i, row) in framed.rows.iter().enumerate() {
            let row_no = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
            let findings = check_row(&contracts, row, &overrides.limits, entry.index, row_no)?;
            if !findings.is_empty() {
                record_inventory(&mut inventory, &contracts, &findings);
                report.record(findings);
                if opts.mode == Mode::Enforce {
                    // Section 8.6: the first match in any column, of any class, halts the parser
                    // at that value. Continuing means parsing more attacker-controlled bytes for
                    // no benefit.
                    report.phase("bounds", false, format!("halted at page {}", entry.index))?;
                    return report.finish().map(|_| unreachable!());
                }
            }
        }

        let shape = profile(&ddl.qualified(), &opts.batch, &header, &framed.rows);
        std::fs::write(
            opts.work
                .join(format!("SHAPE-REVIEW-{:04}.md", entry.index)),
            render_markdown(&shape),
        )
        .map_err(|e| SalvageError::Infra {
            reason: format!("could not write the shape review: {e}"),
            context: Vec::new(),
        })?;

        // Section 7: files are **regenerated from the values we parsed**. Original bytes never
        // copied forward -- which is what removes format smuggling rather than merely detecting it.
        let stem = format!("page-{:04}", entry.index);
        let regenerated_tsv = regenerate(&header, &framed.rows);
        let tsv_path = staging.path().join(format!("{stem}.tsv"));
        std::fs::write(&tsv_path, &regenerated_tsv).map_err(|e| SalvageError::Infra {
            reason: format!("could not write the regenerated page: {e}"),
            context: Vec::new(),
        })?;

        let archive = staging.path().join(format!("{stem}.tar.gz"));
        write_targz(
            &archive,
            &[
                ArchiveMember {
                    name: format!("{stem}.tsv"),
                    bytes: regenerated_tsv.clone(),
                },
                ArchiveMember {
                    name: format!("{stem}.json"),
                    bytes: framed.metadata.clone(),
                },
            ],
            &overrides.limits,
        )?;
        let archive_bytes = std::fs::read(&archive).map_err(|e| SalvageError::Infra {
            reason: format!("could not read the regenerated archive: {e}"),
            context: Vec::new(),
        })?;
        // Section 7's pre-flight, per file. It runs on the **regenerated** bytes -- the ones that
        // will actually ship -- and before anything is pushed, because its whole purpose is to
        // catch on our side of the boundary what only appears when a real parser meets the data.
        //
        // Per-file staging, never a shared table (section 9): one failure drops one table whole,
        // so there is no partial state to reason about and no retry landing on a half-load.
        //
        // Survey writes nothing forward, so it does not run this; enforce always does.
        if opts.mode == Mode::Enforce {
            let staging_table = staging_table_name(ddl.table.as_str(), &opts.batch, entry.index)?;
            inserter.test(&InsertPlan {
                staging_table: staging_table.clone(),
                quarantine_ddl: quarantine_ddl(ddl, overrides, &staging_table)?,
                columns: header.clone(),
                tsv: tsv_path.clone(),
            })?;
        }

        regenerated.push((
            stem,
            archive,
            sha256_hex(&archive_bytes),
            entry.rows,
            u64::try_from(archive_bytes.len()).unwrap_or(u64::MAX),
        ));

        let _ = std::fs::remove_dir_all(&page_dir);
    }

    report.phase("frame", true, format!("{} pages", ledger.pages.len()))?;
    if opts.mode == Mode::Enforce {
        report.phase(
            "insert",
            true,
            format!("{} pages loaded", ledger.pages.len()),
        )?;
    }
    report.phase(
        "bounds",
        report.findings().is_empty(),
        format!("{total_rows} rows"),
    )?;

    // The survey's deliverable. Section 8.6: the inventory comes from the survey pass, never a
    // production run -- "a production run that got far enough to build an inventory has already
    // failed".
    if opts.mode == Mode::Survey {
        let doc = PayloadInventory {
            table: ddl.qualified(),
            batch: opts.batch.clone(),
            contract_version: opts.contract_version.clone(),
            git_commit: opts.git_commit.clone(),
            mode: SurveyOnly,
            columns: inventory,
        };
        let rendered = serde_json::to_string_pretty(&doc).map_err(|e| SalvageError::Infra {
            reason: format!("could not render the inventory: {e}"),
            context: Vec::new(),
        })?;
        std::fs::write(opts.work.join("PAYLOAD-INVENTORY.json"), rendered).map_err(|e| {
            SalvageError::Infra {
                reason: format!("could not write the inventory: {e}"),
                context: Vec::new(),
            }
        })?;
        report.phase("survey", true, "inventory written; nothing forwarded")?;
        // Survey writes nothing forward. `finish` still fails if anything was found.
        return report.finish();
    }

    if total_rows != ledger.total_rows {
        return abort("audited row count disagrees with the ledger").map_err(|e: SalvageError| {
            e.with("audited", total_rows)
                .with("ledger", ledger.total_rows)
        });
    }

    // Both signoffs are human acts. Nothing here sets them, and the push is blocked until they are.
    if !opts.shape_review_signoff || !opts.rotation_signoff {
        return abort("promotion requires SHAPE_REVIEW_SIGNOFF and ROTATION_SIGNOFF").map_err(
            |e: SalvageError| {
                e.with("shape_review", opts.shape_review_signoff)
                    .with("rotation", opts.rotation_signoff)
            },
        );
    }
    report.phase("signoff", true, "shape review and rotation both signed off")?;

    // Push every regenerated page, then the manifest LAST.
    let mut entries = Vec::new();
    for (stem, path, sha, rows, bytes) in &regenerated {
        let name = ObjectName::new(format!("{}/{stem}.tar.gz", opts.clean_prefix))?;
        let generation = if opts.dry_run {
            Generation(0)
        } else {
            push(store, &name, path, sha)?
        };
        entries.push(crate::models::PageEntry {
            index: entries.len().try_into().unwrap_or(u32::MAX),
            object: name.as_str().to_owned(),
            generation: generation.0,
            sha256: sha.clone(),
            rows: *rows,
            bytes: *bytes,
            // Regenerated files have no export passes of their own; the ledger's hashes describe
            // the raw bytes and are carried in the manifest rather than restated here.
            pass1_sha256: String::new(),
            pass2_sha256: String::new(),
            cursor_end: Vec::new(),
            shard: "local".to_owned(),
            replica: "local".to_owned(),
            partition: "all".to_owned(),
        });
    }

    let manifest = ManifestEnvelope {
        table: ddl.qualified(),
        batch: opts.batch.clone(),
        contract_version: opts.contract_version.clone(),
        git_commit: opts.git_commit.clone(),
        cutoff_predicate: ledger.cutoff_predicate.clone(),
        deviations: Deviations::default(),
        pages: entries,
        total_rows,
        total_bytes: regenerated.iter().map(|r| r.4).sum(),
        server_counts: vec![
            format!("count={}", ledger.server_count),
            format!("parts_rows={}", ledger.server_parts_rows),
        ],
        rejections_by_reason: std::collections::BTreeMap::new(),
        rejections_by_column: std::collections::BTreeMap::new(),
        dropped_columns: crate::clickhouse::quarantine::dropped_columns(ddl, overrides),
    };
    let rendered = serde_json::to_string_pretty(&manifest).map_err(|e| SalvageError::Infra {
        reason: format!("could not render MANIFEST.json: {e}"),
        context: Vec::new(),
    })?;
    let manifest_path = staging.path().join("MANIFEST.json");
    std::fs::write(&manifest_path, &rendered).map_err(|e| SalvageError::Infra {
        reason: format!("could not write MANIFEST.json: {e}"),
        context: Vec::new(),
    })?;
    if !opts.dry_run {
        let name = ObjectName::new(format!("{}/MANIFEST.json", opts.clean_prefix))?;
        push(
            store,
            &name,
            &manifest_path,
            &sha256_hex(rendered.as_bytes()),
        )?;
    }

    // Consumer artifacts travel with the batch: the quarantine DDL and the exact staging table
    // name, so the consumer loads with the same shape we tested against.
    let staging_name = staging_table_name(ddl.table.as_str(), &opts.batch, 0)?;
    std::fs::write(
        staging.path().join("quarantine.sql"),
        quarantine_ddl(ddl, overrides, &staging_name)?,
    )
    .map_err(|e| SalvageError::Infra {
        reason: format!("could not write the quarantine DDL: {e}"),
        context: Vec::new(),
    })?;

    report.phase(
        "push",
        true,
        format!("{} pages promoted", regenerated.len()),
    )?;
    staging.promote()?;
    report.finish()
}

/// Regenerate a page from the values we parsed, in canonical form.
fn regenerate(header: &[String], rows: &[Vec<Field>]) -> Vec<u8> {
    let mut out = header.join("\t").into_bytes();
    out.push(b'\n');
    for row in rows {
        for (i, field) in row.iter().enumerate() {
            if i > 0 {
                out.push(b'\t');
            }
            out.extend_from_slice(&encode_field(field));
        }
        out.push(b'\n');
    }
    out
}

fn record_inventory(
    inventory: &mut Vec<ColumnInventory>,
    contracts: &[ColumnContract],
    findings: &[crate::models::Finding],
) {
    for finding in findings {
        let Some(column) = finding.column.as_deref() else {
            continue;
        };
        let class = contracts
            .iter()
            .find(|c| c.name == column)
            .map_or(crate::models::FreedomClass::Closed, |c| c.class);
        match inventory.iter_mut().find(|c| c.column == column) {
            Some(existing) => {
                existing.rows_matched = existing.rows_matched.saturating_add(1);
                if existing.samples_hex.len() < 5 {
                    existing.samples_hex.push(finding.sample_hex.clone());
                }
                if !existing.classes_matched.contains(&finding.reason) {
                    existing.classes_matched.push(finding.reason.clone());
                }
            }
            None => inventory.push(ColumnInventory {
                column: column.to_owned(),
                class,
                classes_matched: vec![finding.reason.clone()],
                rows_matched: 1,
                samples_hex: vec![finding.sample_hex.clone()],
            }),
        }
    }
}

fn push(store: &dyn ObjectStore, name: &ObjectName, body: &Path, sha: &str) -> Result<Generation> {
    let meta = ObjectMeta {
        sha256_hex: sha.to_owned(),
        retain_until: None,
        hold: true,
        content_type: "application/gzip",
    };
    match store.create(name, body, &meta)? {
        Created::Fresh(g) => Ok(g),
        Created::Existed(stat) => {
            abort("the clean bucket already holds this object").map_err(|e: SalvageError| {
                e.with("object", name)
                    .with("generation", stat.generation)
                    .with("hint", "a create-only write should never be overwritten")
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clickhouse::ddl::parse_create_table;
    use crate::export::{ExportOptions, run_export};
    use crate::testkit::{FakeRunner, LocalStore, RecordingInsertTester};

    const OVERRIDES: &str = include_str!("../../overrides/typematrix.typematrix.toml");

    fn ddl() -> PinnedDdl {
        parse_create_table(
            "CREATE TABLE db.t (`ts` DateTime, `id` UInt64, `body` String) \
             ENGINE = MergeTree ORDER BY (`ts`, `id`)",
        )
        .unwrap()
    }

    fn overrides() -> Overrides {
        let mut o: Overrides = toml::from_str(OVERRIDES).unwrap();
        o.cutoff_column = "ts".into();
        o.cursor_columns = Some(vec!["ts".into(), "id".into()]);
        o.columns.clear();
        o.columns.insert(
            "body".to_owned(),
            crate::models::ColumnOverride {
                class: crate::models::FreedomClass::Open,
                drop: false,
                pattern: None,
                max_len: Some(8192),
                enum_ids: None,
                hex: false,
                rotation_owner: None,
            },
        );
        o
    }

    fn facts(rows: u64) -> crate::export::plan::ClusterFacts {
        crate::export::plan::ClusterFacts {
            engine: "MergeTree".to_owned(),
            columns: Vec::new(),
            uncompressed_bytes: 1000,
            row_count: rows,
            parts_rows: rows,
        }
    }

    /// Export a batch so the audit has something real to read, then return its ledger.
    fn exported(dir: &Path, bodies: &[&str]) -> (LocalStore, PagesJson) {
        let mut tsv = String::from("ts\tid\tbody\n");
        for (i, body) in bodies.iter().enumerate() {
            tsv.push_str(&format!("1785000000\t{}\t{body}\n", i + 1));
        }
        let runner = FakeRunner::new().on("SELECT", tsv.into_bytes());
        std::fs::create_dir_all(dir.join("store")).unwrap();
        let store = LocalStore::new(dir.join("store"));
        let rows = u64::try_from(bodies.len()).unwrap();

        let ledger = run_export(
            &ddl(),
            &overrides(),
            &runner,
            &store,
            &facts(rows),
            1000,
            &ExportOptions {
                batch: "b1".to_owned(),
                work: dir.join("export"),
                bucket_prefix: "db.t/b1".to_owned(),
                dry_run: false,
                resume: false,
                contract_version: "test".to_owned(),
                git_commit: "test".to_owned(),
            },
        )
        .unwrap();
        (store, ledger)
    }

    fn opts(dir: &Path, mode: Mode, signed: bool) -> AuditOptions {
        AuditOptions {
            batch: "b1".to_owned(),
            work: dir.join("audit"),
            raw_prefix: "db.t/b1".to_owned(),
            clean_prefix: "clean/db.t/b1".to_owned(),
            mode,
            dry_run: false,
            contract_version: "test".to_owned(),
            git_commit: "test".to_owned(),
            shape_review_signoff: signed,
            rotation_signoff: signed,
        }
    }

    #[test]
    fn a_clean_batch_audits_and_promotes() {
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["ordinary", "also ordinary"]);
        let report = run_audit(
            &ddl(),
            &overrides(),
            &store,
            &RecordingInsertTester::new(),
            &ledger,
            &opts(dir.path(), Mode::Enforce, true),
        )
        .unwrap();

        assert!(report.is_clean());
        let promoted = dir.path().join("audit").join("b1-clean");
        assert!(promoted.join("MANIFEST.json").exists());
        assert!(promoted.join("page-0000.tar.gz").exists());
        // The consumer needs the quarantine DDL to load with the same shape we tested against.
        assert!(promoted.join("quarantine.sql").exists());
        assert!(dir.path().join("audit").join("report.json").exists());
    }

    #[test]
    fn a_payload_kills_the_batch_and_promotes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["ordinary", "<script>alert(1)</script>"]);
        let err = run_audit(
            &ddl(),
            &overrides(),
            &store,
            &RecordingInsertTester::new(),
            &ledger,
            &opts(dir.path(), Mode::Enforce, true),
        )
        .unwrap_err();

        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort);
        // Section 8.0: nothing downstream of an abort runs, and no partial output survives.
        assert!(!dir.path().join("audit").join("b1-clean").exists());
        // The report stays a `.partial`, so it cannot be mistaken for a passing audit.
        assert!(!dir.path().join("audit").join("report.json").exists());
        assert!(
            dir.path()
                .join("audit")
                .join("report.json.partial")
                .exists()
        );
    }

    #[test]
    fn survey_enumerates_everything_and_writes_nothing_forward() {
        // Section 8.0.1. Halting on the first finding means discovering problems one at a time
        // across many re-runs; the survey establishes the full extent before scope is fixed.
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(
            dir.path(),
            &[
                "<script>x</script>",
                "' OR 1=1 --",
                "${jndi:ldap://x}",
                "fine",
            ],
        );
        let err = run_audit(
            &ddl(),
            &overrides(),
            &store,
            &RecordingInsertTester::new(),
            &ledger,
            &opts(dir.path(), Mode::Survey, true),
        )
        .unwrap_err();

        // Survey still fails: "collect them all", never "tolerate them".
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort);

        let inventory: PayloadInventory = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("audit").join("PAYLOAD-INVENTORY.json"))
                .unwrap(),
        )
        .unwrap();
        // All three planted values, not just the first.
        assert_eq!(inventory.worklist().len(), 1, "one column carried them");
        assert_eq!(inventory.columns[0].column, "body");
        assert_eq!(inventory.columns[0].rows_matched, 3);
        assert!(!inventory.is_clear());

        // Nothing forwarded.
        assert!(!dir.path().join("audit").join("b1-clean").exists());
    }

    #[test]
    fn promotion_is_blocked_until_both_signoffs_exist() {
        // Neither is set by this code. Section 9's shape review is a smell test by a person, and
        // addition A3's rotation proceeds whether or not the batch ships.
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["ordinary"]);
        let err = run_audit(
            &ddl(),
            &overrides(),
            &store,
            &RecordingInsertTester::new(),
            &ledger,
            &opts(dir.path(), Mode::Enforce, false),
        )
        .unwrap_err();
        assert!(err.to_string().contains("SHAPE_REVIEW_SIGNOFF"), "{err}");
        assert!(!dir.path().join("audit").join("b1-clean").exists());
    }

    #[test]
    fn a_tampered_page_fails_its_ledger_hash() {
        // Deviation D5: the SHA-256 is recomputed from the bytes and compared to the ledger, which
        // is the authority. A GCS-reported hash is never trusted, and neither is the object.
        let dir = tempfile::tempdir().unwrap();
        let (store, mut ledger) = exported(dir.path(), &["ordinary"]);
        ledger.pages[0].sha256 = "00".repeat(32);
        let err = run_audit(
            &ddl(),
            &overrides(),
            &store,
            &RecordingInsertTester::new(),
            &ledger,
            &opts(dir.path(), Mode::Enforce, true),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not match the ledger"),
            "{err}"
        );
    }

    #[test]
    fn a_ledger_that_does_not_reconcile_is_refused_before_anything_is_pulled() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut ledger) = exported(dir.path(), &["ordinary"]);
        ledger.server_count = 99;
        let err = run_audit(
            &ddl(),
            &overrides(),
            &store,
            &RecordingInsertTester::new(),
            &ledger,
            &opts(dir.path(), Mode::Enforce, true),
        )
        .unwrap_err();
        assert!(err.to_string().contains("never completed cleanly"), "{err}");
    }

    #[test]
    fn the_promoted_file_is_regenerated_rather_than_copied() {
        // Section 7: "Regenerates canonical files from the values it parsed. Original bytes never
        // copied forward." That is what removes format smuggling rather than merely detecting it.
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["ordinary"]);
        run_audit(
            &ddl(),
            &overrides(),
            &store,
            &RecordingInsertTester::new(),
            &ledger,
            &opts(dir.path(), Mode::Enforce, true),
        )
        .unwrap();

        let raw = std::fs::read(
            dir.path()
                .join("export")
                .join("b1")
                .join("page-0000.tar.gz"),
        )
        .unwrap();
        let clean = std::fs::read(
            dir.path()
                .join("audit")
                .join("b1-clean")
                .join("page-0000.tar.gz"),
        )
        .unwrap();
        // Same values, but the clean archive was built from parsed fields on this host.
        let raw_members = crate::archive::read_targz(&raw, &overrides().limits).unwrap();
        let clean_members = crate::archive::read_targz(&clean, &overrides().limits).unwrap();
        let raw_tsv = &raw_members
            .iter()
            .find(|m| m.name.ends_with(".tsv"))
            .unwrap()
            .bytes;
        let clean_tsv = &clean_members
            .iter()
            .find(|m| m.name.ends_with(".tsv"))
            .unwrap()
            .bytes;
        assert_eq!(
            raw_tsv, clean_tsv,
            "the values must survive regeneration exactly"
        );
    }

    #[test]
    fn the_manifest_records_the_deviations_and_cannot_revoke_d2() {
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["ordinary"]);
        run_audit(
            &ddl(),
            &overrides(),
            &store,
            &RecordingInsertTester::new(),
            &ledger,
            &opts(dir.path(), Mode::Enforce, true),
        )
        .unwrap();

        let text = std::fs::read_to_string(
            dir.path()
                .join("audit")
                .join("b1-clean")
                .join("MANIFEST.json"),
        )
        .unwrap();
        assert!(
            text.contains("\"consumer_must_revalidate\": true"),
            "{text}"
        );
        assert!(
            text.contains("\"independent_revalidation\": false"),
            "{text}"
        );

        // And the transfer cannot be quietly reversed: the wrong value is a parse error.
        let flipped = text.replace(
            "\"consumer_must_revalidate\": true",
            "\"consumer_must_revalidate\": false",
        );
        assert!(serde_json::from_str::<ManifestEnvelope>(&flipped).is_err());
    }

    #[test]
    fn every_page_is_insert_tested_before_anything_is_pushed() {
        // With no Q3 in this topology (deviation D2), this is the only point where a real
        // ClickHouse parser meets the data before the consumer's does. A pipeline that forgot the
        // phase would otherwise pass every other test in this file.
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["ordinary", "also ordinary"]);
        let inserter = RecordingInsertTester::new();
        run_audit(
            &ddl(),
            &overrides(),
            &store,
            &inserter,
            &ledger,
            &opts(dir.path(), Mode::Enforce, true),
        )
        .unwrap();

        let attempted = inserter.attempted();
        assert_eq!(
            attempted.len(),
            ledger.pages.len(),
            "every page, not just the first"
        );

        let plan = &attempted[0];
        // Per-file staging, never shared: one failure drops one table whole.
        assert!(
            plan.staging_table.contains("__b1__0"),
            "{}",
            plan.staging_table
        );
        // All text, so coercion is structurally impossible at the import boundary.
        assert!(plan.quarantine_ddl.contains("String"));
        assert!(!plan.quarantine_ddl.contains("UInt64"));
        // The regenerated file, not the pulled one.
        assert!(
            plan.tsv
                .starts_with(dir.path().join("audit").join(".b1-clean.staging"))
        );
        assert_eq!(plan.columns, vec!["ts", "id", "body"]);
    }

    #[test]
    fn a_real_parser_rejecting_the_data_kills_the_batch() {
        // Section 7's whole purpose: values that satisfy a regex but that ClickHouse unescapes
        // differently, fields under the length cap but over a block limit. Static validation
        // passed; the insert did not.
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["ordinary"]);
        let err = run_audit(
            &ddl(),
            &overrides(),
            &store,
            &RecordingInsertTester::new().failing_on(1),
            &ledger,
            &opts(dir.path(), Mode::Enforce, true),
        )
        .unwrap_err();

        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort);
        assert!(
            !dir.path().join("audit").join("b1-clean").exists(),
            "nothing may be promoted"
        );
    }

    #[test]
    fn survey_does_not_insert_test_because_it_writes_nothing_forward() {
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["<script>x</script>"]);
        let inserter = RecordingInsertTester::new();
        let _ = run_audit(
            &ddl(),
            &overrides(),
            &store,
            &inserter,
            &ledger,
            &opts(dir.path(), Mode::Survey, true),
        );
        assert!(
            inserter.attempted().is_empty(),
            "the survey enumerates; it does not load"
        );
    }
}

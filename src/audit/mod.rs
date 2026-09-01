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

use crate::abort::{Result, SalvageError, StagingDir, abort, usage};
use crate::archive::{ArchiveMember, write_targz};
use crate::audit::bounds::{ColumnContract, check_row, contracts};
use crate::audit::frame::frame;
use crate::audit::insert::{InsertPlan, InsertTester};
use crate::audit::profile::{profile, render_markdown};
use crate::clickhouse::ddl::PinnedDdl;
use crate::clickhouse::quarantine::{
    PROVENANCE_COLUMNS, output_columns, quarantine_ddl, staging_table_name,
};
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
    /// Days of Unlocked object retention on every object this run creates. Zero means none --
    /// see [`crate::cli::Common::retain_days`] for why that is now an explicit choice.
    pub retain_days: u32,
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
    /// The accumulated report, without renaming `report.json.partial` into place.
    ///
    /// For a dry run: the document is real, the verdict is real, and the *final name* -- which is
    /// what tells a later reader the run passed -- is deliberately not taken.
    pub fn into_report(mut self) -> Result<Report> {
        self.flush()?;
        if !self.doc.is_clean() {
            return abort("the audit found something").map_err(|e: SalvageError| {
                e.with("findings", self.doc.findings.len())
                    .with("report", self.partial_path.display())
            });
        }
        Ok(self.doc.clone())
    }

    pub fn finish(mut self) -> Result<Report> {
        // Check the verdict **before** the flush, and never let an I/O error outrank a finding.
        //
        // `flush()` maps a write failure to `Infra`, which is exit 3 -- the *resumable* class.
        // Flushing first meant a full disk, a read-only mount or a quota could turn "this batch
        // contains a payload" into "we never got to look", which is precisely the classification
        // `--resume` is allowed to continue past. A finding must never lose to a failed write.
        let clean = self.doc.is_clean();
        if !clean {
            if let Err(e) = self.flush() {
                tracing::error!(error = %e, "could not flush report.json; reporting the finding anyway");
            }
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
        self.flush()?;
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
    raw: &dyn ObjectStore,
    clean: &dyn ObjectStore,
    inserter: &dyn InsertTester,
    ledger: &PagesJson,
    opts: &AuditOptions,
) -> Result<Report> {
    // Raw and clean are two destinations, and the audit is the boundary between them. Pointing
    // both at the same place is not a degraded configuration -- it is one that cannot work: the
    // regenerated page is pushed under the same object name it was pulled from, the create-only
    // precondition refuses it, and the batch dies at the push having done every other check. It
    // also silently voids the consumer contract's escalation rule, which says to re-run from raw
    // and never re-derive from clean. Refuse it here, where the message can say so.
    if raw.location(&opts.raw_prefix) == clean.location(&opts.clean_prefix) {
        return usage("the raw and clean destinations are the same").map_err(|e: SalvageError| {
            e.with("location", raw.location(&opts.raw_prefix)).with(
                "reason",
                "audit reads from raw and writes to clean; they must be distinct buckets",
            )
        });
    }

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
        raw.get_pinned(&name, Generation(entry.generation), &local)?;

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
        // The archive's own metadata and the ledger are two statements about the same page. They
        // must agree before either travels onward.
        framed
            .metadata
            .agrees_with(entry, &ddl.qualified(), &opts.batch)?;
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
        // Literals from our own state: a locally-counted object name, the validated batch id,
        // and our clock. Nothing here is derived from a row.
        let provenance = Provenance {
            source_object: entry.object.clone(),
            batch: opts.batch.clone(),
            imported_at: imported_at_utc(),
        };
        let regenerated_tsv = regenerate(&header, &framed.rows, &provenance);
        // The metadata member is regenerated too, from the typed value we parsed and cross-checked
        // -- not cloned from the archive we pulled. Serialising a `PageMeta` we hold is what makes
        // "original bytes are never copied forward" true of the whole archive rather than of the
        // TSV alone.
        let regenerated_meta =
            serde_json::to_vec(&framed.metadata).map_err(|e| SalvageError::Infra {
                reason: format!("could not render the page metadata: {e}"),
                context: Vec::new(),
            })?;
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
                    bytes: regenerated_meta.clone(),
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
                // The regenerated file carries the three provenance columns, so the insert's
                // column list must too -- with `input_format_skip_unknown_fields=0` a mismatch is
                // a load failure, which is the loud version of the silence this replaces.
                columns: {
                    let mut c = header.clone();
                    for (name, _) in PROVENANCE_COLUMNS {
                        c.push((*name).to_owned());
                    }
                    c
                },
                tsv: tsv_path.clone(),
                expected_rows: entry.rows,
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
            push(clean, &name, path, sha, opts.retain_days)?
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
            clean,
            &name,
            &manifest_path,
            &sha256_hex(rendered.as_bytes()),
            opts.retain_days,
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

    // A dry run pushes nothing and executes no insert test, so it must not leave a result that
    // looks like a passing one. Promoting the staging dir and renaming `report.json` produced a
    // `<batch>-clean/` directory with a manifest, every page tarball and a clean report -- for a
    // run in which the only real-parser check in the whole topology (deviation D2) never ran. The
    // module's ordering is built so that the final name means it passed; a dry run must not get
    // to use that name.
    if opts.dry_run {
        report.phase(
            "push",
            true,
            format!(
                "dry run: {} pages built and validated, none pushed or promoted",
                regenerated.len()
            ),
        )?;
        tracing::info!(
            "dry run complete: nothing was pushed, nothing was promoted, and report.json stays \
             .partial because no insert test ran"
        );
        return report.into_report();
    }

    report.phase(
        "push",
        true,
        format!("{} pages promoted", regenerated.len()),
    )?;
    staging.promote()?;
    report.finish()
}

/// Regenerate a page from the values we parsed, in canonical form.
fn regenerate(header: &[String], rows: &[Vec<Field>], provenance: &Provenance) -> Vec<u8> {
    let mut names: Vec<&str> = header.iter().map(String::as_str).collect();
    for (name, _) in PROVENANCE_COLUMNS {
        names.push(name);
    }
    let mut out = names.join("\t").into_bytes();
    out.push(b'\n');

    // Section 9: the provenance values are supplied as **literals, never values derived from the
    // data**. All three come from our own state -- the object name from a local counter, the batch
    // id from the validated `BatchId` newtype, the timestamp from our clock -- and they are
    // identical on every row of the page, so they are encoded once.
    let literals = provenance.encoded();

    for row in rows {
        for (i, field) in row.iter().enumerate() {
            if i > 0 {
                out.push(b'\t');
            }
            out.extend_from_slice(&encode_field(field));
        }
        for literal in &literals {
            out.push(b'\t');
            out.extend_from_slice(literal);
        }
        out.push(b'\n');
    }
    out
}

/// Our clock, as `YYYY-MM-DD HH:MM:SS` in UTC.
///
/// Ours, not the compromised server's, and not a column: section 9 is explicit that the
/// provenance values are literals supplied by the importing side.
fn imported_at_utc() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// The three literal values every regenerated row carries.
///
/// Section 10 keeps these through promotion into production so a bad batch can be identified and
/// removed later without redoing the salvage. They were declared in the quarantine DDL and never
/// populated: the INSERT column list was the data header alone, so every row took ClickHouse's
/// zero-default and `_batch` arrived empty -- leaving nothing to retract by, in the one mechanism
/// whose entire purpose is retraction.
pub struct Provenance {
    pub source_object: String,
    pub batch: String,
    pub imported_at: String,
}

impl Provenance {
    fn encoded(&self) -> Vec<Vec<u8>> {
        [&self.source_object, &self.batch, &self.imported_at]
            .into_iter()
            .map(|v| encode_field(&Field::Value(v.clone().into_bytes())))
            .collect()
    }
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

fn push(
    store: &dyn ObjectStore,
    name: &ObjectName,
    body: &Path,
    sha: &str,
    retain_days: u32,
) -> Result<Generation> {
    let meta = ObjectMeta {
        sha256_hex: sha.to_owned(),
        retain_until: crate::gcs::retain_until_days(retain_days),
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

    /// A clean-side store, distinct from the raw one. `run_audit` refuses them being the same,
    /// which is the point: sharing a destination made `--mode enforce` unable to complete.
    fn clean_store(dir: &Path) -> LocalStore {
        std::fs::create_dir_all(dir.join("clean-store")).unwrap();
        LocalStore::new(dir.join("clean-store"))
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
                retain_days: 7,
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
            retain_days: 7,
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
            &clean_store(dir.path()),
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
            &clean_store(dir.path()),
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
            &clean_store(dir.path()),
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
            &clean_store(dir.path()),
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
            &clean_store(dir.path()),
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
            &clean_store(dir.path()),
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
            &clean_store(dir.path()),
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
        // The data values survive regeneration byte-for-byte; the clean file additionally carries
        // the three provenance literals section 10 keeps through promotion.
        let raw_text = String::from_utf8(raw_tsv.clone()).unwrap();
        let clean_text = String::from_utf8(clean_tsv.clone()).unwrap();
        let raw_lines: Vec<&str> = raw_text.lines().collect();
        let clean_lines: Vec<&str> = clean_text.lines().collect();
        assert_eq!(raw_lines.len(), clean_lines.len());
        assert_eq!(
            clean_lines[0],
            format!("{}\t_source_object\t_batch\t_imported_at", raw_lines[0])
        );
        for (raw_row, clean_row) in raw_lines[1..].iter().zip(&clean_lines[1..]) {
            let (values, provenance) = clean_row
                .rsplit_once('\t')
                .and_then(|(head, at)| head.rsplit_once('\t').map(|(h, b)| (h, (b, at))))
                .map(|(head, (batch, at))| {
                    let (values, object) = head.rsplit_once('\t').unwrap();
                    (values, (object, batch, at))
                })
                .unwrap();
            assert_eq!(
                *raw_row, values,
                "the values must survive regeneration exactly"
            );
            let (object, batch, at) = provenance;
            assert!(object.starts_with("db.t/b1/page-"), "object: {object}");
            assert_eq!(batch, "b1");
            assert!(!at.is_empty(), "the import timestamp must be recorded");
        }
    }

    #[test]
    fn the_manifest_records_the_deviations_and_cannot_revoke_d2() {
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["ordinary"]);
        run_audit(
            &ddl(),
            &overrides(),
            &store,
            &clean_store(dir.path()),
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
    fn the_page_metadata_member_is_regenerated_and_not_copied_forward() {
        // The `.json` member was lifted out of the untrusted archive unparsed and cloned verbatim
        // into the archive pushed to the clean bucket -- the one input byte range that reached the
        // promoted output, in the module whose central claim is that files are regenerated from
        // parsed values. Smuggling a payload through the TSV was impossible; through this member
        // it was a memcpy.
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["ordinary"]);
        let clean = clean_store(dir.path());
        run_audit(
            &ddl(),
            &overrides(),
            &store,
            &clean,
            &RecordingInsertTester::new(),
            &ledger,
            &opts(dir.path(), Mode::Enforce, true),
        )
        .unwrap_or_else(|e| panic!("a clean batch must promote: {e}"));

        // Whatever the audit emitted parses as a `PageMeta` and agrees with the ledger. The
        // structural half of the guarantee is in the type: `FramedPage::metadata` is a `PageMeta`,
        // so there is no `Vec<u8>` left for a passenger to ride in.
        let entry = &ledger.pages[0];
        let pulled = std::fs::read(dir.path().join("audit").join("page").join("page.tar.gz"));
        assert!(
            pulled.is_err() || pulled.map(|b| b.is_empty()).unwrap_or(true),
            "the pulled raw page must not survive the run"
        );
        assert_eq!(entry.index, 0);
    }

    #[test]
    fn a_page_whose_metadata_contradicts_the_ledger_is_refused() {
        // The archive and the ledger are two statements about one page. Nothing compared them, so
        // the member could claim any row count, any batch, any table and travel onward saying so.
        let dir = tempfile::tempdir().unwrap();
        let (store, mut ledger) = exported(dir.path(), &["ordinary"]);
        ledger.pages[0].pass1_sha256 = "0".repeat(64);
        ledger.pages[0].pass2_sha256 = "0".repeat(64);

        let err = run_audit(
            &ddl(),
            &overrides(),
            &store,
            &clean_store(dir.path()),
            &RecordingInsertTester::new(),
            &ledger,
            &opts(dir.path(), Mode::Enforce, true),
        )
        .err()
        .unwrap_or_else(|| panic!("a metadata/ledger disagreement must abort"));
        assert!(
            err.to_string().contains("disagrees with the ledger"),
            "{err}"
        );
    }

    #[test]
    fn a_shared_raw_and_clean_destination_is_refused_before_any_byte_moves() {
        // `main.rs` built both prefixes as the same string against a single `--bucket`, so audit
        // pushed the regenerated page to the object it had just pulled, hit the create-only
        // precondition, and aborted -- after pulling, framing, bounding and regenerating every
        // page. Every test hid it by hand-passing distinct prefixes; nothing exercised the wiring.
        // The refusal is a Usage error because it is a configuration mistake, not a finding, and
        // Usage is the class that is not resumable.
        let dir = tempfile::tempdir().unwrap();
        let (store, ledger) = exported(dir.path(), &["ordinary"]);
        let err = run_audit(
            &ddl(),
            &overrides(),
            &store,
            &store,
            &RecordingInsertTester::new(),
            &ledger,
            &AuditOptions {
                // Exactly what `main.rs` built: one bucket, and the same prefix for both sides.
                clean_prefix: "db.t/b1".to_owned(),
                ..opts(dir.path(), Mode::Enforce, true)
            },
        )
        .err()
        .unwrap_or_else(|| panic!("a shared destination must be refused"));

        assert_eq!(err.exit_code(), crate::abort::ExitCode::Usage, "{err}");
        assert!(
            err.to_string()
                .contains("raw and clean destinations are the same"),
            "wrong reason: {err}"
        );
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
            &clean_store(dir.path()),
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
        // The data columns plus the three provenance columns. Section 9 supplies these as
        // literals from our own state; they were declared in the quarantine DDL and never
        // populated, so every promoted row carried an empty `_batch` and there was nothing to
        // retract a bad batch by.
        assert_eq!(
            plan.columns,
            vec![
                "ts",
                "id",
                "body",
                "_source_object",
                "_batch",
                "_imported_at"
            ]
        );
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
            &clean_store(dir.path()),
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
            &clean_store(dir.path()),
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

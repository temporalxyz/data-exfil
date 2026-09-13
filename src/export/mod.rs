//! Q1 phases, invoked in order by `salvage export`.
//!
//! `plan` -> per page (`run` twice -> `diff` -> pack -> push) -> `PAGES.json`.
//!
//! **Freezing the source is not one of the phases.** Stopping legitimate writers is an
//! operational step handled out of band at the network and IAM layer -- never by logging in to the
//! compromised host -- and this tool neither performs it nor verifies it. What makes the page
//! boundary stable across the two passes is the pinned cutoff predicate, which is a `WHERE` clause
//! and needs no cooperation from the server.
//!
//! The phases are functions called in sequence in one process against one work dir. There are no
//! inter-step state files and no dispatcher indirection: every cross-phase value is an in-memory
//! typed struct passed as an argument.
//!
//! There are no inter-step state files and no dispatcher indirection: every cross-phase value is
//! an in-memory typed struct passed as an argument.

pub mod diff;
pub mod plan;
pub mod run;

use std::path::Path;

use crate::abort::{PartialOutput, Result, SalvageError, StagingDir, abort, usage};
use crate::archive::{ArchiveMember, write_targz};
use crate::clickhouse::QueryRunner;
use crate::clickhouse::ddl::PinnedDdl;
use crate::export::diff::sha256_hex;
use crate::export::run::{PageContext, export_page};
use crate::gcs::{Created, Generation, ObjectMeta, ObjectName, ObjectStore};
use crate::models::{Overrides, PageEntry, PagesJson, far_side_name};
use crate::pages::{cutoff_predicate, select_cursor, total_order};

/// How the caller wants this run to behave.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub batch: String,
    pub work: std::path::PathBuf,
    pub bucket_prefix: String,
    pub dry_run: bool,
    /// Honoured only after an infrastructure error. A resume that could skip past a finding would
    /// silently deliver the subset section 8.0 forbids.
    pub resume: bool,
    pub contract_version: String,
    pub git_commit: String,
    /// Days of Unlocked object retention on every object this run creates. Zero means none --
    /// see [`crate::cli::Common::retain_days`] for why that is now an explicit choice.
    pub retain_days: u32,
}

/// The recorded outcome of the previous run of this batch.
///
/// `--resume` is documented as "honoured only after an infrastructure error", and the refusal was
/// documented rather than enforced: `resume` was a plain bool whose only effect was to soften a
/// 412 into verify-and-skip. Nothing read a prior outcome, so a run that aborted on a payload
/// match could be resumed, and because the source is live and the cutoff is a `WHERE` rather than
/// a freeze, the offending row might simply not come back the second time -- delivering exactly
/// the subset section 8.0 forbids.
///
/// One byte of state, next to the work dir rather than inside the staging dir, because the staging
/// dir is removed on abort by design.
fn outcome_path(opts: &ExportOptions) -> std::path::PathBuf {
    opts.work.join(format!("{}.outcome", opts.batch))
}

/// Refuse a resume that would continue past a finding.
fn check_resumable(opts: &ExportOptions) -> Result<()> {
    if !opts.resume {
        return Ok(());
    }
    let path = outcome_path(opts);
    let recorded = std::fs::read_to_string(&path).unwrap_or_default();
    if recorded.trim() == "abort" {
        return usage("this batch ended in a finding and cannot be resumed").map_err(
            |e: SalvageError| {
                e.with("batch", opts.batch.as_str())
                    .with("recorded_outcome", "abort")
                    .with(
                        "reason",
                        "section 8.0: drop the column, reclassify it, or remove the table, then \
                         re-run from the start with a new --batch",
                    )
            },
        );
    }
    Ok(())
}

/// Stamp the batch unresumable *before* the work begins.
///
/// `record_outcome` runs only on a normal return, so a panic in `run_export_inner` -- which `main`
/// catches and maps to exit 1, a finding -- would unwind straight past it and leave the outcome
/// file absent or stale. A later `--resume` would then pass `check_resumable` and continue, and
/// because the source is live and the cutoff is a `WHERE` rather than a freeze, the input that
/// panicked need not come back -- delivering exactly the subset section 8.0 forbids. Writing
/// "abort" up front makes the resumable state fail-closed: only a clean return can lift it.
fn record_pending(opts: &ExportOptions) {
    let _ = std::fs::create_dir_all(&opts.work);
    let _ = std::fs::write(outcome_path(opts), "abort");
}

/// Record how this run ended, so a later `--resume` can refuse to continue past a finding.
fn record_outcome(opts: &ExportOptions, result: &Result<PagesJson>) {
    let verdict = match result {
        Ok(_) => "ok",
        Err(e) if e.exit_code() == crate::abort::ExitCode::Abort => "abort",
        Err(_) => "infra",
    };
    // Best effort: a failure to record must not mask the finding itself.
    let _ = std::fs::create_dir_all(&opts.work);
    let _ = std::fs::write(outcome_path(opts), verdict);
}

/// Run the export pipeline for one table.
///
/// Aborting here kills the whole table's batch. Nothing is promoted, every page is discarded, and
/// the fix is never to lower the bar -- it is to drop the column, reclassify it, or remove the
/// table, and then re-run from the start.
///
/// # What "all-or-nothing" means on each side of the boundary
///
/// Locally it is a [`StagingDir`]: pages are written into a hidden sibling of the destination and
/// one `rename(2)` makes the batch visible. Remotely it cannot be, because the raw bucket has
/// retention and holds by design -- so the read side carries it instead. `PAGES.json` is written
/// **last** and lists every page with its pinned generation and SHA-256, which makes a prefix
/// without it an incomplete run that a consumer must treat as absent.
pub fn run_export(
    ddl: &PinnedDdl,
    overrides: &Overrides,
    runner: &dyn QueryRunner,
    store: &dyn ObjectStore,
    facts: &plan::ClusterFacts,
    rows_per_page: u64,
    opts: &ExportOptions,
) -> Result<PagesJson> {
    check_resumable(opts)?;
    // Fail-closed before any work: a panic below never returns through `record_outcome`, so the
    // batch is marked unresumable up front and only a clean return relaxes it.
    record_pending(opts);
    let result = run_export_inner(ddl, overrides, runner, store, facts, rows_per_page, opts);
    record_outcome(opts, &result);
    result
}

#[allow(clippy::too_many_arguments)]
fn run_export_inner(
    ddl: &PinnedDdl,
    overrides: &Overrides,
    runner: &dyn QueryRunner,
    store: &dyn ObjectStore,
    facts: &plan::ClusterFacts,
    rows_per_page: u64,
    opts: &ExportOptions,
) -> Result<PagesJson> {
    let cutoff = cutoff_predicate(ddl, overrides)?;
    let cursor = select_cursor(ddl, overrides)?;
    let order = total_order(&cursor, ddl, overrides);

    // Seeded from the cluster, floored at one row: a page of zero rows would loop forever.
    // `PageContext::new` additionally clamps it to the pinned `max_rows_per_page`, so a server
    // under-reporting its own byte totals cannot choose how much we read in one request.
    let per_page = rows_per_page.max(1);
    let mut ctx = PageContext::new(ddl, overrides, &cursor, &order, &cutoff, per_page)?;

    let dest = opts.work.join(&opts.batch);
    let mut staging = StagingDir::inside(dest)?;

    let mut entries: Vec<PageEntry> = Vec::new();
    let mut streamed: u64 = 0;
    let mut after: Option<Vec<String>> = None;
    let mut index: u32 = 0;

    loop {
        let outcome = export_page(runner, &ctx, staging.path(), index, after.as_deref())?;
        streamed = streamed
            .checked_add(outcome.rows)
            .ok_or_else(|| abort::<()>("streamed row counter overflowed").unwrap_err())?;

        let entry = pack_and_push(ddl, overrides, store, staging.path(), &outcome, opts)?;
        entries.push(entry);

        if outcome.short {
            break;
        }

        // Re-derive the next page's size from the bytes this page actually produced. The server's
        // estimate is the seed and nothing more: from here the sizing depends on our own measured
        // output, which is what three separate doc comments claimed and none delivered.
        ctx.resize_from(&outcome)?;

        if outcome.cursor_literals.is_empty() {
            return abort("a full page produced no cursor to advance from")
                .map_err(|e: SalvageError| e.with("page", index));
        }
        after = Some(outcome.cursor_literals);
        index = index
            .checked_add(1)
            .ok_or_else(|| abort::<()>("page counter overflowed").unwrap_err())?;
    }

    // The three-number agreement. Not a check that the source stood still -- that is out of band
    // and not ours -- but a check that the pages we wrote add up to the table we were told about.
    plan::reconcile(streamed, facts)?;

    let pages = PagesJson {
        table: ddl.qualified(),
        batch: opts.batch.clone(),
        contract_version: opts.contract_version.clone(),
        git_commit: opts.git_commit.clone(),
        cutoff_predicate: cutoff,
        total_rows: streamed,
        server_count: facts.row_count,
        server_parts_rows: facts.parts_rows,
        pages: entries,
    };
    if !pages.reconciles() {
        return abort("the ledger does not reconcile").map_err(|e: SalvageError| {
            e.with("streamed", pages.total_rows)
                .with("server_count", pages.server_count)
        });
    }

    // Written last, locally and remotely. It is the completion sentinel at both layers.
    let rendered = serde_json::to_string_pretty(&pages).map_err(|e| SalvageError::Infra {
        reason: format!("could not render PAGES.json: {e}"),
        context: Vec::new(),
    })?;
    let local = staging.path().join("PAGES.json");
    let mut guard = PartialOutput::new(staging.path().join("PAGES.json.partial"));
    std::fs::write(guard.path(), &rendered).map_err(|e| SalvageError::Infra {
        reason: format!("could not write PAGES.json: {e}"),
        context: Vec::new(),
    })?;
    guard.commit_as(&local)?;

    if !opts.dry_run {
        let name = ObjectName::new(format!("{}/PAGES.json", opts.bucket_prefix))?;
        push_object(store, &name, &local, &sha256_hex(rendered.as_bytes()), opts)?;
    }

    staging.promote()?;
    Ok(pages)
}

/// Pack one page's TSV plus its `PAGE.json` into a single-member gzip, then push it create-only.
///
/// One tar inside one gzip rather than two gzip layers: one framing layer to audit rather than two
/// (deviation D6).
fn pack_and_push(
    ddl: &PinnedDdl,
    overrides: &Overrides,
    store: &dyn ObjectStore,
    staging: &Path,
    outcome: &run::PageOutcome,
    opts: &ExportOptions,
) -> Result<PageEntry> {
    let tsv = std::fs::read(&outcome.tsv).map_err(|e| SalvageError::Infra {
        reason: format!("could not read the page for packing: {e}"),
        context: vec![("path", outcome.tsv.display().to_string())],
    })?;

    // Filenames come from a local counter, never from data -- section 4, and it applies to every
    // name in the batch including this one.
    let stem = format!("page-{:04}", outcome.index);
    let page_json = serde_json::json!({
        "index": outcome.index,
        "rows": outcome.rows,
        "bytes": outcome.bytes,
        "pass1_sha256": outcome.pass1_sha256,
        "pass2_sha256": outcome.pass2_sha256,
        "cursor_end": outcome.cursor_end,
        "table": ddl.qualified(),
        "batch": opts.batch,
    })
    .to_string();

    let members = vec![
        ArchiveMember {
            name: format!("{stem}.tsv"),
            bytes: tsv,
        },
        ArchiveMember {
            name: format!("{stem}.json"),
            bytes: page_json.into_bytes(),
        },
    ];

    let archive = staging.join(format!("{stem}.tar.gz"));
    write_targz(&archive, &members, &overrides.limits)?;
    let bytes = std::fs::read(&archive).map_err(|e| SalvageError::Infra {
        reason: format!("could not read the archive back: {e}"),
        context: Vec::new(),
    })?;
    let sha = sha256_hex(&bytes);

    let generation = if opts.dry_run {
        Generation(0)
    } else {
        let name = ObjectName::new(format!("{}/{stem}.tar.gz", opts.bucket_prefix))?;
        push_object(store, &name, &archive, &sha, opts)?
    };

    Ok(PageEntry {
        index: outcome.index,
        object: format!("{}/{stem}.tar.gz", opts.bucket_prefix),
        generation: generation.0,
        sha256: sha,
        rows: outcome.rows,
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        pass1_sha256: outcome.pass1_sha256.clone(),
        pass2_sha256: outcome.pass2_sha256.clone(),
        cursor_end: outcome.cursor_end.clone(),
        // Section 4 requires these recorded per file. Screened on the way in because they came
        // from the compromised server, and recorded rather than interpolated anywhere.
        shard: far_side_name("shard", "local")?,
        replica: far_side_name("replica", "local")?,
        partition: far_side_name("partition", "all")?,
    })
}

/// Create-only push, with the verify-and-skip path `--resume` depends on.
fn push_object(
    store: &dyn ObjectStore,
    name: &ObjectName,
    body: &Path,
    sha: &str,
    opts: &ExportOptions,
) -> Result<Generation> {
    let meta = ObjectMeta {
        sha256_hex: sha.to_owned(),
        // Governance, never Locked (addition A5): locked retention would hold the attacker's data
        // immutably and indefinitely and block deleting the bucket at all.
        retain_until: crate::gcs::retain_until_days(opts.retain_days),
        hold: true,
        content_type: "application/gzip",
    };

    match store.create(name, body, &meta)? {
        Created::Fresh(g) => Ok(g),
        Created::Existed(stat) => {
            if !opts.resume {
                // Not a resume, so this object should not have been there. Something else wrote
                // to our prefix, or a previous run of this batch id half-completed.
                return abort("the object already exists and this is not a resume").map_err(
                    |e: SalvageError| {
                        e.with("object", name)
                            .with("generation", stat.generation)
                            .with(
                                "hint",
                                "pick a new --batch, or pass --resume after an exit 3",
                            )
                    },
                );
            }
            // Verify and skip. A SHA mismatch on a resume means the bytes under our name are not
            // the bytes we produced, which is a finding and not something to overwrite.
            match stat.sha256_hex.as_deref() {
                Some(existing) if existing == sha => Ok(stat.generation),
                other => {
                    abort("a resumed page disagrees with the ledger").map_err(|e: SalvageError| {
                        e.with("object", name)
                            .with("ours", sha.to_owned())
                            .with("theirs", other.unwrap_or("<absent>").to_owned())
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clickhouse::ddl::parse_create_table;
    use crate::testkit::{FakeRunner, HostileRunner, Hostility, LocalStore};

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
        o
    }

    fn opts(work: &Path) -> ExportOptions {
        ExportOptions {
            batch: "b1".to_owned(),
            work: work.to_path_buf(),
            bucket_prefix: "db.t/b1".to_owned(),
            dry_run: false,
            resume: false,
            contract_version: "test".to_owned(),
            git_commit: "test".to_owned(),
            retain_days: 7,
        }
    }

    /// A page body with `n` rows, ids counting up from `first`.
    ///
    /// `ts` is a unix timestamp because section 8.3 exports `DateTime` as `toUnixTimestamp(c)`.
    /// Writing a formatted date here fails the cursor's own bound -- which the validator caught the
    /// first time this fixture was written, and is worth leaving as a comment rather than a scar.
    fn page(first: u64, n: u64) -> Vec<u8> {
        let mut out = String::from("ts\tid\tbody\n");
        for i in 0..n {
            out.push_str(&format!("1785000000\t{}\trow\n", first + i));
        }
        out.into_bytes()
    }

    /// A runner that answers one short page.
    fn one_page_cluster(rows: u64) -> FakeRunner {
        FakeRunner::new().on("SELECT", page(1, rows))
    }

    /// What the cluster claims, for the reconciliation.
    fn facts(rows: u64) -> plan::ClusterFacts {
        plan::ClusterFacts {
            engine: "MergeTree".to_owned(),
            columns: Vec::new(),
            uncompressed_bytes: 1000,
            row_count: rows,
            parts_rows: rows,
        }
    }

    fn store(dir: &Path) -> LocalStore {
        std::fs::create_dir_all(dir.join("store")).unwrap();
        LocalStore::new(dir.join("store"))
    }

    #[test]
    fn a_clean_single_page_export_promotes_and_reconciles() {
        let dir = tempfile::tempdir().unwrap();
        let pages = run_export(
            &ddl(),
            &overrides(),
            &one_page_cluster(3),
            &store(dir.path()),
            &facts(3),
            100,
            &opts(dir.path()),
        )
        .unwrap();

        assert_eq!(pages.total_rows, 3);
        assert!(pages.reconciles());
        assert_eq!(pages.pages.len(), 1);
        // Both passes agreed, so the hashes are equal and the page shipped.
        assert_eq!(pages.pages[0].pass1_sha256, pages.pages[0].pass2_sha256);

        // Promotion happened: the batch directory is visible and carries its sentinel.
        let dest = dir.path().join("b1");
        assert!(dest.join("PAGES.json").exists());
        assert!(dest.join("page-0000.tar.gz").exists());
        // And nothing is left staged.
        assert!(!dir.path().join(".b1.staging").exists());
    }

    #[test]
    fn a_second_pass_that_differs_kills_the_batch_and_leaves_nothing() {
        // Addition A2's whole point, and the reason `HostileRunner` exists.
        let dir = tempfile::tempdir().unwrap();
        let runner =
            HostileRunner::new(Hostility::DifferentOnSecondCall).with_header("ts\tid\tbody");
        let err = run_export(
            &ddl(),
            &overrides(),
            &runner,
            &store(dir.path()),
            &facts(3),
            100,
            &opts(dir.path()),
        )
        .unwrap_err();

        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort);
        assert!(err.to_string().contains("passes disagree"), "{err}");
        // Section 8.0: no partial output. The staging directory took everything with it.
        assert!(!dir.path().join("b1").exists());
        assert!(!dir.path().join(".b1.staging").exists());
    }

    /// A page of `n` rows starting at `id = first`, all sharing one timestamp so the caller
    /// controls key-group shape by choosing ids.
    fn page_at(ts: u64, first: u64, n: u64) -> Vec<u8> {
        let mut out = String::from("ts\tid\tbody\n");
        for i in 0..n {
            out.push_str(&format!("{ts}\t{}\trow\n", first + i));
        }
        out.into_bytes()
    }

    #[test]
    fn the_cursor_advances_across_pages_and_every_row_is_exported_once() {
        // Multi-page pagination had no test anywhere: every fixture returned one short page and
        // `a7d` asserted `pages.len() == 1`. Cursor advance, the seek predicate and the key-group
        // extension were all unexercised -- which is where four separate defects were living.
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new()
            // Registered most-specific first: the group-extension equality, then the seek, then
            // the opening page.
            .on("= (", page_at(1785000000, 2, 1))
            .on("> (", page_at(1785000001, 3, 1))
            .on("SELECT", page_at(1785000000, 1, 2));

        let pages = run_export(
            &ddl(),
            &overrides(),
            &runner,
            &store(dir.path()),
            &facts(3),
            2,
            &opts(dir.path()),
        )
        .unwrap_or_else(|e| panic!("a two-page export must succeed: {e}"));

        assert_eq!(pages.pages.len(), 2, "the run must not stop after page 0");
        assert_eq!(pages.total_rows, 3);
        assert!(pages.reconciles());

        // The second query must carry a seek built from the first page's last key, not an OFFSET.
        let sql: Vec<String> = runner.recorded().into_iter().map(|q| q.sql).collect();
        assert!(
            sql.iter().any(|q| q.contains("(`ts`, `id`) > (")),
            "no keyset seek was issued: {sql:?}"
        );
        assert!(
            !sql.iter().any(|q| q.to_uppercase().contains("OFFSET")),
            "OFFSET must never appear: {sql:?}"
        );
    }

    #[test]
    fn every_pushed_object_carries_the_requested_unlocked_retention() {
        // Addition A5's retention code was correct, tested and unreachable: every production call
        // site passed `retain_until: None`, so a temporary hold released at teardown was the only
        // protection any object ever carried. `LocalStore` ignoring the field is why no test could
        // notice -- an oracle that drops a control cannot fail a caller that forgets it.
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        run_export(
            &ddl(),
            &overrides(),
            &one_page_cluster(2),
            &s,
            &facts(2),
            10,
            &opts(dir.path()),
        )
        .unwrap();

        for name in ["db.t/b1/page-0000.tar.gz", "db.t/b1/PAGES.json"] {
            let object = ObjectName::new(name).unwrap();
            assert!(
                s.retain_until(&object).unwrap().is_some(),
                "{name} was pushed without retention"
            );
        }

        // Zero days is a real choice and stays a choice: no retention requested, none recorded.
        let bare = tempfile::tempdir().unwrap();
        let s2 = store(bare.path());
        run_export(
            &ddl(),
            &overrides(),
            &one_page_cluster(2),
            &s2,
            &facts(2),
            10,
            &ExportOptions {
                retain_days: 0,
                ..opts(bare.path())
            },
        )
        .unwrap();
        assert!(
            s2.retain_until(&ObjectName::new("db.t/b1/page-0000.tar.gz").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn resume_is_refused_after_a_finding_and_allowed_after_an_infrastructure_error() {
        // `--resume` was a bool with one effect: softening a 412 into verify-and-skip. Nothing
        // read a prior outcome, so a run that aborted on a finding could be resumed -- and since
        // the source is live and the cutoff is a `WHERE` rather than a freeze, the offending row
        // might simply not come back, delivering the subset section 8.0 forbids.
        let dir = tempfile::tempdir().unwrap();
        let base = opts(dir.path());

        // A run that ends in a finding.
        let runner = FakeRunner::new().on("SELECT", page_at(1785000000, 1, 5));
        let err = run_export(
            &ddl(),
            &overrides(),
            &runner,
            &store(dir.path()),
            &facts(5),
            2,
            &base,
        )
        .err()
        .unwrap_or_else(|| panic!("expected a finding"));
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort, "{err}");

        // Resuming it is refused, and refused as a Usage error -- Infra is the resumable class and
        // this is precisely the case that must not be.
        let resumed = ExportOptions {
            resume: true,
            ..opts(dir.path())
        };
        let refused = run_export(
            &ddl(),
            &overrides(),
            &FakeRunner::new().on("SELECT", page_at(1785000000, 1, 1)),
            &store(dir.path()),
            &facts(1),
            2,
            &resumed,
        )
        .err()
        .unwrap_or_else(|| panic!("a resume past a finding must be refused"));
        assert_eq!(
            refused.exit_code(),
            crate::abort::ExitCode::Usage,
            "{refused}"
        );
        assert!(
            refused.to_string().contains("cannot be resumed"),
            "{refused}"
        );

        // An infrastructure outcome stays resumable: that is the whole point of the 1-vs-3 split.
        std::fs::write(dir.path().join("b1.outcome"), "infra").unwrap();
        run_export(
            &ddl(),
            &overrides(),
            &FakeRunner::new().on("SELECT", page_at(1785000000, 1, 1)),
            &store(dir.path()),
            &facts(1),
            2,
            &ExportOptions {
                resume: true,
                batch: "b1".to_owned(),
                ..opts(dir.path())
            },
        )
        .unwrap_or_else(|e| panic!("an infra outcome must stay resumable: {e}"));
    }

    #[test]
    fn a_run_that_panics_leaves_an_unresumable_batch() {
        // `record_outcome` runs only on a normal return, so a panic in `run_export_inner` -- which
        // `main` maps to exit 1, a finding -- would unwind past it and leave no "abort" recorded,
        // silently permitting a resume that skips the input that panicked. `record_pending` stamps
        // the batch unresumable before the work starts; this reproduces that state directly, since
        // an in-process panic would poison the test harness.
        let dir = tempfile::tempdir().unwrap();
        let base = opts(dir.path());

        // What run_export writes before it calls the inner pipeline. If the inner had panicked,
        // this is the state left behind: no clean return ever overwrote it.
        record_pending(&base);
        assert_eq!(
            std::fs::read_to_string(outcome_path(&base)).unwrap().trim(),
            "abort"
        );

        let resumed = ExportOptions {
            resume: true,
            ..opts(dir.path())
        };
        let refused = check_resumable(&resumed)
            .err()
            .unwrap_or_else(|| panic!("a resume after a panic must be refused"));
        assert_eq!(
            refused.exit_code(),
            crate::abort::ExitCode::Usage,
            "{refused}"
        );
        assert!(
            refused.to_string().contains("cannot be resumed"),
            "{refused}"
        );
    }

    #[test]
    fn a_page_longer_than_its_own_limit_is_a_finding() {
        // The extension gate tested `rows == rows_per_page`, so a page returning *more* than its
        // LIMIT skipped extension entirely and the cursor then advanced past a partly-consumed key
        // group. Nothing anywhere asserted the "every page is exactly rows_per_page except the
        // last" invariant the design states.
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new().on("SELECT", page_at(1785000000, 1, 5));
        let err = run_export(
            &ddl(),
            &overrides(),
            &runner,
            &store(dir.path()),
            &facts(5),
            2,
            &opts(dir.path()),
        )
        .err()
        .unwrap_or_else(|| panic!("a page over its LIMIT must abort"));
        assert!(
            err.to_string().contains("more rows than its LIMIT"),
            "{err}"
        );
        assert!(!dir.path().join("b1").exists(), "nothing may be promoted");
    }

    #[test]
    fn a_group_extension_that_disagrees_with_itself_aborts() {
        // The extension read once and appended, so the tail of an extended page shipped with no
        // completeness signal while the recorded pass hashes described only the diffed prefix.
        let dir = tempfile::tempdir().unwrap();
        let runner = HostileRunner::new(Hostility::DifferentOnSecondCall);
        let err = run_export(
            &ddl(),
            &overrides(),
            &runner,
            &store(dir.path()),
            &facts(2),
            2,
            &opts(dir.path()),
        )
        .err()
        .unwrap_or_else(|| panic!("a non-deterministic source must abort"));
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort, "{err}");
    }

    #[test]
    fn a_row_count_the_server_contradicts_aborts_before_promotion() {
        // The three-number agreement. Here the server claims ten rows and streams three.
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new().on("SELECT", page(1, 3));
        let err = run_export(
            &ddl(),
            &overrides(),
            &runner,
            &store(dir.path()),
            &facts(10),
            100,
            &opts(dir.path()),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the server's count()"),
            "{err}"
        );
        assert!(!dir.path().join("b1").exists(), "nothing may be promoted");
    }

    #[test]
    fn a_header_that_does_not_match_the_projection_aborts() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new()
            // Columns reordered: `input_format_with_names_use_header` would catch this on import,
            // but the export projection is built from the pinned order and is already wrong.
            .on("SELECT", b"id\tts\tbody\n1\t1785000000\trow\n".to_vec());

        let err = run_export(
            &ddl(),
            &overrides(),
            &runner,
            &store(dir.path()),
            &facts(1),
            100,
            &opts(dir.path()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("header"), "{err}");
    }

    #[test]
    fn the_pushed_object_is_create_only_and_the_ledger_records_its_generation() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let pages = run_export(
            &ddl(),
            &overrides(),
            &one_page_cluster(2),
            &s,
            &facts(2),
            100,
            &opts(dir.path()),
        )
        .unwrap();

        let entry = &pages.pages[0];
        assert!(
            entry.generation > 0,
            "the ledger must pin a real generation"
        );
        assert_eq!(entry.object, "db.t/b1/page-0000.tar.gz");

        // A second run of the same batch id hits the create-only precondition. Without --resume
        // that is a finding: something else wrote to our prefix, or a previous run half-completed.
        let dir2 = tempfile::tempdir().unwrap();
        let err = run_export(
            &ddl(),
            &overrides(),
            &one_page_cluster(2),
            &s,
            &facts(2),
            100,
            &opts(dir2.path()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn the_archive_holds_exactly_the_page_and_its_metadata() {
        let dir = tempfile::tempdir().unwrap();
        run_export(
            &ddl(),
            &overrides(),
            &one_page_cluster(2),
            &store(dir.path()),
            &facts(2),
            100,
            &opts(dir.path()),
        )
        .unwrap();

        let bytes = std::fs::read(dir.path().join("b1").join("page-0000.tar.gz")).unwrap();
        let members = crate::archive::read_targz(&bytes, &overrides().limits).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name, "page-0000.json");
        assert_eq!(members[1].name, "page-0000.tsv");
        assert!(members[1].bytes.starts_with(b"ts\tid\tbody\n"));
    }

    #[test]
    fn freezing_the_source_is_deliberately_not_this_tool_s_job() {
        // Stopping legitimate writers happens out of band at the network and IAM layer, never by
        // logging in to the compromised host. What makes the page boundary stable across the two
        // passes is the pinned cutoff predicate -- a WHERE clause that needs no cooperation from
        // the server at all.
        let (_, over) = (ddl(), overrides());
        let predicate = crate::pages::cutoff_predicate(&ddl(), &over).unwrap();
        assert!(predicate.contains("`ts` <"), "{predicate}");
        assert!(
            !predicate.contains("SYSTEM"),
            "no server-side freeze is issued: {predicate}"
        );
    }
}

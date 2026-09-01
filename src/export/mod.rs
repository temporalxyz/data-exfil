//! Q1 phases, invoked in order by `salvage export`.
//!
//! `quiesce` -> `plan` -> per page (`run` twice -> `diff` -> pack -> push) -> `PAGES.json`.
//!
//! The phases are functions called in sequence in one process against one work dir. There are no
//! inter-step state files and no dispatcher indirection: every cross-phase value is an in-memory
//! typed struct passed as an argument.
//!
//! The submodules named in the plan (`quiesce`, `plan`, `run`, `diff`) are split out as their
//! build step lands; see the plan's step 9.

use crate::abort::{Result, infra};
use crate::cli::ExportArgs;
use crate::clickhouse::QueryRunner;
use crate::gcs::ObjectStore;

/// Run the export pipeline for one table.
///
/// Aborting here kills the whole table's batch. Nothing is promoted, every page is discarded, and
/// the fix is never to lower the bar -- it is to drop the column, reclassify it, or remove the
/// table, and then re-run from the start.
pub fn run(_args: &ExportArgs, _runner: &dyn QueryRunner, _store: &dyn ObjectStore) -> Result<()> {
    infra("export: not implemented")
}

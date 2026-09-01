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

use crate::abort::{Result, infra};
use crate::cli::AuditArgs;
use crate::gcs::ObjectStore;

/// Run the audit pipeline for one table.
///
/// Survey mode enumerates every finding and writes nothing forward, which is how scope gets fixed
/// between runs -- halting on the first finding means discovering problems one at a time across
/// many re-runs. It still fails if it found anything.
///
/// Enforce mode is the production run and is expected to find nothing. If it aborts, the survey
/// was incomplete or the scope decision was wrong; both are worth knowing.
pub fn run(_args: &AuditArgs, _store: &dyn ObjectStore) -> Result<()> {
    infra("audit: not implemented")
}

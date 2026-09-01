//! Google Cloud Storage: create-only push, generation-pinned pull, retention and holds.
//!
//! Hand-written over `reqwest` on purpose, and this stays hand-written even though the ClickHouse
//! side now uses a client crate. Every GCS feature relied on here is a security control --
//! `ifGenerationMatch=0`, generation-pinned reads, SHA-256 in custom metadata, Unlocked object
//! retention, temporary holds -- and object retention in particular is new enough that crate
//! coverage is patchy. A dependency that might not expose a control is worse than a reviewed
//! implementation that does.
//!
//! Two traps, recorded here because both read as pedantic and are not:
//!
//! - A client-side existence check is **not** `ifGenerationMatch=0`. Checking first needs read or
//!   list, which `roles/storage.objectCreator` deliberately lacks, and races anyway. Only the
//!   precondition is a real server-side create-only write.
//! - `ifGenerationMatch=0` means "no *live* object". With versioning on it still succeeds when only
//!   noncurrent generations exist, so reconcile against the ledger, never against the precondition
//!   alone.
//!
//! Not yet implemented; see the plan's step 7.

use std::path::Path;

use crate::abort::{Result, infra};

/// A GCS object generation. Named `Generation`, never `gen` -- `gen` is a reserved keyword in
/// edition 2024.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generation(pub u64);

/// A validated object name: no `..`, no leading `/`, no control bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectName(String);

impl ObjectName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The seam every caller uses, so push and pull can be tested against a local oracle with no GCP.
pub trait ObjectStore {
    /// Create-only write. Fails if a live object already exists at this name.
    fn create(&self, name: &ObjectName, body: &Path) -> Result<Generation>;

    /// Read one exact generation. Never "latest under prefix".
    fn get_pinned(&self, name: &ObjectName, generation: Generation, dest: &Path) -> Result<()>;

    /// Set or release a temporary hold.
    fn set_hold(&self, name: &ObjectName, generation: Generation, hold: bool) -> Result<()>;
}

/// The real client. Constructed exactly once in `main` -- `reqwest::blocking` spins its own
/// runtime thread, and constructing one inside a `Drop` would deadlock, which is a live risk given
/// how much of this design lives in destructors.
#[derive(Debug)]
pub struct HttpStore;

impl ObjectStore for HttpStore {
    fn create(&self, _name: &ObjectName, _body: &Path) -> Result<Generation> {
        infra("gcs::HttpStore::create: not implemented")
    }

    fn get_pinned(&self, _name: &ObjectName, _generation: Generation, _dest: &Path) -> Result<()> {
        infra("gcs::HttpStore::get_pinned: not implemented")
    }

    fn set_hold(&self, _name: &ObjectName, _generation: Generation, _hold: bool) -> Result<()> {
        infra("gcs::HttpStore::set_hold: not implemented")
    }
}

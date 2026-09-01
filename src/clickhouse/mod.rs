//! Everything that talks to, or reasons about, ClickHouse.
//!
//! The submodules named in the plan (`types`, `ddl`, `tsv`, `settings`, `quarantine`, `client`)
//! are split out as their build steps land. What is here now is the seam itself, which must exist
//! first so that `pages`, `export` and `audit` can be written and tested against fakes before any
//! client exists.
//!
//! # Why the seam lives here and not in `client.rs`
//!
//! If [`QueryRunner`] were declared alongside the real client, every test double would have to
//! link against the client's dependencies. Declaring it here keeps the fakes free of them.
//!
//! # Why it is byte-oriented
//!
//! [`QueryRunner::stream`] hands back bytes, not parsed rows. The premise of the whole tool is
//! that the far side is hostile and nothing may parse its output before we have validated it --
//! so the seam must not pre-parse, and no dependency may deserialize on our behalf.

pub mod settings;
pub mod tsv;

use crate::abort::Result;
use crate::clickhouse::settings::Settings;

/// What a query is for. Recorded in the local query log so the log reads as a narrative rather
/// than as a pile of SQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKind {
    /// Cluster and settings cross-checks; reads no table data.
    Introspect,
    /// The quiesce fingerprint: counts and part rows, before and after.
    Fingerprint,
    /// A page of table data.
    Page,
}

/// A query, carrying its pinned settings.
///
/// `settings` is a field rather than something the caller splices into `sql`. That makes "no query
/// leaves without pinned SETTINGS" a property of the type instead of a review item.
#[derive(Debug, Clone)]
pub struct Query {
    pub sql: String,
    pub settings: &'static Settings,
    pub kind: QueryKind,
}

/// The seam. Two methods only.
///
/// Everything higher-level -- `describe`, `count`, `part_rows` -- is a free function over
/// `&dyn QueryRunner`, so the fakes never grow a method when a new query is added.
pub trait QueryRunner {
    /// Stream a result as raw bytes. The caller enforces its own deadline and byte cap: nothing in
    /// an HTTP stack provides a total budget, and a hostile server may slow-drip forever.
    fn stream(&self, query: &Query) -> Result<Box<dyn std::io::Read + Send>>;

    /// Fetch a single scalar as text.
    fn scalar(&self, query: &Query) -> Result<String>;
}

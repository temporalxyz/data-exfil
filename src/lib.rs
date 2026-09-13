//! Fail-closed ClickHouse data salvage from a compromised cluster.
//!
//! Implements the Selective ClickHouse Data Salvage Plan (v-final, 25 Aug 2026) for a two-host
//! topology: Q1 exports from the compromised cluster, Q2 audits and insert-tests, and the clean
//! bucket is the end of the pipeline. Section references in the docs point at that document.
//!
//! # Reading order
//!
//! [`abort`] first -- every other module inherits its fail-closed semantics. A phase that is not
//! yet implemented returns [`abort::SalvageError::Infra`], never `Ok`. There is no code path in
//! this crate that reports success for work it did not do.

pub mod abort;
pub mod archive;
pub mod audit;
pub mod cli;
pub mod clickhouse;
pub mod export;
pub mod gcs;
pub mod limits;
pub mod models;
pub mod pages;
pub mod parquet_audit;
pub mod teardown;

/// Test doubles: fake and hostile query sources, a local object store, and a byte-level tar
/// builder for archives that cannot be committed as fixtures (`.gitignore` excludes `*.tar`).
///
/// Deliberately not feature-gated. Integration tests under `tests/` are separate crates and cannot
/// see `#[cfg(test)]` items; a `testkit` feature would create a self-dev-dependency and a build
/// matrix in which the fakes rot outside the default build. On a one-shot forensics tool, a test
/// path that the default build does not compile is a liability.
#[doc(hidden)]
pub mod testkit;

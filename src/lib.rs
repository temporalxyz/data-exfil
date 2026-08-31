//! Fail-closed ClickHouse data salvage from a compromised cluster.
//!
//! Implements the Selective ClickHouse Data Salvage Plan (v-final, 25 Aug 2026) for a two-host
//! topology: Q1 exports from the compromised cluster, Q2 audits and insert-tests, and the clean
//! bucket is the end of the pipeline. Section references in the docs point at that document.

pub mod abort;

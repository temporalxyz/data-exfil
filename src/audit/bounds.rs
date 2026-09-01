//! Section 8.3 bounds and section 8.5 freedom classes, applied per value.
//!
//! > Decode before validating. Any column without a written contract is out of scope -- generic
//! > JSON conversion is not a fallback.
//!
//! Decoding happened in [`crate::audit::frame`]; this applies the bound. The rules come from
//! `types.rs` verbatim, so the form the export emitted and the form this accepts cannot drift --
//! they are produced by the same `match`.
//!
//! # Why the class decides how the batch dies
//!
//! Section 8.5: injection is a property of the sink, not the value. `'; DROP TABLE users;--` is
//! inert in a ClickHouse `String`. So a payload match is a **flag** in an Open column and a
//! **gate** in a Closed or Constrained one -- and in the latter it escalates as well, because the
//! value already failed its allowlist, which means either the schema is wrong or something put a
//! payload where one cannot legitimately be.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use regex::bytes::Regex;

use crate::abort::{Result, SalvageError, abort};
use crate::audit::payloads;
use crate::clickhouse::ddl::PinnedDdl;
use crate::clickhouse::tsv::Field;
use crate::clickhouse::types::{Validator, rules_for};
use crate::limits::Limits;
use crate::models::{ColumnOverride, Finding, FreedomClass, Overrides};

/// Everything needed to judge one output column's values.
#[derive(Debug, Clone)]
pub struct ColumnContract {
    pub name: String,
    /// The source column this projection came from. Several outputs share one source.
    pub source: String,
    pub class: FreedomClass,
    pub validator: Validator,
    pub nullable: bool,
    pub max_len: Option<u32>,
    /// The per-column exact pattern for a Closed or Constrained column.
    pub pattern: Option<String>,
}

/// Build one contract per exported column, in the order the header declares them.
pub fn contracts(ddl: &PinnedDdl, overrides: &Overrides) -> Result<Vec<ColumnContract>> {
    let mut out = Vec::new();
    for column in &ddl.columns {
        let over: Option<&ColumnOverride> = overrides.columns.get(column.name.as_str());
        if over.is_some_and(|o| o.drop) {
            continue;
        }
        let rules = rules_for(&column.ty, overrides.limits.max_array_elements)
            .map_err(|e| e.with("column", column.name.as_str()))?;
        for projected in &rules.columns {
            out.push(ColumnContract {
                name: format!("{}{}", column.name.as_str(), projected.suffix),
                source: column.name.as_str().to_owned(),
                // A column nobody classified inherits Closed: fail-closed, so an unclassified
                // column is never silently treated as free text.
                class: over.map_or(FreedomClass::Closed, |o| o.class),
                validator: projected.validator.clone(),
                nullable: rules.nullable,
                max_len: over.and_then(|o| o.max_len),
                pattern: over.and_then(|o| o.pattern.clone()),
            });
        }
    }
    Ok(out)
}

/// Compile a per-column pattern once and keep it.
///
/// Row-time `Regex::new` would be unaffordable, and the leak is bounded by the number of distinct
/// pinned patterns -- a property of source control, not of the data.
fn column_pattern(pattern: &str) -> Result<&'static Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, &'static Regex>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache
        .lock()
        .map_err(|_| abort::<()>("pattern cache poisoned").unwrap_err())?;
    if let Some(found) = guard.get(pattern) {
        return Ok(found);
    }
    let compiled = Regex::new(pattern).map_err(|e| {
        abort::<()>("a pinned column pattern does not compile")
            .unwrap_err()
            .with("pattern", pattern.escape_debug())
            .with("detail", e.to_string())
    })?;
    let leaked: &'static Regex = Box::leak(Box::new(compiled));
    guard.insert(pattern.to_owned(), leaked);
    Ok(leaked)
}

/// Judge one value. Returns a finding, or `None` if it is clean.
///
/// A finding is returned rather than raised so survey mode can accumulate. Enforce mode turns the
/// first one into an abort -- the rejection threshold is zero in both, and survey means "collect
/// them all", not "tolerate them".
pub fn check_value(
    contract: &ColumnContract,
    field: &Field,
    limits: &Limits,
    page: u32,
    row: u64,
) -> Result<Option<Finding>> {
    let finding = |reason: &str, escalate: bool, sample: &[u8]| Finding {
        phase: "bounds".to_owned(),
        column: Some(contract.name.clone()),
        page: Some(page),
        row: Some(row),
        reason: reason.to_owned(),
        escalate,
        // Hex only. Section 8.0 forbids re-emitting a rejected value forward, and typing the
        // sample as a hex string means there is no variant that could carry the original bytes.
        sample_hex: hex_sample(sample),
    };

    let bytes = match field {
        Field::Null => {
            if contract.nullable {
                return Ok(None);
            }
            // Section 8.2: null is not empty. A NULL in a NOT NULL column is a contract violation,
            // not a value to coerce.
            return Ok(Some(finding("NULL in a non-nullable column", true, b"")));
        }
        Field::Value(bytes) => bytes.as_slice(),
    };

    // The section 8.3 bound, produced by the same match that produced the export form.
    if let Err(e) = contract.validator.check(bytes) {
        return Ok(Some(finding(&e.to_string(), true, bytes)));
    }

    if let Some(cap) = contract.max_len {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if len > u64::from(cap) {
            return Ok(Some(finding(
                "value exceeds its pinned length cap",
                false,
                bytes,
            )));
        }
    }

    if let Some(pattern) = &contract.pattern
        && !column_pattern(pattern)?.is_match(bytes)
    {
        return Ok(Some(finding(
            "value does not match its per-column pattern",
            true,
            bytes,
        )));
    }

    // Section 8.6, after decoding and after normalisation, on both forms.
    let scan = payloads::scan(bytes, limits)?;
    if !scan.is_clean() {
        let escalate = contract.class.escalates_on_match();
        let reason = if scan.classes.is_empty() {
            "value's normalised form differs from its raw form".to_owned()
        } else {
            format!(
                "payload catalogue match: {} (via {})",
                scan.classes.join(", "),
                scan.via.join(", ")
            )
        };
        return Ok(Some(finding(&reason, escalate, bytes)));
    }

    Ok(None)
}

/// Judge one row against the contracts, in order.
pub fn check_row(
    contracts: &[ColumnContract],
    fields: &[Field],
    limits: &Limits,
    page: u32,
    row: u64,
) -> Result<Vec<Finding>> {
    if contracts.len() != fields.len() {
        return abort("row width does not match the contract").map_err(|e: SalvageError| {
            e.with("contracts", contracts.len())
                .with("fields", fields.len())
        });
    }
    let mut out = Vec::new();
    for (contract, field) in contracts.iter().zip(fields) {
        if let Some(f) = check_value(contract, field, limits, page, row)? {
            out.push(f);
        }
    }
    Ok(out)
}

/// A bounded hex sample of a rejected value.
///
/// Bounded because a finding goes into a report a human reads, and the whole value could be a
/// megabyte. Hex because the alternative is re-emitting attacker bytes into an artifact that gets
/// opened in an editor.
fn hex_sample(bytes: &[u8]) -> String {
    const MAX: usize = 64;
    let head = bytes.get(..MAX.min(bytes.len())).unwrap_or(&[]);
    let mut out = String::with_capacity(head.len().saturating_mul(2));
    for b in head {
        out.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > MAX {
        out.push_str("...");
    }
    out
}

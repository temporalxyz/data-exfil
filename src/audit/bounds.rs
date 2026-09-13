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

use crate::abort::{Result, SalvageError, abort, usage};
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
    /// Whether this projection belongs to a group whose arrays must all be the same length in
    /// every row -- `Map` (keys and values) and `Nested` (one array per field).
    ///
    /// Section 8.3 states the rule for both, and section 12 item 1 names "Nested with unequal
    /// array lengths" as a corpus case. `TypeRules::equal_length_group` was computed, serialized,
    /// golden-tested and read by nobody: the flag existed, its doc comment named this module as
    /// its enforcer, and this module had never mentioned it.
    pub equal_length_group: bool,
}

/// Build one contract per exported column, in the order the header declares them.
pub fn contracts(ddl: &PinnedDdl, overrides: &Overrides) -> Result<Vec<ColumnContract>> {
    let mut out = Vec::new();
    for column in &ddl.columns {
        let over: Option<&ColumnOverride> = overrides.columns.get(column.name.as_str());
        if over.is_some_and(|o| o.drop) {
            continue;
        }
        let mut rules = rules_for(&column.ty, overrides.limits.max_array_elements)
            .map_err(|e| e.with("column", column.name.as_str()))?;
        // Section 8.2's prefer-hex directive, per column. This is the only consumer of
        // `ColumnOverride.hex`; before it existed the flag was pinned, documented and inert.
        if overrides
            .columns
            .get(column.name.as_str())
            .is_some_and(|o| o.hex)
        {
            crate::clickhouse::types::apply_hex_override(&column.ty, &mut rules)
                .map_err(|e| e.with("column", column.name.as_str()))?;
        }

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
                equal_length_group: rules.equal_length_group,
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
    // Section 8.5 defines Closed as "must match an **exact** pattern". `is_match` succeeds on any
    // substring, so an unanchored pinned pattern silently degraded a column's allowlist into a
    // substring search -- and nothing required the anchors. Requiring them here makes the pinned
    // file mean what section 8.5 says it means, and a missing anchor a loud error rather than a
    // reviewer's job to spot.
    if !pattern.starts_with('^') || !pattern.ends_with('$') {
        return usage("a pinned column pattern must be anchored at both ends").map_err(
            |e: SalvageError| {
                e.with("pattern", pattern.escape_debug()).with(
                    "reason",
                    "an unanchored pattern is a substring search; section 8.5 requires an exact \
                     match",
                )
            },
        );
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
    let pattern = contract
        .pattern
        .as_deref()
        .map(column_pattern)
        .transpose()?;
    check_value_precompiled(contract, field, limits, page, row, pattern)
}

/// Compile a pinned pattern before entering a parallel value loop.
pub fn prepare_pattern(contract: &ColumnContract) -> Result<Option<&'static Regex>> {
    contract.pattern.as_deref().map(column_pattern).transpose()
}

/// The same checks as `check_value`, with no pattern-cache lock in the value loop.
pub fn check_value_precompiled(
    contract: &ColumnContract,
    field: &Field,
    limits: &Limits,
    page: u32,
    row: u64,
    pattern: Option<&Regex>,
) -> Result<Option<Finding>> {
    check_value_impl(contract, field, limits, page, row, pattern, true)
}

/// Validate a native scalar's generated representation without treating it as source text.
/// Callers must ensure the underlying value is not a string or binary field.
pub(crate) fn check_native_scalar_precompiled(
    contract: &ColumnContract,
    field: &Field,
    limits: &Limits,
    page: u32,
    row: u64,
    pattern: Option<&Regex>,
) -> Result<Option<Finding>> {
    check_value_impl(contract, field, limits, page, row, pattern, false)
}

fn check_value_impl(
    contract: &ColumnContract,
    field: &Field,
    limits: &Limits,
    page: u32,
    row: u64,
    pattern: Option<&Regex>,
    scan_payloads: bool,
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
            return Ok(Some(finding(
                "NULL in a non-nullable column",
                contract.class.escalates_on_match(),
                b"",
            )));
        }
        Field::Value(bytes) => bytes.as_slice(),
    };

    // The section 8.3 bound, produced by the same match that produced the export form.
    //
    // The finding carries the validator's *reason*, never its rendered `Display`. `SalvageError`
    // renders its context, and the type validators attach `.with("value", ...)` at twenty-odd
    // sites -- so `e.to_string()` put the rejected value verbatim into `Finding.reason`, which is
    // written to `report.json` and copied into `PAYLOAD-INVENTORY.json`. Section 8.0 forbids
    // re-emitting a rejected value forward, and `models.rs` claims the struct structurally cannot;
    // the careful `hex_sample()` beside it was being bypassed by the field next to it.
    if let Err(e) = contract.validator.check(bytes) {
        return Ok(Some(finding(
            e.reason(),
            contract.class.escalates_on_match(),
            bytes,
        )));
    }

    if let Some(cap) = contract.max_len {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if len > u64::from(cap) {
            // Section 8.5 decides this, not the branch. Hardcoding `false` here meant a
            // Constrained column busting its pinned length -- precisely the escalating case --
            // did not escalate, while an Open column with a stray control byte did.
            return Ok(Some(finding(
                "value exceeds its pinned length cap",
                contract.class.escalates_on_match(),
                bytes,
            )));
        }
    }

    if let Some(pattern) = pattern
        && !pattern.is_match(bytes)
    {
        return Ok(Some(finding(
            "value does not match its per-column pattern",
            contract.class.escalates_on_match(),
            bytes,
        )));
    }

    if !scan_payloads {
        return Ok(None);
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
/// How many elements a JSON-array projection holds, or `None` if it is not one.
///
/// Deliberately tolerant: the per-value validator has already judged the array's shape and its
/// elements, so anything unparseable here has been reported by a finding of its own and this
/// check simply declines to add a second, more confusing one.
fn array_len(field: &Field) -> Option<usize> {
    let bytes = field.bytes()?;
    let text = std::str::from_utf8(bytes).ok()?;
    match serde_json::from_str::<serde_json::Value>(text).ok()? {
        serde_json::Value::Array(items) => Some(items.len()),
        _ => None,
    }
}

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

    // Section 8.3's equal-length rule, for `Map` (keys against values) and `Nested` (every field's
    // array against its siblings). Each projection passed its own validator independently, so a
    // `Map` whose keys and values came back at different lengths -- or a `Nested` group whose
    // arrays disagree -- satisfied every per-column check and landed in quarantine silently
    // truncated. That is the same misalignment the Map export goes to real trouble to prevent by
    // sorting zipped pairs rather than keys alone; it was prevented on the way out and unchecked
    // on the way back in.
    let mut groups: Vec<(&str, usize, &str)> = Vec::new();
    for (contract, field) in contracts.iter().zip(fields) {
        if !contract.equal_length_group {
            continue;
        }
        let Some(len) = array_len(field) else {
            continue;
        };
        match groups.iter().find(|(src, _, _)| *src == contract.source) {
            Some((_, first_len, first_name)) if *first_len != len => {
                out.push(Finding {
                    phase: "bounds".to_owned(),
                    page: Some(page),
                    row: Some(row),
                    column: Some(contract.source.clone()),
                    reason: format!(
                        "parallel arrays in one group have different lengths: `{first_name}` has \
                         {first_len}, `{}` has {len}",
                        contract.name
                    ),
                    // A group that does not line up is a structural contract violation, not a
                    // value judgement, so it escalates regardless of the column's freedom class.
                    escalate: true,
                    sample_hex: String::new(),
                });
            }
            Some(_) => {}
            None => groups.push((&contract.source, len, &contract.name)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clickhouse::ddl::parse_create_table;
    use crate::models::{ColumnOverride, FreedomClass};

    fn ddl() -> crate::clickhouse::ddl::PinnedDdl {
        parse_create_table(
            "CREATE TABLE db.t (`id` UInt64, `body` String) ENGINE = MergeTree ORDER BY (`id`)",
        )
        .unwrap()
    }

    fn overrides_with(
        class: FreedomClass,
        pattern: Option<&str>,
        max_len: Option<u32>,
    ) -> Overrides {
        let toml = std::fs::read_to_string("overrides/typematrix.typematrix.toml").unwrap();
        let mut o: Overrides = toml::from_str(&toml).unwrap();
        o.columns.clear();
        o.columns.insert(
            "body".to_owned(),
            ColumnOverride {
                class,
                pattern: pattern.map(str::to_owned),
                max_len,
                enum_ids: None,
                drop: false,
                hex: false,
                rotation_owner: None,
            },
        );
        o
    }

    fn body_contract(o: &Overrides) -> ColumnContract {
        contracts(&ddl(), o)
            .unwrap()
            .into_iter()
            .find(|c| c.name == "body")
            .unwrap()
    }

    fn limits(o: &Overrides) -> Limits {
        o.limits.clone()
    }

    #[test]
    fn an_unclassified_column_inherits_the_most_restrictive_class() {
        // The fail-closed default. Nothing asserted it, so flipping it to `Open` would have made
        // every unclassified column free text with no test failing.
        let toml = std::fs::read_to_string("overrides/typematrix.typematrix.toml").unwrap();
        let mut o: Overrides = toml::from_str(&toml).unwrap();
        o.columns.clear();
        assert_eq!(body_contract(&o).class, FreedomClass::Closed);
    }

    #[test]
    fn escalation_follows_the_freedom_class_on_every_branch() {
        // Section 8.5 decides escalation, not the branch that produced the finding. Three branches
        // hardcoded `true` and one hardcoded `false`, so the polarity was inverted in both
        // directions: an Open column with a stray control byte escalated, while a Constrained
        // column busting its pinned length -- the escalating case -- did not.
        let open = overrides_with(FreedomClass::Open, None, Some(4));
        let c = body_contract(&open);
        let l = limits(&open);

        let over_cap = check_value(&c, &Field::Value(b"abcdefghij".to_vec()), &l, 0, 1)
            .unwrap()
            .expect("a value over its cap is a finding");
        assert!(!over_cap.escalate, "Open must not escalate");

        let closed = overrides_with(FreedomClass::Constrained, None, Some(4));
        let c2 = body_contract(&closed);
        let over_cap2 = check_value(
            &c2,
            &Field::Value(b"abcdefghij".to_vec()),
            &limits(&closed),
            0,
            1,
        )
        .unwrap()
        .expect("a value over its cap is a finding");
        assert!(
            over_cap2.escalate,
            "Constrained failing its own bound is exactly the escalating case"
        );
    }

    #[test]
    fn a_rejected_value_is_never_re_emitted_into_the_finding_reason() {
        // `Finding.reason` was built from `SalvageError`'s `Display`, which renders its context --
        // and the section 8.3 validators attach the offending value as context. So the value the
        // run rejected was written verbatim into `report.json`, right beside the carefully
        // hex-encoded sample, in a struct documented as structurally unable to carry it.
        let o = overrides_with(FreedomClass::Closed, None, None);
        let ddl = parse_create_table(
            "CREATE TABLE db.t (`id` UInt64, `body` String) ENGINE = MergeTree ORDER BY (`id`)",
        )
        .unwrap();
        let c = contracts(&ddl, &o)
            .unwrap()
            .into_iter()
            .find(|c| c.name == "id")
            .unwrap();

        let payload = "<script>alert(1)</script>";
        let f = check_value(
            &c,
            &Field::Value(payload.as_bytes().to_vec()),
            &limits(&o),
            0,
            1,
        )
        .unwrap()
        .expect("a non-numeric UInt64 is a finding");
        assert!(
            !f.reason.contains("script"),
            "the rejected value leaked into the reason: {}",
            f.reason
        );
        // The hex sample is the only place it may appear, and it does.
        assert!(!f.sample_hex.is_empty());
        assert!(f.sample_hex.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn a_null_in_a_non_nullable_column_is_a_finding_and_a_nullable_one_is_not() {
        let o = overrides_with(FreedomClass::Closed, None, None);
        let c = body_contract(&o);
        assert!(
            check_value(&c, &Field::Null, &limits(&o), 0, 1)
                .unwrap()
                .is_some(),
            "section 8.2: null is not empty and not a value to coerce"
        );
        let nullable = ColumnContract {
            nullable: true,
            ..c
        };
        assert!(
            check_value(&nullable, &Field::Null, &limits(&o), 0, 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_per_column_pattern_gates_the_value() {
        let o = overrides_with(FreedomClass::Closed, Some("^[a-z]{1,8}$"), None);
        let c = body_contract(&o);
        assert!(
            check_value(&c, &Field::Value(b"ok".to_vec()), &limits(&o), 0, 1)
                .unwrap()
                .is_none()
        );
        let bad = check_value(&c, &Field::Value(b"NOPE!".to_vec()), &limits(&o), 0, 1)
            .unwrap()
            .expect("a value outside its allowlist is a finding");
        assert!(bad.escalate, "a Closed column escalates on a match");
    }

    #[test]
    fn parallel_arrays_that_disagree_in_length_are_a_finding() {
        // Section 8.3 requires a `Map`'s keys and values -- and every array in a `Nested` group --
        // to be the same length in every row. `TypeRules::equal_length_group` computed exactly
        // that, its doc comment named this module as its enforcer, and this module had never
        // mentioned it: each projection passed its own validator independently, so a silently
        // truncated map landed in quarantine with nothing firing.
        let ddl = parse_create_table(
            "CREATE TABLE db.t (`id` UInt64, `labels` Map(UInt32, UInt32)) \
             ENGINE = MergeTree ORDER BY (`id`)",
        )
        .unwrap();
        let toml = std::fs::read_to_string("overrides/typematrix.typematrix.toml").unwrap();
        let mut o: Overrides = toml::from_str(&toml).unwrap();
        o.columns.clear();
        let cs = contracts(&ddl, &o).unwrap();
        assert_eq!(cs.len(), 3, "id plus labels.keys and labels.values");
        assert!(
            cs.iter().filter(|c| c.equal_length_group).count() == 2,
            "both map projections belong to the group"
        );

        let row = |keys: &str, values: &str| {
            vec![
                Field::Value(b"1".to_vec()),
                Field::Value(keys.as_bytes().to_vec()),
                Field::Value(values.as_bytes().to_vec()),
            ]
        };

        // Equal lengths: clean.
        let clean = check_row(&cs, &row("[10,20]", "[1,2]"), &o.limits, 0, 1).unwrap();
        assert!(clean.is_empty(), "expected clean, got {clean:?}");

        // Unequal: a finding, escalating, naming the source column.
        let findings = check_row(&cs, &row("[10,20]", "[1]"), &o.limits, 0, 1).unwrap();
        let f = findings
            .iter()
            .find(|f| f.reason.contains("different lengths"))
            .unwrap_or_else(|| panic!("expected an equal-length finding, got {findings:?}"));
        assert!(f.escalate);
        assert_eq!(f.column.as_deref(), Some("labels"));
    }

    #[test]
    fn an_unanchored_pinned_pattern_is_refused_rather_than_silently_weakened() {
        // Section 8.5 defines Closed as an *exact* match, and `is_match` succeeds on any
        // substring -- so `[A-Za-z0-9_]{1,64}` as a pinned pattern turned the allowlist into a
        // substring search, and a value like `'; DROP TABLE users;--x` passed on the strength of
        // its trailing `x`. Nothing required the anchors.
        let o = overrides_with(FreedomClass::Closed, Some("[a-z]{1,8}"), None);
        let c = body_contract(&o);
        let err = check_value(&c, &Field::Value(b"'; DROP--x".to_vec()), &limits(&o), 0, 1)
            .err()
            .unwrap_or_else(|| panic!("an unanchored pattern must be refused"));
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Usage, "{err}");
        assert!(err.to_string().contains("anchored"), "{err}");

        // Anchored patterns keep working, and still reject.
        let ok = overrides_with(FreedomClass::Closed, Some("^[a-z]{1,8}$"), None);
        let c2 = body_contract(&ok);
        assert!(
            check_value(
                &c2,
                &Field::Value(b"'; DROP--x".to_vec()),
                &limits(&ok),
                0,
                1
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn a_row_of_the_wrong_width_is_a_finding() {
        let o = overrides_with(FreedomClass::Closed, None, None);
        let cs = contracts(&ddl(), &o).unwrap();
        let err = check_row(&cs, &[Field::Value(b"1".to_vec())], &limits(&o), 0, 1)
            .err()
            .unwrap_or_else(|| panic!("a short row must be refused"));
        assert!(err.to_string().contains("field"), "{err}");
    }
}

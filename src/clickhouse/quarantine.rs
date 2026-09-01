//! Quarantine DDL: a pure function of the pinned DDL and the pinned overrides.
//!
//! Section 10 is unambiguous about the shape and the reason:
//!
//! > Tables created from pinned source control, never dirty-cluster DDL -- which can carry
//! > poisoned default expressions, silently filtering row policies, constraints, projections and
//! > TTLs. […] Columns are `String` / `Nullable(String)`. Values are already contract-validated,
//! > and holding them as text makes type coercion structurally impossible at the import boundary.
//! > This is what delivers "zero defaulted rows" -- a `Date` column accepts `2300-01-01` and
//! > silently clamps it, a `String` column cannot coerce anything.
//!
//! So everything is text, the engine sorts on nothing, and the generated statement contains no
//! defaults, materialized expressions, TTLs, projections, codecs or comments. Those are absences
//! rather than features, which makes them easy to reintroduce by accident and worth a test that
//! asserts the rendered text contains none of them.
//!
//! # Provenance
//!
//! Three columns are appended that the source table does not have. Section 9: *"insert into
//! consolidated quarantine -- adding fixed batch and file provenance values supplied by Q3,
//! **literals, never values derived from the data**."* Section 10: *"Provenance columns (source
//! file, batch, timestamp) carry into production and are kept, so anything found later can be
//! identified and removed without redoing the salvage."*
//!
//! That last clause is why they are load-bearing rather than bookkeeping: they are the mechanism
//! by which a batch discovered to be bad **six months later** can be retracted from production
//! without re-running a salvage whose source has since been wiped.
//!
//! # Column naming
//!
//! Output names match the export projection exactly, `.` and all -- `labels.keys`, `pair.1`,
//! `events.kind`. They are deliberately *not* rewritten to `_`, because section 9 imports with
//! `input_format_with_names_use_header=1`, which validates the file's header against the target's
//! column names. A rename here would turn that control into a mismatch we would then be tempted to
//! disable.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]

use std::fmt::Write as _;

use crate::abort::{Result, SalvageError, abort, usage};
use crate::clickhouse::ddl::PinnedDdl;
use crate::clickhouse::types::{QuarantineType, rules_for};
use crate::models::Overrides;

/// The provenance columns, with the reason each is kept.
///
/// Underscore-prefixed so a collision with a real column is detectable, and [`quarantine_ddl`]
/// refuses rather than shadowing: a source column called `_batch` would otherwise be silently
/// overwritten by our literal, and the row would claim a provenance it does not have.
pub const PROVENANCE_COLUMNS: &[(&str, &str)] = &[
    (
        "_source_object",
        "the generated object name this row came from; never a value derived from the data",
    ),
    (
        "_batch",
        "the batch id, so a bad batch can be retracted from production without redoing the salvage",
    ),
    (
        "_imported_at",
        "our clock at import, not the server's and not a column",
    ),
];

/// One column of the quarantine table, in export order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputColumn {
    /// The projected name, matching the TSV header exactly.
    pub name: String,
    /// The pinned DDL column this came from. Several outputs share one source when the type
    /// flattens.
    pub source: String,
    pub quarantine: QuarantineType,
}

impl OutputColumn {
    /// Backtick-quoted for SQL. Safe without escaping because [`validate_output_name`] already
    /// excluded every character that would need it.
    #[must_use]
    pub fn quoted(&self) -> String {
        format!("`{}`", self.name)
    }
}

/// Output names may carry `.` because flattening produces `events.kind`; nothing else is allowed.
///
/// 128 rather than 64 because a `Nested` field's name is the source column plus the field name
/// plus a separator, and two 64-char identifiers are legal on their own.
fn validate_output_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
    if ok {
        return Ok(());
    }
    abort("projected column name is not in the permitted charset")
        .map_err(|e: SalvageError| e.with("name", name.escape_debug()))
}

/// The flattened output columns for a table: every non-dropped pinned column, expanded.
///
/// Section 8.7: *"The only permitted removal is by column, decided before the run."* A dropped
/// column disappears here and nowhere else -- not from the pinned DDL, which stays the authority
/// for what the table *is*, so the manifest can say what was excluded and why.
pub fn output_columns(ddl: &PinnedDdl, overrides: &Overrides) -> Result<Vec<OutputColumn>> {
    let mut out: Vec<OutputColumn> = Vec::new();

    for column in &ddl.columns {
        let over = overrides.columns.get(column.name.as_str());
        if over.is_some_and(|o| o.drop) {
            continue;
        }

        // Section 8.4's nesting cap, applied to the declared type. Bounding the type bounds every
        // value it can hold, so this is checked once here rather than per row.
        let depth = column.ty.depth();
        if depth > overrides.limits.max_nesting_depth {
            return Err(usage::<()>("column type nests deeper than the pinned cap")
                .unwrap_err()
                .with("column", column.name.as_str())
                .with("depth", depth)
                .with("cap", overrides.limits.max_nesting_depth));
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
            let name = format!("{}{}", column.name.as_str(), projected.suffix);
            validate_output_name(&name)?;
            if out.iter().any(|c| c.name == name) {
                // Two source columns whose flattened names collide, e.g. `a` of type
                // `Tuple(UInt8)` and a literal column named `a.1`. The header check downstream
                // would see a duplicate and the mapping would be ambiguous.
                return Err(usage::<()>("two columns project to the same output name")
                    .unwrap_err()
                    .with("name", name.escape_debug()));
            }
            out.push(OutputColumn {
                name,
                source: column.name.as_str().to_owned(),
                quarantine: rules.quarantine,
            });
        }
    }

    if out.is_empty() {
        return Err(usage::<()>("every column is dropped; nothing would be exported").unwrap_err());
    }
    Ok(out)
}

/// Columns removed from scope by the overrides, for the manifest's record.
#[must_use]
pub fn dropped_columns(ddl: &PinnedDdl, overrides: &Overrides) -> Vec<String> {
    ddl.columns
        .iter()
        .filter(|c| {
            overrides
                .columns
                .get(c.name.as_str())
                .is_some_and(|o| o.drop)
        })
        .map(|c| c.name.as_str().to_owned())
        .collect()
}

/// `staging.<tbl>__<batch>__<seq>`, per section 9's "per-file staging, never a shared table".
///
/// One table per file is what makes the failure path simple: *"On any failure, drop the entire
/// per-file staging table and abort the batch. No shared partition is touched -- no partial state
/// to reason about, no retry landing on a half-load."*
pub fn staging_table_name(table: &str, batch: &str, seq: u32) -> Result<String> {
    let checked = |what: &'static str, v: &str, dashes_ok: bool| -> Result<()> {
        let ok = !v.is_empty()
            && v.len() <= 64
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || (dashes_ok && b == b'-'));
        if ok {
            return Ok(());
        }
        Err(
            usage::<()>("staging table component is not in the permitted charset")
                .unwrap_err()
                .with("component", what)
                .with("value", v.escape_debug()),
        )
    };
    checked("table", table, false)?;
    // `BatchId` already permits `-`, which is fine inside a backtick-quoted identifier.
    checked("batch", batch, true)?;
    Ok(format!("staging.`{table}__{batch}__{seq}`"))
}

/// Render the quarantine `CREATE TABLE`.
///
/// Pure: same pinned DDL and overrides in, same statement out, so the exact text is reviewable in
/// source control and diffable between runs.
pub fn quarantine_ddl(ddl: &PinnedDdl, overrides: &Overrides, staging: &str) -> Result<String> {
    let columns = output_columns(ddl, overrides)?;

    for (name, _) in PROVENANCE_COLUMNS {
        if columns.iter().any(|c| c.name == *name) {
            return Err(
                usage::<()>("a source column collides with a provenance column")
                    .unwrap_err()
                    .with("column", *name)
                    .with(
                        "reason",
                        "the provenance value is a literal we supply; shadowing it would let a row \
                     claim a provenance it does not have",
                    ),
            );
        }
    }

    let mut sql = format!("CREATE TABLE {staging}\n(\n");
    let width = columns
        .iter()
        .map(|c| c.quoted().len())
        .chain(
            PROVENANCE_COLUMNS
                .iter()
                .map(|(n, _)| n.len().saturating_add(2)),
        )
        .max()
        .unwrap_or(0);

    for column in &columns {
        let quoted = column.quoted();
        // Infallible for String; the result is discarded rather than unwrapped.
        let _ = writeln!(
            sql,
            "    {quoted:<width$}  {},",
            column.quarantine.sql(),
            width = width
        );
    }
    let _ = writeln!(
        sql,
        "\n    -- Provenance. Literals supplied by us, never values derived from the data\n\
         \x20   -- (section 9), and kept through promotion so a batch found bad later can be\n\
         \x20   -- retracted from production without redoing the salvage (section 10)."
    );
    for (i, (name, _)) in PROVENANCE_COLUMNS.iter().enumerate() {
        let quoted = format!("`{name}`");
        let comma = if i.saturating_add(1) == PROVENANCE_COLUMNS.len() {
            ""
        } else {
            ","
        };
        let _ = writeln!(sql, "    {quoted:<width$}  String{comma}", width = width);
    }

    // `ORDER BY tuple()` is section 9 verbatim. There is nothing to sort by and nothing that
    // wants an index: this table is inert, read once by reviewed conversion SQL, and dropped.
    sql.push_str(")\nENGINE = MergeTree\nORDER BY tuple()\n");
    Ok(sql)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clickhouse::ddl::parse_create_table;

    const MATRIX_DDL: &str = include_str!("../../ddl/typematrix.typematrix.sql");
    const MATRIX_OVERRIDES: &str = include_str!("../../overrides/typematrix.typematrix.toml");

    fn fixture() -> (PinnedDdl, Overrides) {
        (
            parse_create_table(MATRIX_DDL).unwrap(),
            toml::from_str::<Overrides>(MATRIX_OVERRIDES).unwrap(),
        )
    }

    #[test]
    fn every_quarantine_column_is_text() {
        let (ddl, over) = fixture();
        for c in output_columns(&ddl, &over).unwrap() {
            assert!(
                matches!(
                    c.quarantine,
                    QuarantineType::String | QuarantineType::NullableString
                ),
                "{} is not text",
                c.name
            );
        }
    }

    #[test]
    fn a_dropped_column_disappears_from_the_output_but_not_from_the_pinned_ddl() {
        let (ddl, over) = fixture();
        let names: Vec<String> = output_columns(&ddl, &over)
            .unwrap()
            .into_iter()
            .map(|c| c.name)
            .collect();

        // Section 11's drop classes, marked `drop = true` in the overrides.
        for dropped in [
            "source_url",
            "attachment_path",
            "render_template",
            "payload_serialized",
        ] {
            assert!(
                !names.contains(&dropped.to_owned()),
                "{dropped} was exported"
            );
            // Still in the DDL: it is the authority for what the table *is*, and a column absent
            // from the schema and a column excluded from scope are different facts.
            assert!(ddl.column(dropped).is_some(), "{dropped} left the DDL");
        }
        assert_eq!(dropped_columns(&ddl, &over).len(), 4);
    }

    #[test]
    fn composite_types_flatten_to_several_columns_with_matching_names() {
        let (ddl, over) = fixture();
        let names: Vec<String> = output_columns(&ddl, &over)
            .unwrap()
            .into_iter()
            .map(|c| c.name)
            .collect();

        // A Map is two parallel arrays; a Tuple is one column per element; a Nested is one
        // parallel array per field. The names are ClickHouse's own convention, unrewritten.
        for expected in [
            "labels.keys",
            "labels.values",
            "pair.1",
            "pair.2",
            "events.kind",
            "events.at",
            "events.note",
        ] {
            assert!(
                names.contains(&expected.to_owned()),
                "missing {expected} in {names:?}"
            );
        }
    }

    #[test]
    fn a_nullable_source_column_stays_nullable_in_quarantine() {
        let (ddl, over) = fixture();
        let cols = output_columns(&ddl, &over).unwrap();
        let find = |n: &str| cols.iter().find(|c| c.name == n).unwrap().quarantine;
        // Section 8.2: null is not empty, and the distinction has to survive the import boundary.
        assert_eq!(find("nullable_text"), QuarantineType::NullableString);
        assert_eq!(find("low_card_nullable"), QuarantineType::NullableString);
        assert_eq!(find("ident"), QuarantineType::String);
    }

    #[test]
    fn the_rendered_ddl_carries_the_provenance_columns() {
        let (ddl, over) = fixture();
        let sql = quarantine_ddl(&ddl, &over, "staging.`t__b1__0`").unwrap();
        for (name, _) in PROVENANCE_COLUMNS {
            assert!(sql.contains(&format!("`{name}`")), "missing {name}:\n{sql}");
        }
        assert!(sql.contains("ORDER BY tuple()"), "{sql}");
        assert!(sql.contains("ENGINE = MergeTree"), "{sql}");
    }

    #[test]
    fn the_rendered_ddl_contains_nothing_section_10_forbids() {
        let (ddl, over) = fixture();
        let sql = quarantine_ddl(&ddl, &over, "staging.`t__b1__0`").unwrap();
        // Each of these is an absence rather than a feature, which is exactly why it is easy to
        // reintroduce by accident. Section 10: the table is inert and disconnected.
        for forbidden in [
            "DEFAULT",
            "MATERIALIZED",
            "ALIAS",
            "EPHEMERAL",
            "TTL",
            "CODEC",
            "PROJECTION",
            "INDEX",
            "ROW POLICY",
            "POPULATE",
        ] {
            assert!(
                !sql.to_ascii_uppercase().contains(forbidden),
                "generated DDL must not contain {forbidden}:\n{sql}"
            );
        }
        // And no typed column survived: coercion is what text makes impossible.
        for typed in [
            "UInt8", "DateTime", "Decimal", "Float64", "Enum8", "UUID", "IPv4",
        ] {
            assert!(
                !sql.contains(typed),
                "{typed} leaked into the quarantine DDL:\n{sql}"
            );
        }
    }

    #[test]
    fn a_source_column_shadowing_a_provenance_column_is_refused() {
        let ddl = parse_create_table(
            "CREATE TABLE db.t (`a` UInt8, `_batch` String) ENGINE = MergeTree ORDER BY (`a`)",
        )
        .unwrap();
        let over = toml::from_str::<Overrides>(MATRIX_OVERRIDES).unwrap();
        let err = quarantine_ddl(&ddl, &over, "staging.`t__b1__0`").unwrap_err();
        assert!(err.to_string().contains("_batch"), "{err}");
    }

    #[test]
    fn a_staging_name_is_one_table_per_file() {
        assert_eq!(
            staging_table_name("hits", "b-0001", 7).unwrap(),
            "staging.`hits__b-0001__7`"
        );
        // The seq is what makes it per file rather than shared, so two files never collide.
        assert_ne!(
            staging_table_name("hits", "b-0001", 7).unwrap(),
            staging_table_name("hits", "b-0001", 8).unwrap()
        );
    }

    #[test]
    fn a_staging_name_component_that_could_break_out_of_the_identifier_is_refused() {
        for (table, batch) in [
            ("hits`; DROP TABLE x;--", "b1"),
            ("hits", "b1`; DROP TABLE x;--"),
            ("", "b1"),
            ("hits", ""),
        ] {
            assert!(
                staging_table_name(table, batch, 0).is_err(),
                "{table} / {batch} must be refused"
            );
        }
    }

    #[test]
    fn dropping_every_column_is_refused_rather_than_producing_an_empty_table() {
        let ddl =
            parse_create_table("CREATE TABLE db.t (`a` UInt8) ENGINE = MergeTree ORDER BY (`a`)")
                .unwrap();
        let mut over = toml::from_str::<Overrides>(MATRIX_OVERRIDES).unwrap();
        over.columns.insert(
            "a".to_owned(),
            crate::models::ColumnOverride {
                class: crate::models::FreedomClass::Closed,
                drop: true,
                pattern: None,
                max_len: None,
                enum_ids: None,
                hex: false,
                rotation_owner: None,
            },
        );
        assert!(output_columns(&ddl, &over).is_err());
    }

    #[test]
    fn a_type_nesting_deeper_than_the_pinned_cap_is_refused() {
        // Section 8.4's nesting cap, which was declared and never read until now. Enforced on the
        // declared type: bounding the type bounds every value it can hold, once, rather than per
        // row.
        let deep = parse_create_table(
            "CREATE TABLE db.t (`a` UInt8, `nest` Array(Array(Array(Array(String))))) \
             ENGINE = MergeTree ORDER BY (`a`)",
        )
        .unwrap();
        let mut over = toml::from_str::<Overrides>(MATRIX_OVERRIDES).unwrap();
        over.limits.max_nesting_depth = 3;
        let err = output_columns(&deep, &over).unwrap_err();
        assert!(err.to_string().contains("nests deeper"), "{err}");

        // Raise the cap and the same type is fine, which is what makes it a pinned decision
        // rather than a hard-coded one.
        over.limits.max_nesting_depth = 8;
        assert!(output_columns(&deep, &over).is_ok());
    }

    #[test]
    fn depth_counts_the_outermost_level_and_takes_the_deepest_branch() {
        use crate::clickhouse::types::parse_type;
        assert_eq!(parse_type("String").unwrap().depth(), 1);
        assert_eq!(parse_type("Nullable(String)").unwrap().depth(), 2);
        assert_eq!(parse_type("Array(Nullable(String))").unwrap().depth(), 3);
        // A composite is as deep as its deepest member, not the sum.
        assert_eq!(
            parse_type("Tuple(UInt8, Array(Array(String)))")
                .unwrap()
                .depth(),
            4
        );
        assert_eq!(parse_type("Map(String, Array(UInt8))").unwrap().depth(), 3);
    }

    #[test]
    fn the_pinned_matrix_fits_inside_its_own_pinned_depth_cap() {
        // The fixture and the overrides that ship with it have to agree, or the worked example
        // does not work.
        let (ddl, over) = fixture();
        assert!(output_columns(&ddl, &over).is_ok());
    }
}

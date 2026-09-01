//! Pagination: cursor selection, page sizing, and key-group extension.
//!
//! Some tables run to ~100 GB, which breaks three things at once: the `ORDER BY` cannot sort
//! whole, Q1's disk cannot hold the file, and "abort the batch" becomes a 100 GB re-run over a
//! hostile link. So a table is read in pages, by keyset cursor rather than `OFFSET` (seeking past
//! 100 GB is quadratic, and the `offset` *setting* is one of the truncation vectors we pin to
//! zero).
//!
//! Three rules make strict `>` safe, and all three are load-bearing:
//!
//! 1. The cursor is **re-rendered from our own parsed, validated value**, never interpolated from
//!    server-supplied text.
//! 2. **Nullable columns never enter the cursor.** `(a, b) > (x, NULL)` evaluates to NULL, the row
//!    is excluded, and rows vanish with no check firing.
//! 3. A page that ends **mid-key-group is extended** to consume the rest of that group before the
//!    cursor advances, so a non-unique key cannot let `>` skip a group's tail.
//!

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]

use crate::abort::{Result, SalvageError, abort};
use crate::clickhouse::ddl::PinnedDdl;
use crate::clickhouse::types::{ClickHouseType, Ident};
use crate::limits::div_floor;
use crate::models::Overrides;

/// How many rows to request per page, from the measured size of a row.
///
/// The server's `system.columns` estimate is only the seed. After each page this is recomputed
/// from **our own measured output**, so within one page the sizing stops depending on the
/// compromised server's arithmetic at all.
///
/// Uncompressed bytes, not `bytes_on_disk`: the TSV is what has to fit, not the compressed part.
pub fn rows_per_page(page_byte_budget: u64, bytes_per_row: u64) -> Result<u64> {
    div_floor(page_byte_budget, bytes_per_row, "rows_per_page")
}

/// Whether a declared type can hold NULL at the top level.
///
/// `LowCardinality(Nullable(T))` counts; `Array(Nullable(T))` does not -- the array itself is never
/// NULL, only its elements, and it is the column's own nullability that breaks a tuple comparison.
#[must_use]
pub fn is_nullable(ty: &ClickHouseType) -> bool {
    match ty {
        ClickHouseType::Nullable(_) => true,
        ClickHouseType::LowCardinality(inner) => is_nullable(inner),
        _ => false,
    }
}

/// Choose the pagination cursor: a NOT NULL prefix of the table's sort key.
///
/// Three properties, each load-bearing, and the second is the one that fails silently:
///
/// 1. **It is a prefix of `ORDER BY`,** so `(cursor) > (last)` drives the MergeTree index and the
///    seek is a range scan rather than a table scan. A cursor that is not a key prefix would still
///    be *correct* and would make every page a full scan of a table that does not fit on disk.
/// 2. **No column in it is nullable.** `(a, b) > (x, NULL)` evaluates to NULL in SQL, so the row is
///    excluded -- rows vanish from the export with no check firing anywhere. This is the reason the
///    cursor is chosen here and validated, rather than assumed to be the sort key.
/// 3. **It is non-empty.** `ORDER BY tuple()` is legal DDL and yields no cursor; such a table
///    cannot be paged and is refused rather than read whole.
///
/// The pinned override wins over the sort key when present, because a table whose leading key
/// column is nullable can still be paged on a shorter prefix -- but the prefix rule still applies.
pub fn select_cursor(ddl: &PinnedDdl, overrides: &Overrides) -> Result<Vec<Ident>> {
    let requested: Vec<Ident> = match &overrides.cursor_columns {
        Some(names) => {
            let mut out = Vec::new();
            for name in names {
                out.push(Ident::new(name)?);
            }
            out
        }
        None => ddl.order_by.clone(),
    };

    if requested.is_empty() {
        return abort("table has no sort key, so it has no pagination cursor").map_err(
            |e: SalvageError| {
                e.with("table", ddl.qualified()).with(
                    "reason",
                    "ORDER BY tuple() cannot be paged; keyset pagination needs a key to seek on",
                )
            },
        );
    }

    // A prefix, not a subset: the order matters, because the index is ordered.
    if requested.len() > ddl.order_by.len() || !ddl.order_by.starts_with(&requested) {
        return abort("cursor is not a prefix of the table's ORDER BY key").map_err(
            |e: SalvageError| {
                e.with("table", ddl.qualified())
                    .with("cursor", render_names(&requested))
                    .with("order_by", render_names(&ddl.order_by))
                    .with(
                        "reason",
                        "a non-prefix cursor makes every page a full scan of a table that does \
                         not fit on disk",
                    )
            },
        );
    }

    for key in &requested {
        let column = ddl.column(key.as_str()).ok_or_else(|| {
            abort::<()>("cursor names a column the table does not declare")
                .unwrap_err()
                .with("column", key.as_str())
        })?;
        if is_nullable(&column.ty) {
            return abort("a nullable column cannot be part of the pagination cursor").map_err(
                |e: SalvageError| {
                    e.with("table", ddl.qualified())
                        .with("column", key.as_str())
                        .with("type", column.declared_type.clone())
                        .with(
                            "reason",
                            "(a, b) > (x, NULL) is NULL, so the row is excluded and rows vanish \
                             with no check firing",
                        )
                },
            );
        }
    }

    Ok(requested)
}

/// The total order every export query sorts by: the cursor first, then every remaining exported
/// column in declaration order.
///
/// The key prefix is what drives the index; the remaining columns are what make the order
/// **total**. Without a total order the same rows can come back in a different sequence on the two
/// passes, and the diff that is our only completeness signal compares different orderings of the
/// same data and aborts on every page.
///
/// Dropped columns are excluded on purpose: they are not exported, so two rows differing only in a
/// dropped column are indistinguishable in the output, and sorting on one would be sorting on
/// something the diff cannot see.
pub fn total_order(cursor: &[Ident], ddl: &PinnedDdl, overrides: &Overrides) -> Vec<Ident> {
    let mut out = cursor.to_vec();
    for column in &ddl.columns {
        if overrides
            .columns
            .get(column.name.as_str())
            .is_some_and(|o| o.drop)
        {
            continue;
        }
        if !out.contains(&column.name) {
            out.push(column.name.clone());
        }
    }
    out
}

/// The cutoff predicate, from pinned configuration only.
///
/// Section A2: this, not wall-clock quiet, is what makes the page boundary stable across the two
/// passes. Both halves come from `overrides/`, never from server data -- but the value still
/// reaches SQL as a literal, so it is screened here rather than trusted for being ours. A quote in
/// a pinned file is a typo on a good day.
pub fn cutoff_predicate(ddl: &PinnedDdl, overrides: &Overrides) -> Result<String> {
    let column = Ident::new(&overrides.cutoff_column)?;
    if ddl.column(column.as_str()).is_none() {
        return abort("cutoff column is not declared by the pinned DDL")
            .map_err(|e: SalvageError| e.with("column", column.as_str()));
    }

    let value = &overrides.cutoff_value;
    let ok = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b':' | b' ' | b'.' | b'T' | b'Z'));
    if !ok {
        return abort("cutoff value is not a plain timestamp literal").map_err(
            |e: SalvageError| {
                e.with("value", value.escape_debug()).with(
                    "reason",
                    "it is interpolated into the WHERE clause, so the charset is the control",
                )
            },
        );
    }

    Ok(format!("{} < '{value}'", column.quoted()))
}

/// Render one cursor value as a SQL literal.
///
/// Section A7b: **the cursor is re-rendered from our own parsed, validated value, never
/// interpolated from server text.** The value reaching here has already passed its section 8.3
/// validator, so its charset is known -- and this function re-asserts that rather than trusting
/// it, because the distance between "validated upstream" and "safe to concatenate" is exactly
/// where injection lives.
///
/// Numerics render bare and everything else quoted, because ClickHouse will not compare a `UInt64`
/// column against a `String` literal -- it raises a type error, which would look like a settings
/// problem and send the operator hunting in the wrong place.
pub fn cursor_literal(ty: &ClickHouseType, value: &str) -> Result<String> {
    // Belt and braces over the validator. Nothing that passed a section 8.3 bound can contain
    // these, so this can only fire if a bound is wrong -- which is worth knowing loudly.
    if value.bytes().any(|b| matches!(b, b'\'' | b'\\' | 0)) || value.len() > 128 {
        return abort("cursor value is not renderable as a literal").map_err(|e: SalvageError| {
            e.with("value", value.escape_debug()).with(
                "reason",
                "it passed its type bound and still contains a quote, a backslash or a NUL",
            )
        });
    }

    let bare = matches!(
        ty,
        ClickHouseType::UInt(_)
            | ClickHouseType::Int(_)
            | ClickHouseType::Decimal { .. }
            | ClickHouseType::Bool
    );
    if bare {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-' || b == b'.')
        {
            return abort("numeric cursor value is not a plain number")
                .map_err(|e: SalvageError| e.with("value", value.escape_debug()));
        }
        return Ok(value.to_owned());
    }
    Ok(format!("'{value}'"))
}

/// The keyset seek predicate: `(a, b) > ('x', 42)`.
///
/// `OFFSET` is not used. Seeking past 100 GB is quadratic, and the `offset` *setting* is one of the
/// truncation vectors the pinned block holds at zero.
pub fn seek_predicate(cursor: &[Ident], literals: &[String]) -> Result<String> {
    if cursor.len() != literals.len() || cursor.is_empty() {
        return abort("cursor tuple and value tuple disagree").map_err(|e: SalvageError| {
            e.with("columns", cursor.len())
                .with("values", literals.len())
        });
    }
    let cols = cursor
        .iter()
        .map(Ident::quoted)
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!("({cols}) > ({})", literals.join(", ")))
}

/// The equality predicate used to extend a page that ended mid-key-group.
///
/// If the sort key is not unique, a key group can straddle a page boundary and strict `>` would
/// skip its tail. Consuming the rest of the group before the cursor advances is what makes `>`
/// correct -- one extra bounded query per page, and only when the boundary actually falls inside
/// a group.
pub fn group_predicate(cursor: &[Ident], literals: &[String]) -> Result<String> {
    if cursor.len() != literals.len() || cursor.is_empty() {
        return abort("cursor tuple and value tuple disagree").map_err(|e: SalvageError| {
            e.with("columns", cursor.len())
                .with("values", literals.len())
        });
    }
    let cols = cursor
        .iter()
        .map(Ident::quoted)
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!("({cols}) = ({})", literals.join(", ")))
}

fn render_names(names: &[Ident]) -> String {
    names
        .iter()
        .map(Ident::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::abort::ExitCode;

    #[test]
    fn page_size_comes_from_row_size() {
        assert_eq!(rows_per_page(1_000_000, 100).unwrap(), 10_000);
    }

    #[test]
    fn a_fatter_row_yields_a_shorter_page() {
        let thin = rows_per_page(1_000_000, 100).unwrap();
        let fat = rows_per_page(1_000_000, 1_000).unwrap();
        assert!(fat < thin);
    }

    #[test]
    fn a_zero_byte_row_estimate_aborts_rather_than_panicking() {
        let e = rows_per_page(1_000_000, 0).unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
    }

    use crate::clickhouse::ddl::parse_create_table;
    use crate::models::Overrides;

    const MATRIX_DDL: &str = include_str!("../ddl/typematrix.typematrix.sql");
    const MATRIX_OVER: &str = include_str!("../overrides/typematrix.typematrix.toml");

    fn fixture() -> (PinnedDdl, Overrides) {
        (
            parse_create_table(MATRIX_DDL).unwrap(),
            toml::from_str(MATRIX_OVER).unwrap(),
        )
    }

    fn names(v: &[Ident]) -> Vec<&str> {
        v.iter().map(Ident::as_str).collect()
    }

    #[test]
    fn the_cursor_is_the_pinned_key_tuple() {
        let (ddl, over) = fixture();
        assert_eq!(
            names(&select_cursor(&ddl, &over).unwrap()),
            vec!["ts", "id"]
        );
    }

    #[test]
    fn a_nullable_column_can_never_enter_the_cursor() {
        // The failure this prevents is silent: `(a, b) > (x, NULL)` is NULL, so the row is
        // excluded and rows vanish from the export with no check firing anywhere.
        let ddl = parse_create_table(
            "CREATE TABLE db.t (`ts` DateTime, `maybe` Nullable(UInt64)) \
             ENGINE = MergeTree ORDER BY (`ts`, `maybe`)",
        )
        .unwrap();
        // Fall back to the DDL's own sort key rather than the fixture's pinned cursor.
        let (_, mut over) = fixture();
        over.cursor_columns = None;
        let err = select_cursor(&ddl, &over).unwrap_err();
        assert!(err.to_string().contains("maybe"), "{err}");
        assert!(err.to_string().contains("NULL"), "{err}");
        assert_eq!(err.exit_code(), ExitCode::Abort);
    }

    #[test]
    fn low_cardinality_hides_a_nullable_and_is_still_refused() {
        let ddl = parse_create_table(
            "CREATE TABLE db.t (`ts` DateTime, `k` LowCardinality(Nullable(String))) \
             ENGINE = MergeTree ORDER BY (`ts`, `k`)",
        )
        .unwrap();
        let (_, mut over) = fixture();
        over.cursor_columns = None;
        let err = select_cursor(&ddl, &over).unwrap_err();
        assert!(err.to_string().contains("NULL"), "{err}");
    }

    #[test]
    fn an_array_of_nullable_is_not_itself_nullable() {
        // The array is never NULL, only its elements, and it is the column's own nullability that
        // breaks the tuple comparison.
        let ty = crate::clickhouse::types::parse_type("Array(Nullable(UInt8))").unwrap();
        assert!(!is_nullable(&ty));
        let ty = crate::clickhouse::types::parse_type("Nullable(UInt8)").unwrap();
        assert!(is_nullable(&ty));
    }

    #[test]
    fn a_cursor_that_is_not_a_key_prefix_is_refused() {
        // Correct but catastrophic: every page would be a full scan of a table that does not fit
        // on disk. A shorter prefix is fine; a different order is not.
        let (ddl, mut over) = fixture();
        over.cursor_columns = Some(vec!["id".into(), "ts".into()]);
        assert!(select_cursor(&ddl, &over).is_err());

        over.cursor_columns = Some(vec!["ts".into()]);
        assert_eq!(names(&select_cursor(&ddl, &over).unwrap()), vec!["ts"]);
    }

    #[test]
    fn a_table_with_no_sort_key_cannot_be_paged() {
        let ddl =
            parse_create_table("CREATE TABLE db.t (`a` UInt8) ENGINE = MergeTree ORDER BY tuple()")
                .unwrap();
        let (_, mut over) = fixture();
        over.cursor_columns = None;
        let err = select_cursor(&ddl, &over).unwrap_err();
        assert!(err.to_string().contains("no pagination cursor"), "{err}");
    }

    #[test]
    fn the_total_order_starts_with_the_cursor_and_excludes_dropped_columns() {
        let (ddl, over) = fixture();
        let cursor = select_cursor(&ddl, &over).unwrap();
        let order = total_order(&cursor, &ddl, &over);
        let o = names(&order);

        assert_eq!(&o[..2], &["ts", "id"], "the key prefix drives the index");
        // Without the remaining columns the order is not total, and two passes of the same page
        // need not come back byte-identical -- which would abort the diff on every page.
        assert!(o.len() > 2);
        for dropped in [
            "source_url",
            "attachment_path",
            "render_template",
            "payload_serialized",
        ] {
            assert!(
                !o.contains(&dropped),
                "{dropped} is not exported, so sorting on it is invisible to the diff"
            );
        }
        let mut deduped = o.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            o.len(),
            "a column appears twice in the ORDER BY"
        );
    }

    #[test]
    fn the_cutoff_predicate_comes_from_pinned_config_and_is_charset_screened() {
        let (ddl, mut over) = fixture();
        assert_eq!(
            cutoff_predicate(&ddl, &over).unwrap(),
            "`ts` < '2026-08-25 00:00:00'"
        );

        // It is interpolated into the WHERE clause, so the charset is the control -- even though
        // the value comes from our own pinned file.
        for hostile in ["2026-08-25' OR 1=1 --", "x", "2026-08-25\u{0}", ""] {
            over.cutoff_value = hostile.to_owned();
            assert!(cutoff_predicate(&ddl, &over).is_err(), "{hostile:?}");
        }

        over.cutoff_value = "2026-08-25 00:00:00".to_owned();
        over.cutoff_column = "not_a_column".to_owned();
        assert!(cutoff_predicate(&ddl, &over).is_err());
    }
}

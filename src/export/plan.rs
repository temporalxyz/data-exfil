//! `salvage plan`: derive the contract from pinned source control, then cross-check the cluster.
//!
//! Section 4 fixes the direction of trust and it is the whole point of this module:
//!
//! > Allowlist comes from source control. The server's `system.tables` answer is a **cross-check,
//! > never the authority.**
//!
//! So the plan is built from `ddl/` and `overrides/` alone, and the cluster is then asked whether
//! it agrees. A disagreement aborts. Nothing the server says is ever *adopted* -- if
//! `system.columns` reports a column our pinned DDL does not declare, that is a finding, not a
//! schema update.
//!
//! # Running without a cluster
//!
//! The cross-check needs a connection; deriving the contract does not. `plan` therefore runs in
//! both modes, and [`crate::models::PlanJson::cluster_cross_checked`] records which one produced
//! the document. That flag exists because an unverified plan and a verified one are otherwise
//! indistinguishable on disk, and the acceptance criterion for this whole step is that a reviewer
//! can read the exact bound for every column **before** anything touches the compromised cluster.

use crate::abort::{Result, SalvageError, abort};
use crate::clickhouse::ddl::PinnedDdl;
use crate::clickhouse::quarantine::{dropped_columns, output_columns};
use crate::clickhouse::settings::EXPORT_SETTINGS;
use crate::clickhouse::types::{Ident, parse_type, rules_for};
use crate::clickhouse::{Query, QueryKind, QueryRunner, tsv};
use crate::models::{ColumnPlan, FreedomClass, Overrides, PlanJson, far_side_name};
use crate::pages::{cutoff_predicate, rows_per_page, select_cursor, total_order};

/// Set by the release build; `unpinned` in a local one. It travels in every plan and manifest, so
/// a document can be traced to the code that produced it.
pub const GIT_COMMIT: &str = match option_env!("SALVAGE_GIT_COMMIT") {
    Some(c) => c,
    None => "unpinned",
};

/// The contract version is the crate version: the bounds live in this binary, so they move together.
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the compromised server says about the table. Every field is a cross-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterFacts {
    pub engine: String,
    /// `(name, type)` in declaration order, from `system.columns`.
    pub columns: Vec<(String, String)>,
    /// `sum(data_uncompressed_bytes)`. Uncompressed because the TSV is what has to fit on Q1's
    /// disk, not the compressed part.
    pub uncompressed_bytes: u64,
    /// `count()` under the cutoff.
    pub row_count: u64,
    /// `sum(rows) FROM system.parts WHERE active`, for the **whole table**.
    ///
    /// The third number in the reconciliation, and the only one that is not scoped to the cutoff:
    /// `system.parts` counts granules, and a part can straddle the cutoff, so there is no
    /// predicate that would scope it without trusting the server to apply one. That makes it an
    /// upper bound rather than an equal -- see [`reconcile`]. Both this and `row_count` come from
    /// the compromised server, so agreement with what we streamed is a cross-check, never a proof.
    pub parts_rows: u64,
}

fn introspect_query(sql: String) -> Query {
    Query {
        sql,
        settings: &EXPORT_SETTINGS,
        kind: QueryKind::Introspect,
    }
}

/// Ask the cluster about the table. Reads no table data beyond a `count()`.
pub fn introspect(runner: &dyn QueryRunner, ddl: &PinnedDdl, cutoff: &str) -> Result<ClusterFacts> {
    // `db` and `table` are `Ident`s from our own pinned DDL -- charset `[A-Za-z0-9_]` -- so
    // quoting them as literals is safe. This is the one direction section 4 permits: our names
    // into their query, never their names into ours.
    let db = ddl.database.as_str();
    let table = ddl.table.as_str();
    let scope = format!("database = '{db}' AND table = '{table}'");

    let engine = runner.scalar(&introspect_query(format!(
        "SELECT engine FROM system.tables WHERE database = '{db}' AND name = '{table}'"
    )))?;
    if engine.is_empty() {
        return abort("the cluster does not have this table")
            .map_err(|e: SalvageError| e.with("table", ddl.qualified()));
    }

    let columns = read_rows(
        runner,
        format!("SELECT name, type FROM system.columns WHERE {scope} ORDER BY position"),
        2,
    )?
    .into_iter()
    .map(|mut row| {
        let ty = row.pop().unwrap_or_default();
        let name = row.pop().unwrap_or_default();
        (name, ty)
    })
    .collect();

    let uncompressed_bytes = parse_u64(&runner.scalar(&introspect_query(format!(
        "SELECT sum(data_uncompressed_bytes) FROM system.columns WHERE {scope}"
    )))?)?;

    let row_count = parse_u64(&runner.scalar(&introspect_query(format!(
        "SELECT count() FROM `{db}`.`{table}` WHERE {cutoff}"
    )))?)?;

    let parts_rows = parse_u64(&runner.scalar(&introspect_query(format!(
        "SELECT sum(rows) FROM system.parts \
         WHERE active AND database = '{db}' AND table = '{table}'"
    )))?)?;

    Ok(ClusterFacts {
        engine,
        columns,
        uncompressed_bytes,
        row_count,
        parts_rows,
    })
}

/// Assert every pinned setting name exists on this server (addition A1).
///
/// ClickHouse renames settings across versions, and a name the server does not recognise is a
/// setting we **silently failed to pin** -- indistinguishable, from the client, from never having
/// pinned it at all.
pub fn assert_settings_known(runner: &dyn QueryRunner) -> Result<()> {
    let names: Vec<String> = read_rows(runner, "SELECT name FROM system.settings".to_owned(), 1)?
        .into_iter()
        .filter_map(|mut r| r.pop())
        .collect();
    EXPORT_SETTINGS.assert_all_known(&names)
}

/// Compare the cluster's answer against the pinned DDL. Any disagreement is a finding.
pub fn cross_check(ddl: &PinnedDdl, facts: &ClusterFacts) -> Result<()> {
    if !crate::clickhouse::ddl::APPROVED_ENGINES.contains(&facts.engine.as_str()) {
        return abort("the cluster reports an engine outside the approved MergeTree family")
            .map_err(|e: SalvageError| {
                e.with("table", ddl.qualified())
                    .with("engine", facts.engine.escape_debug())
            });
    }
    if facts.engine != ddl.engine {
        return abort("the cluster's engine disagrees with the pinned DDL").map_err(
            |e: SalvageError| {
                e.with("pinned", ddl.engine.clone())
                    .with("cluster", facts.engine.escape_debug())
            },
        );
    }

    if facts.columns.len() != ddl.columns.len() {
        return abort("the cluster reports a different number of columns").map_err(
            |e: SalvageError| {
                e.with("pinned", ddl.columns.len())
                    .with("cluster", facts.columns.len())
            },
        );
    }

    for (i, (name, ty)) in facts.columns.iter().enumerate() {
        // The server's column name is attacker-influenced, so it is screened before it is even
        // compared -- section 4's far-side-name rule.
        let name = far_side_name("column", name)?;
        let pinned = ddl.columns.get(i).ok_or_else(|| {
            abort::<()>("column index out of range")
                .unwrap_err()
                .with("index", i)
        })?;
        if pinned.name.as_str() != name {
            return abort("the cluster's column order disagrees with the pinned DDL").map_err(
                |e: SalvageError| {
                    e.with("position", i)
                        .with("pinned", pinned.name.as_str())
                        .with("cluster", name)
                },
            );
        }
        // Canonical comparison, so `Decimal(5, 2)` and `Decimal(5,2)` agree while anything
        // genuinely different does not. Parsing the server's type here is safe: it either parses
        // to something we model, or it aborts -- and a type we do not model is a finding anyway.
        let cluster_ty = parse_type(ty).map_err(|e| {
            e.with("column", pinned.name.as_str())
                .with("cluster_type", ty.escape_debug())
        })?;
        if cluster_ty.canonical() != pinned.ty.canonical() {
            return abort("the cluster's column type disagrees with the pinned DDL").map_err(
                |e: SalvageError| {
                    e.with("column", pinned.name.as_str())
                        .with("pinned", pinned.ty.canonical())
                        .with("cluster", cluster_ty.canonical())
                },
            );
        }
    }
    Ok(())
}

/// Build `plan.json` from pinned source control, optionally folding in the cluster's answer.
pub fn build(
    ddl: &PinnedDdl,
    overrides: &Overrides,
    facts: Option<&ClusterFacts>,
) -> Result<PlanJson> {
    let cursor = select_cursor(ddl, overrides)?;
    let order = total_order(&cursor, ddl, overrides);
    let cutoff = cutoff_predicate(ddl, overrides)?;
    let outputs = output_columns(ddl, overrides)?;
    let dropped = dropped_columns(ddl, overrides);

    let mut columns = Vec::new();
    for column in &ddl.columns {
        let over = overrides.columns.get(column.name.as_str());
        let is_dropped = over.is_some_and(|o| o.drop);
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

        let export_sql = if is_dropped {
            Vec::new()
        } else {
            rules
                .columns
                .iter()
                .map(|c| c.expr.render(&column.name))
                .collect()
        };

        columns.push(ColumnPlan {
            name: column.name.as_str().to_owned(),
            declared_type: column.declared_type.clone(),
            // A column nobody classified inherits Closed. That is the fail-closed default: an
            // unclassified column is not silently treated as free text.
            class: over.map_or(FreedomClass::Closed, |o| o.class),
            dropped: is_dropped,
            rules,
            export_sql,
        });
    }

    // Seeded from the server when we have it, and from the budget alone when we do not. Either
    // way it is only a seed: after each page this is recomputed from our own measured output, so
    // within one page the sizing stops depending on the compromised server's arithmetic.
    let rows = match facts {
        Some(f) if f.row_count > 0 => {
            let per_row =
                crate::limits::div_floor(f.uncompressed_bytes, f.row_count, "bytes_per_row")?
                    .max(1);
            rows_per_page(overrides.page_byte_budget, per_row)?
        }
        _ => 0,
    };

    Ok(PlanJson {
        table: ddl.qualified(),
        contract_version: CONTRACT_VERSION.to_owned(),
        git_commit: GIT_COMMIT.to_owned(),
        engine: ddl.engine.clone(),
        columns,
        cursor_columns: cursor.iter().map(|i| i.as_str().to_owned()).collect(),
        order_by: order.iter().map(|i| i.as_str().to_owned()).collect(),
        rows_per_page: rows,
        cutoff_predicate: cutoff,
        cluster_cross_checked: facts.is_some(),
        dropped_columns: dropped,
        output_columns: outputs.iter().map(|c| c.name.clone()).collect(),
    })
}

/// Read a `TabSeparatedWithNames` result into rows of decoded, screened strings.
///
/// Bounded by the reader the seam handed back, decoded by section 8.2's strict rules, and every
/// value screened as a far-side name -- because everything here becomes an identifier we compare
/// against pinned source control.
fn read_rows(runner: &dyn QueryRunner, sql: String, fields: usize) -> Result<Vec<Vec<String>>> {
    let mut body = Vec::new();
    let mut reader = runner.stream(&introspect_query(sql))?;
    std::io::Read::read_to_end(&mut reader, &mut body).map_err(|e| {
        if crate::clickhouse::client::is_budget_overrun(&e) {
            abort::<()>("introspection response exceeded its budget")
                .unwrap_err()
                .with("detail", e.to_string())
        } else {
            crate::abort::infra::<()>(format!("introspection read failed: {e}")).unwrap_err()
        }
    })?;

    let mut lines = body.split(|b| *b == b'\n');
    // Discard the header: we asked for these columns by name, in this order.
    let _ = lines.next();

    let mut rows = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let raw = tsv::split_row(line);
        if raw.len() != fields {
            return abort("introspection row has the wrong field count")
                .map_err(|e: SalvageError| e.with("expected", fields).with("got", raw.len()));
        }
        let mut row = Vec::with_capacity(fields);
        for field in raw {
            let decoded = tsv::decode_field(field)?;
            let bytes = decoded.bytes().ok_or_else(|| {
                abort::<()>("introspection returned NULL where a name was expected").unwrap_err()
            })?;
            let text = std::str::from_utf8(bytes)
                .map_err(|_| abort::<()>("introspection value is not UTF-8").unwrap_err())?;
            row.push(text.to_owned());
        }
        rows.push(row);
    }
    Ok(rows)
}

fn parse_u64(s: &str) -> Result<u64> {
    // Screened before parsing, the same discipline `types.rs` applies to `num-bigint`: the regex
    // is the authority, the parser is not. Rust's `parse` is stricter than num-bigint's, but the
    // habit is worth keeping uniform.
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return abort("expected a plain decimal integer from the cluster")
            .map_err(|e: SalvageError| e.with("value", s.escape_debug()));
    }
    s.parse::<u64>()
        .map_err(|_| abort::<()>("integer from the cluster does not fit in u64").unwrap_err())
}

/// The three-number agreement: what we streamed, what `count()` said, what `system.parts` said.
///
/// Two of the three come from the compromised server, so agreement is a cross-check and not a
/// proof -- a root attacker can lie consistently. It is still the only completeness signal the
/// chain has, because section 0 concedes *"nothing verifies that what came back is all of what
/// existed"*, and any inconsistency plus every accidental gap shows up here.
///
/// This is **not** a check that the source stood still. Freezing the source is an operational step
/// handled out of band, and nothing in this tool attempts it or verifies it. What this checks is
/// our own export: that the pages we wrote add up to the table we were told about.
pub fn reconcile(streamed: u64, facts: &ClusterFacts) -> Result<()> {
    // The two cutoff-scoped numbers must be exactly equal: `count()` carries the same `WHERE` the
    // pages did, so a dropped page or a short read shows up here as an inequality.
    if streamed != facts.row_count {
        return abort("the streamed row count does not match the server's count()").map_err(
            |e: SalvageError| {
                e.with("streamed", streamed)
                    .with("server_count", facts.row_count)
                    .with("cutoff_scoped", "both")
                    .with(
                        "reason",
                        "a page was dropped, or the server returned fewer rows than it counted",
                    )
            },
        );
    }
    // `parts_rows` is the whole table, cutoff included and excluded alike, so it can only ever be
    // an upper bound. Demanding equality here would abort every run against a table that is still
    // receiving rows above the cutoff -- which is every live table. Streaming *more* than the
    // parts total is still a contradiction, because no predicate can select rows that no part
    // holds, and that is what this arm catches.
    if streamed > facts.parts_rows {
        return abort("more rows were streamed than the server's parts hold").map_err(
            |e: SalvageError| {
                e.with("streamed", streamed)
                    .with("server_parts_rows", facts.parts_rows)
                    .with(
                        "reason",
                        "the server's own two numbers are inconsistent with each other",
                    )
            },
        );
    }
    Ok(())
}

/// The projection: one `(output name, SQL expression)` per exported column, in order.
///
/// This is the only place the export query's column list is produced, and every expression comes
/// from [`crate::clickhouse::types::ExportExpr::render`] rather than from string concatenation.
/// The names are also the TSV header, which the import validates against with
/// `input_format_with_names_use_header=1`.
pub fn projection(ddl: &PinnedDdl, overrides: &Overrides) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for column in &ddl.columns {
        if overrides
            .columns
            .get(column.name.as_str())
            .is_some_and(|o| o.drop)
        {
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
            out.push((
                format!("{}{}", column.name.as_str(), projected.suffix),
                projected.expr.render(&column.name),
            ));
        }
    }
    Ok(out)
}

/// Both names, for the `--json` summary and for `Ident` reuse elsewhere.
#[must_use]
pub fn cursor_names(cursor: &[Ident]) -> Vec<String> {
    cursor.iter().map(|i| i.as_str().to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clickhouse::ddl::parse_create_table;
    use crate::testkit::FakeRunner;

    const OVERRIDES: &str = include_str!("../../overrides/typematrix.typematrix.toml");

    fn ddl() -> PinnedDdl {
        parse_create_table(
            "CREATE TABLE db.t (`ts` DateTime, `id` UUID, `n` Decimal(5, 2)) \
             ENGINE = MergeTree ORDER BY (`ts`, `id`)",
        )
        .unwrap()
    }

    fn overrides() -> Overrides {
        let mut o: Overrides = toml::from_str(OVERRIDES).unwrap();
        o.cutoff_column = "ts".into();
        o.cursor_columns = Some(vec!["ts".into(), "id".into()]);
        o.columns.clear();
        o
    }

    /// A cluster that agrees with `ddl()`.
    fn honest_cluster() -> FakeRunner {
        FakeRunner::new()
            .on("system.tables", b"MergeTree".to_vec())
            .on("system.parts", b"1000".to_vec())
            // Registered before the byte-sum query, which also names system.columns.
            .on(
                "ORDER BY position",
                b"name\ttype\nts\tDateTime\nid\tUUID\nn\tDecimal(5, 2)\n".to_vec(),
            )
            .on("data_uncompressed_bytes", b"1000000".to_vec())
            .on("count()", b"1000".to_vec())
            .on("system.settings", render_settings_response().into_bytes())
    }

    /// Every pinned setting name, as `system.settings` would report them.
    fn render_settings_response() -> String {
        let mut out = String::from("name\n");
        for item in EXPORT_SETTINGS.items {
            out.push_str(item.name);
            out.push('\n');
        }
        out
    }

    #[test]
    fn a_cluster_that_agrees_with_the_pinned_ddl_passes() {
        let runner = honest_cluster();
        let facts = introspect(&runner, &ddl(), "`ts` < '2026-08-25'").unwrap();
        cross_check(&ddl(), &facts).unwrap();
        assert_eq!(facts.engine, "MergeTree");
        assert_eq!(facts.row_count, 1000);
        // The third number, and the one the reconciliation needs.
        assert_eq!(facts.parts_rows, 1000);
        reconcile(1000, &facts).unwrap();
        // A dropped page shows up here and nowhere else.
        assert!(reconcile(999, &facts).is_err());

        // `parts_rows` is the whole table while `row_count` carries the cutoff, so a table still
        // taking writes above the cutoff must still reconcile. Requiring equality against an
        // unscoped parts total made a successful run impossible on any live table.
        let live = ClusterFacts {
            parts_rows: 9_999,
            ..facts.clone()
        };
        reconcile(1000, &live).unwrap();

        // Streaming more than the parts hold is the server contradicting itself.
        let short = ClusterFacts {
            row_count: 20_000,
            parts_rows: 1_000,
            ..facts.clone()
        };
        let err = reconcile(20_000, &short)
            .err()
            .unwrap_or_else(|| panic!("streaming past the parts total must abort"));
        assert!(
            err.to_string().contains("parts hold"),
            "wrong reason: {err}"
        );

        // Addition A1: the throw-mode block rides on the introspection queries too. A query that
        // slipped out without it could be truncated just as quietly as a page read.
        assert!(runner.every_query_carried("read_overflow_mode = 'throw'"));
    }

    #[test]
    fn a_type_disagreement_is_a_finding_not_a_schema_update() {
        // Section 4: the server's answer is a cross-check, never the authority. `Decimal(5,2)`
        // becoming `Decimal(10,2)` on the cluster means the table is not what source control says.
        let runner = honest_cluster().on(
            "ORDER BY position",
            b"name\ttype\nts\tDateTime\nid\tUUID\nn\tDecimal(10, 2)\n".to_vec(),
        );
        let _ = runner;
        let runner = FakeRunner::new()
            .on("system.tables", b"MergeTree".to_vec())
            .on("system.parts", b"10".to_vec())
            .on(
                "ORDER BY position",
                b"name\ttype\nts\tDateTime\nid\tUUID\nn\tDecimal(10, 2)\n".to_vec(),
            )
            .on("data_uncompressed_bytes", b"1000".to_vec())
            .on("count()", b"10".to_vec());
        let facts = introspect(&runner, &ddl(), "1").unwrap();
        let err = cross_check(&ddl(), &facts).unwrap_err();
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort);
        assert!(err.to_string().contains("Decimal(10, 2)"), "{err}");
    }

    #[test]
    fn whitespace_in_a_type_is_not_a_disagreement() {
        // `Decimal(5,2)` and `Decimal(5, 2)` are the same type. Comparing raw strings would abort
        // every run against a server that formats them differently from our pinned file.
        let runner = FakeRunner::new()
            .on("system.tables", b"MergeTree".to_vec())
            .on("system.parts", b"10".to_vec())
            .on(
                "ORDER BY position",
                b"name\ttype\nts\tDateTime\nid\tUUID\nn\tDecimal(5,2)\n".to_vec(),
            )
            .on("data_uncompressed_bytes", b"1000".to_vec())
            .on("count()", b"10".to_vec());
        let facts = introspect(&runner, &ddl(), "1").unwrap();
        cross_check(&ddl(), &facts).unwrap();
    }

    #[test]
    fn a_reordered_or_extra_column_is_refused() {
        for body in [
            // Reordered: `input_format_with_names_use_header` would catch this later, but the
            // export projection is built from the pinned order and would already be wrong.
            &b"name\ttype\nid\tUUID\nts\tDateTime\nn\tDecimal(5, 2)\n"[..],
            // An extra column the pinned DDL does not declare.
            &b"name\ttype\nts\tDateTime\nid\tUUID\nn\tDecimal(5, 2)\nsneaky\tString\n"[..],
            // A missing one.
            &b"name\ttype\nts\tDateTime\nid\tUUID\n"[..],
        ] {
            let runner = FakeRunner::new()
                .on("system.tables", b"MergeTree".to_vec())
                .on("system.parts", b"10".to_vec())
                .on("ORDER BY position", body.to_vec())
                .on("data_uncompressed_bytes", b"1000".to_vec())
                .on("count()", b"10".to_vec());
            let facts = introspect(&runner, &ddl(), "1").unwrap();
            assert!(cross_check(&ddl(), &facts).is_err(), "{body:?}");
        }
    }

    #[test]
    fn an_engine_the_cluster_swapped_underneath_us_is_refused() {
        // The pinned DDL says MergeTree; the live table is a Distributed pointing somewhere else.
        // Section 4 rejects the engine, and this is the path where the server volunteers it.
        let runner = FakeRunner::new()
            .on("system.tables", b"Distributed".to_vec())
            .on("system.parts", b"10".to_vec())
            .on(
                "ORDER BY position",
                b"name\ttype\nts\tDateTime\nid\tUUID\nn\tDecimal(5, 2)\n".to_vec(),
            )
            .on("data_uncompressed_bytes", b"1000".to_vec())
            .on("count()", b"10".to_vec());
        let facts = introspect(&runner, &ddl(), "1").unwrap();
        let err = cross_check(&ddl(), &facts).unwrap_err();
        assert!(err.to_string().contains("Distributed"), "{err}");
    }

    #[test]
    fn a_setting_name_the_server_does_not_know_aborts() {
        // Addition A1. ClickHouse renames settings across versions, and a name the server does not
        // recognise is a setting we silently failed to pin -- indistinguishable, from here, from
        // never having pinned it.
        let mut short = String::from("name\n");
        for item in EXPORT_SETTINGS.items.iter().skip(1) {
            short.push_str(item.name);
            short.push('\n');
        }
        let runner = FakeRunner::new().on("system.settings", short.into_bytes());
        let err = assert_settings_known(&runner).unwrap_err();
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort);

        let honest =
            FakeRunner::new().on("system.settings", render_settings_response().into_bytes());
        assert_settings_known(&honest).unwrap();
    }

    #[test]
    fn a_column_name_the_server_invents_is_screened_before_it_is_compared() {
        // Section 4: column names returned by the server are attacker-influenced.
        let runner = FakeRunner::new()
            .on("system.tables", b"MergeTree".to_vec())
            .on("system.parts", b"10".to_vec())
            .on(
                "ORDER BY position",
                b"name\ttype\nts'; DROP TABLE x;--\tDateTime\nid\tUUID\nn\tDecimal(5, 2)\n"
                    .to_vec(),
            )
            .on("data_uncompressed_bytes", b"1000".to_vec())
            .on("count()", b"10".to_vec());
        let facts = introspect(&runner, &ddl(), "1").unwrap();
        let err = cross_check(&ddl(), &facts).unwrap_err();
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort);
        assert!(err.to_string().contains("charset"), "{err}");
    }

    #[test]
    fn the_page_size_is_seeded_from_the_cluster_but_the_plan_says_so_when_it_is_not() {
        let runner = honest_cluster();
        let facts = introspect(&runner, &ddl(), "1").unwrap();
        // 1,000,000 uncompressed bytes over 1,000 rows is 1,000 bytes/row against a 64 MiB budget.
        let with = build(&ddl(), &overrides(), Some(&facts)).unwrap();
        assert_eq!(with.rows_per_page, 67_108_864 / 1000);
        assert!(with.cluster_cross_checked);

        // Without a cluster the plan is still complete and reviewable -- and honest about which
        // one it is. An unverified plan and a verified one are otherwise identical on disk.
        let without = build(&ddl(), &overrides(), None).unwrap();
        assert!(!without.cluster_cross_checked);
        assert_eq!(without.rows_per_page, 0);
        assert_eq!(with.columns, without.columns);
        assert_eq!(with.cutoff_predicate, without.cutoff_predicate);
    }

    #[test]
    fn a_missing_table_is_a_finding_rather_than_an_empty_plan() {
        let runner = FakeRunner::new()
            .on("system.tables", Vec::new())
            .on("system.parts", b"0".to_vec())
            .on("ORDER BY position", b"name\ttype\n".to_vec())
            .on("data_uncompressed_bytes", b"0".to_vec())
            .on("count()", b"0".to_vec());
        assert!(introspect(&runner, &ddl(), "1").is_err());
    }

    #[test]
    fn a_non_numeric_count_from_the_cluster_is_refused() {
        let runner = FakeRunner::new()
            .on("system.tables", b"MergeTree".to_vec())
            .on("system.parts", b"10".to_vec())
            .on(
                "ORDER BY position",
                b"name\ttype\nts\tDateTime\nid\tUUID\nn\tDecimal(5, 2)\n".to_vec(),
            )
            .on("data_uncompressed_bytes", b"1000".to_vec())
            .on("count()", b"1e6".to_vec());
        assert!(introspect(&runner, &ddl(), "1").is_err());
    }
}

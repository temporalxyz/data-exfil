//! A deliberately restricted `CREATE TABLE` parser.
//!
//! Section 3 requires the schema to come from a pinned commit, and section 4 makes the consequence
//! explicit: *"Allowlist comes from source control. The server's `system.tables` answer is a
//! cross-check, never the authority."* So `ddl/<db>.<table>.sql` is what the table **is**, and this
//! module turns it into a [`PinnedDdl`] that the rest of the tool reasons about.
//!
//! # Why this is not a SQL parser
//!
//! It accepts the subset our pinned DDL uses and **rejects everything else**. A general parser
//! would be a large attack surface solving a problem we do not have -- we control this input, and
//! anything it cannot express is something we would rather not have in scope.
//!
//! The refusals that are security controls rather than convenience:
//!
//! - **`ALIAS`, `EPHEMERAL` and `MATERIALIZED` columns are rejected outright.** Section 4:
//!   *"they evaluate at query time; selecting one asks the compromised server to run
//!   attacker-written code (poisoned UDF, `dictGet`)."* This is the single most important thing
//!   this file does.
//! - **`DEFAULT`, `CODEC`, `TTL` and `COMMENT` on a column are rejected too.** Not because they
//!   execute, but because their presence means the pinned DDL is doing something this tool has not
//!   reasoned about -- and a modifier silently ignored is worse than one refused.
//! - **The engine must be in the MergeTree family.** Section 4 rejects `Distributed`, `Merge`,
//!   `View`, `MaterializedView`, `File`, `URL`, `S3`, `Executable`, `Kafka`, `Dictionary` and every
//!   external-database engine, because *"`Executable` runs a program on SELECT; `URL`/`S3` make the
//!   server fetch; `Dictionary` can invoke an external source."*
//!
//! # Note on the input's trust level
//!
//! This file is ours, from source control, so a parse failure is a `Usage` error rather than a
//! finding -- with one exception. Identifiers and types go through [`Ident::new`] and
//! [`parse_type`], which raise `Abort`, because those same functions run against `system.columns`
//! answers from the compromised server and must behave identically in both directions.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]

use crate::abort::{Result, SalvageError, usage};
use crate::clickhouse::types::{ClickHouseType, Ident, parse_type};

/// Engines permitted by section 4: MergeTree-family **local base tables**.
///
/// `Replicated*` variants are included because they are still local base tables reading local
/// parts. Everything absent from this list is rejected by name, including engines that look
/// harmless: the allowlist is the control, not a denylist we keep having to extend.
pub const APPROVED_ENGINES: &[&str] = &[
    "MergeTree",
    "ReplacingMergeTree",
    "SummingMergeTree",
    "AggregatingMergeTree",
    "CollapsingMergeTree",
    "VersionedCollapsingMergeTree",
    "GraphiteMergeTree",
    "ReplicatedMergeTree",
    "ReplicatedReplacingMergeTree",
    "ReplicatedSummingMergeTree",
    "ReplicatedAggregatingMergeTree",
    "ReplicatedCollapsingMergeTree",
    "ReplicatedVersionedCollapsingMergeTree",
    "ReplicatedGraphiteMergeTree",
];

/// Column modifiers that must never appear, each with why.
///
/// The first three are the section 4 refusals and are the reason this list exists at all.
const FORBIDDEN_COLUMN_MODIFIERS: &[(&str, &str)] = &[
    (
        "ALIAS",
        "an ALIAS column evaluates at query time; selecting one asks the compromised server to run \
         attacker-written code",
    ),
    (
        "MATERIALIZED",
        "a MATERIALIZED column evaluates at query time; selecting one asks the compromised server \
         to run attacker-written code",
    ),
    (
        "EPHEMERAL",
        "an EPHEMERAL column is not stored and cannot be exported",
    ),
    (
        "DEFAULT",
        "a DEFAULT expression is evaluated by the server; export explicit stored columns instead",
    ),
    (
        "CODEC",
        "a per-column CODEC is not modelled; remove it from the pinned DDL",
    ),
    (
        "TTL",
        "a per-column TTL silently removes data and is not modelled",
    ),
    (
        "COMMENT",
        "a column COMMENT is not modelled; keep documentation out of the pinned DDL",
    ),
];

/// Table-level clauses this parser recognises and skips. Anything else is refused, so a clause we
/// have not thought about cannot pass unnoticed.
const KNOWN_TABLE_CLAUSES: &[&str] = &[
    "PARTITION BY",
    "PRIMARY KEY",
    "SAMPLE BY",
    "SETTINGS",
    "TTL",
    "COMMENT",
];

/// One column as the pinned DDL declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedColumn {
    pub name: Ident,
    /// The type exactly as written, before canonicalisation. Kept so `plan.json` can show what the
    /// file said next to what we made of it.
    pub declared_type: String,
    pub ty: ClickHouseType,
}

/// A parsed, validated pinned `CREATE TABLE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedDdl {
    pub database: Ident,
    pub table: Ident,
    pub columns: Vec<PinnedColumn>,
    pub engine: String,
    /// The `ORDER BY` key tuple. This is the pagination cursor's source, so its emptiness matters:
    /// `ORDER BY tuple()` yields no key and step 6 refuses to paginate such a table.
    pub order_by: Vec<Ident>,
}

impl PinnedDdl {
    #[must_use]
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.database.as_str(), self.table.as_str())
    }

    #[must_use]
    pub fn column(&self, name: &str) -> Option<&PinnedColumn> {
        self.columns.iter().find(|c| c.name.as_str() == name)
    }
}

fn bad(reason: impl Into<String>) -> SalvageError {
    usage::<()>(reason).unwrap_err()
}

/// Parse a pinned `CREATE TABLE` statement.
pub fn parse_create_table(sql: &str) -> Result<PinnedDdl> {
    parse_with(sql, Dialect::Pinned)
}

/// Parse a production `SHOW CREATE TABLE` for its column set, order and nullability only.
///
/// Production DDL carries `ON CLUSTER`, per-column `CODEC`, `COMMENT`, `DEFAULT` and `TTL`,
/// none of which say anything about a column's shape. This accepts and discards them. It still
/// refuses `ALIAS`, `MATERIALIZED` and `EPHEMERAL`: those are not stored columns and would never
/// appear in an export, so a schema that names one is not describing the data on disk. Engine and
/// `ORDER BY` are parsed as usual so the same checks apply; callers of this variant do not use
/// them.
pub fn parse_prod_create_table(sql: &str) -> Result<PinnedDdl> {
    parse_with(sql, Dialect::Production)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    /// Our pinned DDL: nothing after a type, nothing between the name and the column list.
    Pinned,
    /// A `SHOW CREATE TABLE` as production writes it.
    Production,
}

/// Column modifiers a production DDL may carry that say nothing about the column's shape.
/// `DEFAULT` and `TTL` take an expression; `CODEC` a parenthesised list; `COMMENT` a string.
const SKIPPED_PROD_MODIFIERS: &[&str] = &["DEFAULT", "CODEC", "COMMENT", "TTL"];

fn parse_with(sql: &str, dialect: Dialect) -> Result<PinnedDdl> {
    let stripped = strip_comments(sql)?;
    let text = stripped.trim();

    let rest = expect_keyword(text, "CREATE")
        .and_then(|r| expect_keyword(r, "TABLE"))
        .ok_or_else(|| bad("pinned DDL must begin with CREATE TABLE"))?;
    // `IF NOT EXISTS` is accepted and ignored; it changes nothing about the shape.
    let rest = expect_keyword(rest, "IF")
        .and_then(|r| expect_keyword(r, "NOT"))
        .and_then(|r| expect_keyword(r, "EXISTS"))
        .unwrap_or(rest);

    let open = rest
        .find('(')
        .ok_or_else(|| bad("pinned DDL has no column list"))?;
    let (name_part, from_paren) = rest.split_at(open);
    let (database, table) = parse_qualified_name(name_part.trim(), dialect)?;

    let close = matching_paren(from_paren)?;
    let body = from_paren
        .get(1..close)
        .ok_or_else(|| bad("malformed column list"))?;
    let tail = from_paren
        .get(close.checked_add(1).ok_or_else(|| bad("overflow"))?..)
        .unwrap_or("")
        .trim();

    let mut columns = Vec::new();
    for entry in split_top_level(body, b',') {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(bad("empty column definition (a trailing comma?)"));
        }
        columns.push(parse_column(entry, dialect)?);
    }
    if columns.is_empty() {
        return Err(bad("pinned DDL declares no columns"));
    }
    // Duplicates would make `system.columns` cross-checking ambiguous and the export column list
    // wrong, and ClickHouse itself would have refused the statement.
    for (i, c) in columns.iter().enumerate() {
        if columns
            .iter()
            .skip(i.checked_add(1).ok_or_else(|| bad("overflow"))?)
            .any(|o| o.name == c.name)
        {
            return Err(bad("duplicate column").with("column", c.name.as_str()));
        }
    }

    let (engine, order_by) = parse_tail(tail, &columns)?;

    Ok(PinnedDdl {
        database,
        table,
        columns,
        engine,
        order_by,
    })
}

/// Split `db.table`, accepting backticks on either part.
fn parse_qualified_name(s: &str, dialect: Dialect) -> Result<(Ident, Ident)> {
    let (db_raw, rest) = read_identifier(s).ok_or_else(|| bad("expected a database name"))?;
    let rest = rest.trim_start();
    let rest = rest
        .strip_prefix('.')
        .ok_or_else(|| bad("expected `db.table`; the database qualifier is not optional"))?;
    let (tbl_raw, rest) = read_identifier(rest.trim_start())
        .ok_or_else(|| bad("expected a table name after the dot"))?;
    // `ON CLUSTER name` routes the statement; it says nothing about the table.
    let rest = match dialect {
        Dialect::Production => expect_keyword(rest, "ON")
            .and_then(|r| expect_keyword(r, "CLUSTER"))
            .and_then(|r| read_identifier(r).map(|(_, after)| after))
            .unwrap_or(rest),
        Dialect::Pinned => rest,
    };
    if !rest.trim().is_empty() {
        return Err(
            bad("unexpected text between the table name and the column list")
                .with("text", rest.trim().escape_debug()),
        );
    }
    Ok((Ident::new(&db_raw)?, Ident::new(&tbl_raw)?))
}

/// One `` `name` Type `` entry, with nothing permitted after the type in the pinned dialect.
fn parse_column(entry: &str, dialect: Dialect) -> Result<PinnedColumn> {
    let (name_raw, rest) = read_identifier(entry).ok_or_else(|| {
        bad("column definition does not begin with a name").with("entry", entry.escape_debug())
    })?;
    let name = Ident::new(&name_raw)?;
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(bad("column has no type").with("column", name.as_str()));
    }

    let (declared_type, trailing) = split_type(rest)?;
    let trailing = match dialect {
        Dialect::Production => skip_prod_modifiers(trailing, name.as_str())?,
        Dialect::Pinned => trailing,
    };
    let trailing = trailing.trim();
    if !trailing.is_empty() {
        // Name the modifier if we recognise it, because the *reason* is the useful part -- an
        // operator who is told "ALIAS columns run server-side code" fixes the DDL correctly,
        // whereas one told "parse error" removes whatever makes the error go away.
        let upper = trailing.to_ascii_uppercase();
        for (kw, why) in FORBIDDEN_COLUMN_MODIFIERS {
            if upper.starts_with(kw) {
                return Err(bad(format!("column modifier `{kw}` is not permitted"))
                    .with("column", name.as_str())
                    .with("reason", *why));
            }
        }
        return Err(bad("unexpected text after a column type")
            .with("column", name.as_str())
            .with("text", trailing.escape_debug()));
    }

    let ty = parse_type(&declared_type)?;
    Ok(PinnedColumn {
        name,
        declared_type,
        ty,
    })
}

/// Consume the shape-irrelevant modifiers a production column may carry, in any order.
///
/// Stops at the first thing it does not recognise and hands it back, so the caller's forbidden-
/// modifier check still names `ALIAS`/`MATERIALIZED`/`EPHEMERAL` with their reasons rather than
/// this function swallowing them. An expression after `DEFAULT` or `TTL` runs to the next
/// recognised modifier keyword at the top level, outside strings and parentheses.
fn skip_prod_modifiers<'a>(mut s: &'a str, column: &str) -> Result<&'a str> {
    loop {
        let trimmed = s.trim_start();
        let Some(kw) = SKIPPED_PROD_MODIFIERS
            .iter()
            .find(|kw| expect_keyword(trimmed, kw).is_some())
        else {
            return Ok(trimmed);
        };
        let after = expect_keyword(trimmed, kw).unwrap_or("").trim_start();
        s = match *kw {
            "CODEC" => {
                let close = matching_paren(after).map_err(|e| e.with("column", column))?;
                after
                    .get(close.checked_add(1).ok_or_else(|| bad("overflow"))?..)
                    .unwrap_or("")
            }
            "COMMENT" => {
                if !after.starts_with('\'') {
                    return Err(bad("COMMENT must be followed by a string").with("column", column));
                }
                after.get(skip_string(after, 0)..).unwrap_or("")
            }
            // DEFAULT / TTL: an expression, ended by the next modifier keyword or the entry's end.
            _ => skip_expression(after),
        };
    }
}

/// Everything up to the next top-level modifier keyword, respecting strings and parentheses.
fn skip_expression(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        let rest = s.get(i..).unwrap_or("");
        if depth == 0
            && i > 0
            && bytes
                .get(i.saturating_sub(1))
                .is_some_and(|b| b.is_ascii_whitespace())
            && SKIPPED_PROD_MODIFIERS
                .iter()
                .chain(FORBIDDEN_COLUMN_MODIFIERS.iter().map(|(kw, _)| kw))
                .any(|kw| expect_keyword(rest, kw).is_some())
        {
            return rest;
        }
        match bytes.get(i) {
            Some(b'(') => depth = depth.saturating_add(1),
            Some(b')') => depth = depth.saturating_sub(1),
            Some(b'\'') => {
                i = skip_string(s, i);
                continue;
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    ""
}

/// Read a type: an identifier optionally followed by one balanced parenthesised argument list.
///
/// Returns the type text and whatever follows it. Greedy on the parens and nothing else, which is
/// exactly what makes `String DEFAULT 'x'` come back with a non-empty tail rather than parsing as
/// a type nobody recognises.
fn split_type(s: &str) -> Result<(String, &str)> {
    let head_end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    if head_end == 0 {
        return Err(bad("expected a type name").with("text", s.escape_debug()));
    }
    let after_head = s.get(head_end..).unwrap_or("");
    if !after_head.starts_with('(') {
        return Ok((s.get(..head_end).unwrap_or("").to_owned(), after_head));
    }
    let close = matching_paren(after_head)?;
    let end = head_end
        .checked_add(close)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| bad("overflow"))?;
    Ok((
        s.get(..end).unwrap_or("").to_owned(),
        s.get(end..).unwrap_or(""),
    ))
}

/// Parse everything after the column list: the engine, the sort key, and the clauses we skip.
fn parse_tail(tail: &str, columns: &[PinnedColumn]) -> Result<(String, Vec<Ident>)> {
    let rest = expect_keyword(tail, "ENGINE")
        .ok_or_else(|| bad("pinned DDL has no ENGINE clause"))?
        .trim_start();
    let rest = rest
        .strip_prefix('=')
        .ok_or_else(|| bad("expected `ENGINE = <engine>`"))?
        .trim_start();

    let (engine, rest) = split_type(rest)?;
    // The engine name without its arguments -- `ReplicatedMergeTree('/path', '{replica}')` is the
    // same engine as `ReplicatedMergeTree`.
    let engine_head = engine.split('(').next().unwrap_or(&engine).to_owned();
    if !APPROVED_ENGINES.contains(&engine_head.as_str()) {
        return Err(
            bad("engine is not an approved MergeTree-family local base table")
                .with("engine", engine_head.escape_debug())
                .with(
                    "reason",
                    "section 4: Executable runs a program on SELECT, URL/S3 make the server fetch, \
                 Dictionary can invoke an external source, and Distributed/Merge/View read \
                 elsewhere",
                ),
        );
    }

    let mut order_by = Vec::new();
    let mut seen_order_by = false;
    let mut cursor = rest.trim_start();

    while !cursor.is_empty() {
        if let Some(after) = expect_keyword(cursor, "ORDER").and_then(|r| expect_keyword(r, "BY")) {
            if seen_order_by {
                return Err(bad("two ORDER BY clauses"));
            }
            seen_order_by = true;
            let (keys, remainder) = parse_key_tuple(after.trim_start())?;
            order_by = keys;
            cursor = remainder.trim_start();
            continue;
        }

        // A known clause we do not model: skip to the next clause keyword and carry on. It is
        // recognised rather than ignored, which is the difference that matters.
        let mut matched = None;
        for clause in KNOWN_TABLE_CLAUSES {
            let mut probe = Some(cursor);
            for word in clause.split(' ') {
                probe = probe.and_then(|p| expect_keyword(p, word));
            }
            if let Some(after) = probe {
                matched = Some(after);
                break;
            }
        }
        match matched {
            Some(after) => cursor = skip_clause(after),
            None => {
                return Err(bad("unrecognised clause after the column list").with(
                    "text",
                    cursor.chars().take(40).collect::<String>().escape_debug(),
                ));
            }
        }
    }

    if !seen_order_by {
        return Err(bad(
            "pinned DDL has no ORDER BY; the pagination cursor is derived from the sort key",
        ));
    }
    for key in &order_by {
        if !columns.iter().any(|c| &c.name == key) {
            return Err(bad("ORDER BY names a column the table does not declare")
                .with("column", key.as_str()));
        }
    }
    Ok((engine_head, order_by))
}

/// `ORDER BY (a, b)`, `ORDER BY a`, or `ORDER BY tuple()`.
fn parse_key_tuple(s: &str) -> Result<(Vec<Ident>, &str)> {
    if let Some(after) = expect_keyword(s, "tuple") {
        let after = after.trim_start();
        let close = matching_paren(after)?;
        if !after.get(1..close).unwrap_or("").trim().is_empty() {
            return Err(bad("ORDER BY tuple(...) with arguments is not modelled"));
        }
        // Legal, and a real answer: this table has no sort key, so it has no cursor. Step 6
        // refuses to paginate such a table rather than inventing one.
        let remainder = after
            .get(close.checked_add(1).ok_or_else(|| bad("overflow"))?..)
            .unwrap_or("");
        return Ok((Vec::new(), remainder));
    }

    if s.starts_with('(') {
        let close = matching_paren(s)?;
        let inner = s.get(1..close).unwrap_or("");
        let mut keys = Vec::new();
        for part in split_top_level(inner, b',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (raw, rest) = read_identifier(part)
                .ok_or_else(|| bad("ORDER BY entry is not a plain column name"))?;
            if !rest.trim().is_empty() {
                // `ORDER BY (toStartOfDay(ts))` is a function call, not a column. The cursor has
                // to re-render from a parsed value, and a value we cannot name we cannot re-render.
                return Err(bad("ORDER BY entry is an expression, not a column")
                    .with("text", part.escape_debug()));
            }
            keys.push(Ident::new(&raw)?);
        }
        let after = s
            .get(close.checked_add(1).ok_or_else(|| bad("overflow"))?..)
            .unwrap_or("");
        return Ok((keys, after));
    }

    let (raw, rest) = read_identifier(s).ok_or_else(|| bad("ORDER BY expects a column name"))?;
    Ok((vec![Ident::new(&raw)?], rest))
}

/// Skip a clause body: everything up to the next top-level clause keyword.
fn skip_clause(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        let rest = s.get(i..).unwrap_or("");
        if depth == 0 {
            let is_boundary = [
                "ORDER BY",
                "PARTITION BY",
                "PRIMARY KEY",
                "SAMPLE BY",
                "SETTINGS",
            ]
            .iter()
            .any(|kw| starts_with_keyword_phrase(rest, kw));
            if is_boundary {
                return rest;
            }
        }
        match bytes.get(i) {
            Some(b'(') => depth = depth.saturating_add(1),
            Some(b')') => depth = depth.saturating_sub(1),
            Some(b'\'') => {
                i = skip_string(s, i);
                continue;
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    ""
}

fn starts_with_keyword_phrase(s: &str, phrase: &str) -> bool {
    let mut probe = Some(s);
    for word in phrase.split(' ') {
        probe = probe.and_then(|p| expect_keyword(p, word));
    }
    probe.is_some()
}

/// Consume a keyword case-insensitively, returning the remainder. `None` if it is not there.
fn expect_keyword<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    let s = s.trim_start();
    if s.len() < keyword.len() {
        return None;
    }
    let (head, tail) = s.split_at(keyword.len());
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    // A keyword must not run into an identifier: `ORDERED` does not start with the keyword ORDER.
    if tail
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(tail)
}

/// Read a backtick-quoted or bare identifier, returning it and the remainder.
fn read_identifier(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    if let Some(body) = s.strip_prefix('`') {
        let end = body.find('`')?;
        return Some((
            body.get(..end)?.to_owned(),
            body.get(end.checked_add(1)?..)?,
        ));
    }
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    Some((s.get(..end)?.to_owned(), s.get(end..)?))
}

/// Index of the `)` matching the `(` at position 0.
fn matching_paren(s: &str) -> Result<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'(') {
        return Err(bad("expected an opening parenthesis"));
    }
    let mut depth = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(b'(') => depth = depth.saturating_add(1),
            Some(b')') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(i);
                }
            }
            // A quoted string can hold anything, including unbalanced parens -- an enum label of
            // `')'` is legal DDL and would otherwise close the list early.
            Some(b'\'') => {
                i = skip_string(s, i);
                continue;
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    Err(bad("unbalanced parentheses in the pinned DDL"))
}

/// Index just past the closing quote of the string starting at `start`.
fn skip_string(s: &str, start: usize) -> usize {
    let bytes = s.as_bytes();
    let mut i = start.saturating_add(1);
    while i < bytes.len() {
        match bytes.get(i) {
            // Backslash escape: skip the escaped byte whatever it is.
            Some(b'\\') => i = i.saturating_add(2),
            Some(b'\'') => {
                // `''` is a doubled quote, not the end of the string.
                if bytes.get(i.saturating_add(1)) == Some(&b'\'') {
                    i = i.saturating_add(2);
                } else {
                    return i.saturating_add(1);
                }
            }
            _ => i = i.saturating_add(1),
        }
    }
    i
}

/// Split on a top-level delimiter, ignoring one inside parentheses or a string literal.
fn split_top_level(s: &str, delim: u8) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(b'(') => depth = depth.saturating_add(1),
            Some(b')') => depth = depth.saturating_sub(1),
            Some(b'\'') => {
                i = skip_string(s, i);
                continue;
            }
            Some(&b) if b == delim && depth == 0 => {
                parts.push(s.get(start..i).unwrap_or(""));
                start = i.saturating_add(1);
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    parts.push(s.get(start..).unwrap_or(""));
    parts
}

/// Replace `--` line comments and `/* */` blocks with spaces, respecting string literals.
///
/// Spaces rather than deletion so every byte offset in the stripped text still lines up with the
/// original, which keeps error messages honest.
fn strip_comments(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let two = s.get(i..i.saturating_add(2)).unwrap_or("");
        if two == "--" {
            while i < bytes.len() && bytes.get(i) != Some(&b'\n') {
                out.push(' ');
                i = i.saturating_add(1);
            }
            continue;
        }
        if two == "/*" {
            let end = s
                .get(i..)
                .and_then(|r| r.find("*/"))
                .ok_or_else(|| bad("unterminated block comment in the pinned DDL"))?;
            for _ in 0..end.saturating_add(2) {
                out.push(' ');
            }
            i = i.saturating_add(end).saturating_add(2);
            continue;
        }
        if bytes.get(i) == Some(&b'\'') {
            let end = skip_string(s, i);
            out.push_str(s.get(i..end).unwrap_or(""));
            i = end;
            continue;
        }
        let ch = s.get(i..).and_then(|r| r.chars().next()).unwrap_or(' ');
        out.push(ch);
        i = i.saturating_add(ch.len_utf8());
    }
    Ok(out)
}

// -- loading the pinned directory ----------------------------------------------------------------

/// Read every `ddl/<db>.<table>.sql`, pairing each with `overrides/<db>.<table>.toml` if present.
///
/// The filename must agree with the `CREATE TABLE` inside it. That check exists because the
/// filename is how everything else addresses the table -- `--table events.hits` finds
/// `ddl/events.hits.sql` -- so a misfiled DDL would silently apply one table's contract to
/// another, which is precisely the class of mistake a pinned-source-control rule is meant to
/// prevent.
///
/// Overrides are optional here. `salvage secrets` runs at incident time and must not wait on
/// anyone having written one yet.
pub fn load_pinned(
    ddl_dir: &std::path::Path,
    overrides_dir: &std::path::Path,
) -> Result<Vec<(PinnedDdl, Option<crate::models::Overrides>)>> {
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(ddl_dir)
        .map_err(|e| {
            bad(format!("could not read the pinned DDL directory: {e}"))
                .with("path", ddl_dir.display())
        })?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    // Sorted so the inventory and every generated document are byte-identical between runs.
    entries.sort();

    let mut out = Vec::new();
    for path in entries {
        let text = std::fs::read_to_string(&path).map_err(|e| {
            bad(format!("could not read pinned DDL: {e}")).with("path", path.display())
        })?;
        let ddl = parse_create_table(&text).map_err(|e| e.with("path", path.display()))?;

        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| bad("pinned DDL has an unreadable filename"))?;
        if stem != ddl.qualified() {
            return Err(
                bad("pinned DDL filename disagrees with the table it declares")
                    .with("filename", stem.escape_debug())
                    .with("declares", ddl.qualified()),
            );
        }

        let over_path = overrides_dir.join(format!("{}.toml", ddl.qualified()));
        let overrides = match std::fs::read_to_string(&over_path) {
            Ok(t) => Some(toml::from_str::<crate::models::Overrides>(&t).map_err(|e| {
                bad(format!("could not parse overrides: {e}")).with("path", over_path.display())
            })?),
            Err(_) => None,
        };
        out.push((ddl, overrides));
    }
    Ok(out)
}

/// Load exactly one table's pinned DDL and its overrides, both required.
///
/// `plan` and everything downstream need the overrides: the caps, the cutoff and the per-column
/// freedom classes all live there, and a missing override file is a scope decision nobody made
/// rather than a set of defaults to fall back on.
pub fn load_one(
    ddl_dir: &std::path::Path,
    overrides_dir: &std::path::Path,
    table: &str,
) -> Result<(PinnedDdl, crate::models::Overrides)> {
    let ddl_path = ddl_dir.join(format!("{table}.sql"));
    let text = std::fs::read_to_string(&ddl_path).map_err(|e| {
        bad(format!("no pinned DDL for this table: {e}"))
            .with("path", ddl_path.display())
            .with(
                "reason",
                "section 4: the allowlist comes from source control",
            )
    })?;
    let ddl = parse_create_table(&text).map_err(|e| e.with("path", ddl_path.display()))?;
    if ddl.qualified() != table {
        return Err(
            bad("pinned DDL filename disagrees with the table it declares")
                .with("filename", table.escape_debug())
                .with("declares", ddl.qualified()),
        );
    }

    let over_path = overrides_dir.join(format!("{table}.toml"));
    let over_text = std::fs::read_to_string(&over_path).map_err(|e| {
        bad(format!("no pinned overrides for this table: {e}"))
            .with("path", over_path.display())
            .with(
                "reason",
                "the caps, the cutoff and the per-column freedom classes all live there",
            )
    })?;
    let overrides = toml::from_str::<crate::models::Overrides>(&over_text).map_err(|e| {
        bad(format!("could not parse overrides: {e}")).with("path", over_path.display())
    })?;
    // Parsing is not enough: a cap can be correctly spelled, correctly typed, and still disable
    // the control it is meant to bound.
    overrides
        .validate()
        .map_err(|e| e.with("path", over_path.display()))?;

    Ok((ddl, overrides))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATRIX: &str = include_str!("../../ddl/typematrix.typematrix.sql");

    fn wrap(columns: &str, tail: &str) -> String {
        format!("CREATE TABLE db.t (\n{columns}\n)\n{tail}")
    }

    fn ok(columns: &str) -> PinnedDdl {
        parse_create_table(&wrap(columns, "ENGINE = MergeTree ORDER BY (`a`)")).unwrap()
    }

    #[test]
    fn the_pinned_type_matrix_parses_end_to_end() {
        let ddl = parse_create_table(MATRIX).unwrap();
        assert_eq!(ddl.qualified(), "typematrix.typematrix");
        assert_eq!(ddl.engine, "MergeTree");
        assert_eq!(
            ddl.order_by.iter().map(Ident::as_str).collect::<Vec<_>>(),
            vec!["ts", "id"]
        );
        // Every declared type must have survived `parse_type`; the fixture exists to exercise all
        // of them, so a regression in either file shows up here.
        assert!(ddl.columns.len() > 40, "got {}", ddl.columns.len());
        assert_eq!(
            ddl.column("low_card_nullable").unwrap().declared_type,
            "LowCardinality(Nullable(String))"
        );
        assert_eq!(
            ddl.column("events").unwrap().declared_type,
            "Nested(kind UInt8, at DateTime, note String)"
        );
    }

    #[test]
    fn a_query_time_column_is_refused_and_told_why() {
        // Section 4's central refusal: these evaluate on the compromised server, so selecting one
        // asks it to run attacker-written code.
        for (modifier, decl) in [
            ("ALIAS", "`a` UInt8, `b` String ALIAS concat('x', 'y')"),
            (
                "MATERIALIZED",
                "`a` UInt8, `b` String MATERIALIZED dictGet('d', 'k', a)",
            ),
            ("EPHEMERAL", "`a` UInt8, `b` String EPHEMERAL"),
        ] {
            let err =
                parse_create_table(&wrap(decl, "ENGINE = MergeTree ORDER BY (`a`)")).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(modifier), "{msg}");
            assert!(
                msg.contains("query time") || msg.contains("not stored"),
                "the operator needs the reason, not just a parse error: {msg}"
            );
        }
    }

    #[test]
    fn a_default_codec_ttl_or_comment_on_a_column_is_refused() {
        for decl in [
            "`a` UInt8, `b` String DEFAULT 'x'",
            "`a` UInt8, `b` String CODEC(ZSTD(3))",
            "`a` UInt8, `b` DateTime TTL a + INTERVAL 1 DAY",
            "`a` UInt8, `b` String COMMENT 'notes'",
        ] {
            assert!(
                parse_create_table(&wrap(decl, "ENGINE = MergeTree ORDER BY (`a`)")).is_err(),
                "{decl} must not parse"
            );
        }
    }

    #[test]
    fn every_engine_section_4_names_is_refused() {
        for engine in [
            "Distributed",
            "Merge",
            "View",
            "MaterializedView",
            "File",
            "URL",
            "S3",
            "Executable",
            "Kafka",
            "Dictionary",
            "MySQL",
            "PostgreSQL",
            "MongoDB",
            "ODBC",
            "JDBC",
            "Log",
            "TinyLog",
            "Memory",
            "Null",
        ] {
            let sql = wrap("`a` UInt8", &format!("ENGINE = {engine} ORDER BY (`a`)"));
            let err = parse_create_table(&sql)
                .err()
                .unwrap_or_else(|| panic!("{engine} should have been refused"));
            let msg = err.to_string();
            assert!(
                msg.contains(engine),
                "the refusal must name the engine: {msg}"
            );
            assert!(
                msg.contains("approved MergeTree-family"),
                "the allowlist is the control, and the message should say so: {msg}"
            );
        }
    }

    #[test]
    fn approved_mergetree_engines_are_accepted_with_or_without_arguments() {
        for engine in [
            "MergeTree",
            "ReplacingMergeTree",
            "ReplacingMergeTree(ver)",
            "ReplicatedMergeTree('/clickhouse/tables/t', '{replica}')",
            "SummingMergeTree",
            "CollapsingMergeTree(sign)",
        ] {
            let sql = wrap("`a` UInt8", &format!("ENGINE = {engine} ORDER BY (`a`)"));
            let ddl = parse_create_table(&sql)
                .unwrap_or_else(|e| panic!("{engine} should be approved: {e}"));
            assert!(
                !ddl.engine.contains('('),
                "the engine name is recorded without its arguments, got {}",
                ddl.engine
            );
        }
    }

    #[test]
    fn an_enum_label_holding_a_comma_or_a_paren_does_not_split_the_column_list() {
        // The scanner has to respect string literals or this DDL parses as five columns, two of
        // them nonsense -- and a column list that is silently wrong is the worst outcome here.
        let ddl = ok("`a` UInt8, `s` Enum8('a,b' = 1, 'c)d' = 2, 'e''f' = 3), `z` String");
        assert_eq!(
            ddl.columns
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "s", "z"]
        );
        assert_eq!(
            ddl.column("s").unwrap().declared_type,
            "Enum8('a,b' = 1, 'c)d' = 2, 'e''f' = 3)"
        );
    }

    #[test]
    fn a_comment_is_stripped_but_a_double_dash_inside_a_string_is_not() {
        let ddl = ok("`a` UInt8, -- this is a comment, with a comma\n `s` Enum8('a--b' = 1)");
        assert_eq!(ddl.columns.len(), 2);
        assert_eq!(ddl.column("s").unwrap().declared_type, "Enum8('a--b' = 1)");
    }

    #[test]
    fn a_block_comment_is_stripped_and_an_unterminated_one_is_refused() {
        assert_eq!(ok("`a` /* inline */ UInt8").columns.len(), 1);
        assert!(
            parse_create_table(&wrap(
                "`a` UInt8 /* oops",
                "ENGINE = MergeTree ORDER BY (`a`)"
            ))
            .is_err()
        );
    }

    #[test]
    fn an_order_by_expression_is_refused_because_a_cursor_must_be_re_renderable() {
        // The cursor is re-rendered from our own parsed value. A sort key that is a function of a
        // column is not a value we hold, so pagination could not resume from it.
        let sql = wrap(
            "`a` UInt8, `ts` DateTime",
            "ENGINE = MergeTree ORDER BY (toStartOfDay(ts))",
        );
        let err = parse_create_table(&sql).unwrap_err();
        assert!(err.to_string().contains("expression"), "{err}");
    }

    #[test]
    fn an_order_by_naming_an_undeclared_column_is_refused() {
        let sql = wrap("`a` UInt8", "ENGINE = MergeTree ORDER BY (`nope`)");
        assert!(parse_create_table(&sql).is_err());
    }

    #[test]
    fn order_by_tuple_parses_to_an_empty_key() {
        // Legal DDL and an honest answer: no sort key means no cursor, which step 6 refuses to
        // paginate rather than inventing one.
        let sql = wrap("`a` UInt8", "ENGINE = MergeTree ORDER BY tuple()");
        assert!(parse_create_table(&sql).unwrap().order_by.is_empty());
    }

    #[test]
    fn a_bare_order_by_column_and_a_backticked_one_are_equivalent() {
        let bare = parse_create_table(&wrap("`a` UInt8", "ENGINE = MergeTree ORDER BY a")).unwrap();
        let quoted =
            parse_create_table(&wrap("a UInt8", "ENGINE = MergeTree ORDER BY (`a`)")).unwrap();
        assert_eq!(bare.order_by, quoted.order_by);
        assert_eq!(bare.columns, quoted.columns);
    }

    #[test]
    fn clauses_we_do_not_model_are_skipped_but_unknown_ones_are_refused() {
        let sql = wrap(
            "`a` UInt8, `ts` DateTime",
            "ENGINE = MergeTree PARTITION BY toYYYYMM(ts) ORDER BY (`ts`, `a`) \
             SAMPLE BY a SETTINGS index_granularity = 8192",
        );
        let ddl = parse_create_table(&sql).unwrap();
        assert_eq!(
            ddl.order_by.iter().map(Ident::as_str).collect::<Vec<_>>(),
            vec!["ts", "a"]
        );

        let unknown = wrap("`a` UInt8", "ENGINE = MergeTree ORDER BY (`a`) WITH FILL");
        assert!(parse_create_table(&unknown).is_err());
    }

    #[test]
    fn a_missing_engine_or_order_by_is_refused() {
        assert!(parse_create_table(&wrap("`a` UInt8", "ORDER BY (`a`)")).is_err());
        let err = parse_create_table(&wrap("`a` UInt8", "ENGINE = MergeTree")).unwrap_err();
        assert!(err.to_string().contains("ORDER BY"), "{err}");
    }

    #[test]
    fn a_duplicate_column_is_refused() {
        let sql = wrap("`a` UInt8, `a` String", "ENGINE = MergeTree ORDER BY (`a`)");
        assert!(parse_create_table(&sql).is_err());
    }

    #[test]
    fn an_unqualified_table_name_is_refused() {
        // `db.table` is not optional: the database reaches the object prefix and the staging table
        // name, and guessing it from a `USE` we never saw is not a thing this tool does.
        assert!(
            parse_create_table("CREATE TABLE t (`a` UInt8) ENGINE = MergeTree ORDER BY a").is_err()
        );
    }

    #[test]
    fn if_not_exists_is_accepted_and_changes_nothing() {
        let a = parse_create_table("CREATE TABLE db.t (`a` UInt8) ENGINE = MergeTree ORDER BY a")
            .unwrap();
        let b = parse_create_table(
            "CREATE TABLE IF NOT EXISTS db.t (`a` UInt8) ENGINE = MergeTree ORDER BY a",
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_column_name_outside_the_permitted_charset_is_a_finding_not_a_usage_error() {
        // `Ident::new` aborts rather than erroring on usage, because the same function screens
        // `system.columns` answers from the compromised server.
        let sql = wrap("`a b` UInt8", "ENGINE = MergeTree ORDER BY tuple()");
        let err = parse_create_table(&sql).unwrap_err();
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort);
    }

    #[test]
    fn an_out_of_scope_type_is_refused_by_name() {
        let sql = wrap("`a` UInt8, `g` Point", "ENGINE = MergeTree ORDER BY (`a`)");
        let err = parse_create_table(&sql).unwrap_err();
        assert!(err.to_string().contains("Geo"), "{err}");
    }
}

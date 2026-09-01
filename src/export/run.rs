//! The export loop: one page, read twice, diffed, packed.
//!
//! Section 4's fragment is three lines of shell. This is the hardened version of it, and the four
//! places it goes beyond the source are each closing something the document's own analysis leaves
//! open:
//!
//! - **The pinned throw-mode `SETTINGS`** (addition A1) ride on every query, so a config-based
//!   truncation raises `SETTING_CONSTRAINT_VIOLATION` instead of returning a shorter answer. The
//!   source's `set -Eeuo pipefail` catches a *pipeline* failure; nothing in it catches a query
//!   that succeeded with fewer rows than existed.
//! - **A total `ORDER BY`**, so the two passes are byte-identical or the batch dies. Ordering by
//!   the primary key alone is not deterministic -- it is rarely unique.
//! - **Keyset pagination**, so a ~100 GB table can be sorted at all: a page sorts inside a `LIMIT`
//!   while the whole table would spill to the attacker's disk and probably fail.
//! - **Row counts from our own stream**, reconciled against the server's two numbers.
//!
//! The completion sentinel is unchanged from the source and still load-bearing: write to
//! `.partial`, verify, then `rename(2)`. Without it *"an export that dies mid-stream still produces
//! a valid gzip with a correct trailer -- `gzip -t` passes, rows silently missing."*

use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};

use crate::abort::{PartialOutput, Result, SalvageError, abort, usage};
use crate::clickhouse::ddl::PinnedDdl;
use crate::clickhouse::settings::EXPORT_SETTINGS;
use crate::clickhouse::types::{Ident, rules_for};
use crate::clickhouse::{Query, QueryKind, QueryRunner, tsv};
use crate::export::diff::{Hasher, assert_passes_agree};
use crate::export::plan::projection;
use crate::limits::OrOverflow;
use crate::models::Overrides;
use crate::pages::{cursor_literal, group_predicate, seek_predicate};

/// Everything one page needs, assembled once per run.
#[derive(Debug)]
pub struct PageContext<'a> {
    pub ddl: &'a PinnedDdl,
    pub overrides: &'a Overrides,
    pub cursor: &'a [Ident],
    pub order_by: &'a [Ident],
    pub cutoff: &'a str,
    pub rows_per_page: u64,
    /// Output column names, in order. This is the TSV header we require back.
    pub header: Vec<String>,
    /// `(name, expression)` pairs for the SELECT list.
    pub projection: Vec<(String, String)>,
}

impl<'a> PageContext<'a> {
    pub fn new(
        ddl: &'a PinnedDdl,
        overrides: &'a Overrides,
        cursor: &'a [Ident],
        order_by: &'a [Ident],
        cutoff: &'a str,
        rows_per_page: u64,
    ) -> Result<Self> {
        let projection = projection(ddl, overrides)?;
        let header = projection.iter().map(|(n, _)| n.clone()).collect();
        if rows_per_page == 0 {
            return abort("page size is zero; a page must hold at least one row")
                .map_err(|e: SalvageError| e.with("table", ddl.qualified()));
        }
        let rows_per_page = clamp_page_rows(rows_per_page, overrides)?;
        Ok(Self {
            ddl,
            overrides,
            cursor,
            order_by,
            cutoff,
            rows_per_page,
            header,
            projection,
        })
    }

    fn select_list(&self) -> String {
        self.projection
            .iter()
            .map(|(name, expr)| format!("{expr} AS `{name}`"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn order_clause(&self) -> String {
        self.order_by
            .iter()
            .map(Ident::quoted)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Adopt a page size re-derived from our own measured output.
    pub fn resize_from(&mut self, outcome: &PageOutcome) -> Result<()> {
        self.rows_per_page = resize_from_measured(self.rows_per_page, outcome, self.overrides)?;
        Ok(())
    }

    /// The page query. Explicit columns, never `SELECT *` (section 4).
    pub fn page_sql(&self, after: Option<&[String]>) -> Result<String> {
        let mut where_clause = self.cutoff.to_owned();
        if let Some(literals) = after {
            where_clause.push_str(" AND ");
            where_clause.push_str(&seek_predicate(self.cursor, literals)?);
        }
        Ok(format!(
            "SELECT {} FROM `{}`.`{}` WHERE {} ORDER BY {} LIMIT {}",
            self.select_list(),
            self.ddl.database.as_str(),
            self.ddl.table.as_str(),
            where_clause,
            self.order_clause(),
            self.rows_per_page
        ))
    }

    /// The extension query for a page that ended mid-key-group.
    pub fn group_sql(&self, at: &[String]) -> Result<String> {
        Ok(format!(
            "SELECT {} FROM `{}`.`{}` WHERE {} AND {} ORDER BY {} LIMIT {}",
            self.select_list(),
            self.ddl.database.as_str(),
            self.ddl.table.as_str(),
            self.cutoff,
            group_predicate(self.cursor, at)?,
            self.order_clause(),
            self.overrides.limits.max_rows_per_page
        ))
    }
}

/// Hold a page size inside the pinned caps.
///
/// The seed is `page_byte_budget / bytes_per_row`, and `bytes_per_row` comes from the compromised
/// server. A source under-reporting `data_uncompressed_bytes` drives the divisor toward one and
/// the quotient toward the whole budget in rows -- and that page is then streamed twice. Clamping
/// here is what stops the server choosing how much we read in one request.
fn clamp_page_rows(rows: u64, overrides: &Overrides) -> Result<u64> {
    let cap = overrides.limits.max_rows_per_page;
    if cap == 0 {
        return usage("max_rows_per_page is zero; no page size can satisfy it")
            .map_err(|e: SalvageError| e.with("cap", cap));
    }
    Ok(rows.clamp(1, cap))
}

/// Re-derive the page size from bytes we measured ourselves.
///
/// The seed comes from the server; every page after the first does not have to. This is the
/// feedback loop the module header, `pages.rs` and `plan.rs` all describe and none implemented --
/// `rows_per_page` was computed once and read-only for the whole run, so the compromised cluster's
/// arithmetic governed every request rather than just the first.
fn resize_from_measured(current: u64, outcome: &PageOutcome, overrides: &Overrides) -> Result<u64> {
    if outcome.rows == 0 || outcome.bytes == 0 {
        return Ok(current);
    }
    let measured =
        crate::limits::div_floor(outcome.bytes, outcome.rows, "measured_bytes_per_row")?.max(1);
    clamp_page_rows(
        crate::pages::rows_per_page(overrides.page_byte_budget, measured)?,
        overrides,
    )
}

/// What one page produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageOutcome {
    pub index: u32,
    pub rows: u64,
    pub bytes: u64,
    pub tsv: PathBuf,
    pub pass1_sha256: String,
    pub pass2_sha256: String,
    /// The cursor tuple this page ended on, as text.
    pub cursor_end: Vec<String>,
    /// The same tuple rendered as SQL literals for the next seek.
    pub cursor_literals: Vec<String>,
    /// A short page terminates the run.
    pub short: bool,
}

/// Stream a query, hashing every byte, optionally writing them to `sink`.
///
/// Pass 1 passes `None` and the bytes are discarded as they are hashed; pass 2 passes the file we
/// keep. That asymmetry is the whole reason peak disk is one page rather than two.
fn stream(
    runner: &dyn QueryRunner,
    sql: &str,
    mut sink: Option<&mut std::fs::File>,
) -> Result<(String, u64)> {
    let query = Query {
        sql: sql.to_owned(),
        settings: &EXPORT_SETTINGS,
        kind: QueryKind::Page,
    };
    let mut reader = runner.stream(&query)?;
    let mut hasher = Hasher::new();
    let mut chunk = vec![0u8; 256 * 1024];

    loop {
        let n = std::io::Read::read(&mut reader, &mut chunk).map_err(|e| {
            // Only the byte cap is a finding. A wall-clock overrun on a congested link is
            // infrastructure and stays resumable; treating it as a finding killed the whole
            // table's batch and made `--resume` refuse to pick it up, for a slow network.
            if crate::clickhouse::client::is_byte_cap_overrun(&e) {
                abort::<()>("the page exceeded its byte cap")
                    .unwrap_err()
                    .with("detail", e.to_string())
                    .with(
                        "reason",
                        "the server sent more than it declared, which is the server \
                         contradicting itself",
                    )
            } else if crate::clickhouse::client::is_budget_overrun(&e) {
                crate::abort::infra::<()>("the page read exceeded its wall-clock budget")
                    .unwrap_err()
                    .with("detail", e.to_string())
            } else {
                crate::abort::infra::<()>(format!("page read failed: {e}")).unwrap_err()
            }
        })?;
        if n == 0 {
            break;
        }
        let bytes = chunk.get(..n).unwrap_or(&[]);
        hasher.update(bytes);
        if let Some(file) = sink.as_deref_mut() {
            file.write_all(bytes).map_err(|e| {
                crate::abort::infra::<()>(format!("could not write the page: {e}")).unwrap_err()
            })?;
        }
    }

    let bytes = hasher.bytes();
    Ok((hasher.finish(), bytes))
}

/// The parsed shape of a page file: how many rows, and what the last cursor tuple was.
#[derive(Debug, Clone)]
struct PageShape {
    rows: u64,
    last_cursor: Vec<String>,
    /// How many trailing rows share the last cursor tuple. If this equals the whole page, the
    /// group is wider than a page and the extension is the only way forward.
    trailing_group: u64,
}

/// Read back the page we just wrote and check its framing.
///
/// Deliberately re-reading from disk rather than remembering the bytes: the file is what gets
/// packed and shipped, so the file is what must be checked. A page validated from a buffer that
/// was never written is a page nobody validated.
fn inspect(path: &Path, ctx: &PageContext<'_>) -> Result<PageShape> {
    let file = std::fs::File::open(path).map_err(|e| {
        crate::abort::infra::<()>(format!("could not reopen the page: {e}")).unwrap_err()
    })?;
    let mut reader = std::io::BufReader::new(file);

    let mut header_line = Vec::new();
    reader.read_until(b'\n', &mut header_line).map_err(|e| {
        crate::abort::infra::<()>(format!("could not read the page header: {e}")).unwrap_err()
    })?;
    while header_line.last() == Some(&b'\n') || header_line.last() == Some(&b'\r') {
        header_line.pop();
    }

    // Section 8.1: the header row must match the expected column list exactly, in order. This is
    // also what makes a truncated stream visible immediately rather than after a hash comparison.
    let expected = ctx.header.join("\t");
    if header_line != expected.as_bytes() {
        return abort("page header does not match the expected column list").map_err(
            |e: SalvageError| {
                e.with("expected", expected)
                    .with("got", String::from_utf8_lossy(&header_line).escape_debug())
            },
        );
    }

    // Which output column holds each cursor value. Cursor columns are scalar by construction --
    // they are NOT NULL sort-key columns -- so they never flatten and match by exact name.
    let mut cursor_at = Vec::new();
    for key in ctx.cursor {
        let idx = ctx
            .header
            .iter()
            .position(|h| h == key.as_str())
            .ok_or_else(|| {
                abort::<()>("cursor column is not in the projection")
                    .unwrap_err()
                    .with("column", key.as_str())
            })?;
        cursor_at.push(idx);
    }

    let mut rows: u64 = 0;
    let mut last_cursor: Vec<String> = Vec::new();
    let mut trailing_group: u64 = 0;
    let mut line = Vec::new();

    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line).map_err(|e| {
            crate::abort::infra::<()>(format!("could not read a page row: {e}")).unwrap_err()
        })?;
        if n == 0 {
            break;
        }
        while line.last() == Some(&b'\n') {
            line.pop();
        }
        // No empty-line skip. `read_until` returns 0 at EOF, so a trailing newline never produces
        // a phantom final line -- which means a skip here could only ever swallow a *real* row.
        // For a single-column projection an empty string is a legal value and renders as an empty
        // line, so skipping it dropped the row from the count; if the page was otherwise full that
        // made a full page look short, and a short page ends the run with the rest of the table
        // unread. For any wider projection an empty line is a one-field row, which the field-count
        // check below rejects. Both outcomes are correct; neither needs a special case.
        rows = rows.saturating_add(1);
        if rows > ctx.overrides.limits.max_rows_per_page {
            return abort("page exceeds the pinned row cap")
                .map_err(|e: SalvageError| e.with("cap", ctx.overrides.limits.max_rows_per_page));
        }

        let fields = tsv::split_row(&line);
        // Section 8.1: field count per row must equal the expected count exactly.
        if fields.len() != ctx.header.len() {
            return abort("page row has the wrong field count").map_err(|e: SalvageError| {
                e.with("row", rows)
                    .with("expected", ctx.header.len())
                    .with("got", fields.len())
            });
        }

        let mut this_cursor = Vec::with_capacity(cursor_at.len());
        for (key, idx) in ctx.cursor.iter().zip(&cursor_at) {
            let raw = fields.get(*idx).copied().unwrap_or(&[]);
            let decoded = tsv::decode_field(raw)?;
            let bytes = decoded.bytes().ok_or_else(|| {
                // Belt and braces over `select_cursor`, which already refused nullable columns.
                // If this fires, the pinned DDL and the live table disagree about nullability.
                abort::<()>("cursor value is NULL")
                    .unwrap_err()
                    .with("column", key.as_str())
                    .with("row", rows)
            })?;

            // Addition A7b: a row whose key does not pass its own section 8.3 bound never becomes
            // a cursor. Validation happens *before* the value is rendered into the next query.
            let column = ctx.ddl.column(key.as_str()).ok_or_else(|| {
                abort::<()>("cursor column vanished from the pinned DDL").unwrap_err()
            })?;
            let rules = rules_for(&column.ty, ctx.overrides.limits.max_array_elements)?;
            let validator = rules
                .columns
                .first()
                .ok_or_else(|| abort::<()>("cursor column has no validator").unwrap_err())?;
            validator
                .validator
                .check(bytes)
                .map_err(|e| e.with("column", key.as_str()).with("row", rows))?;

            let text = std::str::from_utf8(bytes)
                .map_err(|_| abort::<()>("cursor value is not UTF-8").unwrap_err())?;
            this_cursor.push(text.to_owned());
        }

        if this_cursor == last_cursor {
            trailing_group = trailing_group.saturating_add(1);
        } else {
            trailing_group = 1;
            last_cursor = this_cursor;
        }
    }

    Ok(PageShape {
        rows,
        last_cursor,
        trailing_group,
    })
}

/// Export one page: two passes, diffed, left on disk as a `.tsv` in `staging`.
pub fn export_page(
    runner: &dyn QueryRunner,
    ctx: &PageContext<'_>,
    staging: &Path,
    index: u32,
    after: Option<&[String]>,
) -> Result<PageOutcome> {
    let sql = ctx.page_sql(after)?;

    // Pass 1: hashed and discarded. Nothing touches the disk.
    let (pass1, _) = stream(runner, &sql, None)?;

    // Pass 2: hashed and kept. The guard means a stream that dies here leaves no `.tsv` that a
    // later phase could mistake for a complete page.
    let final_path = staging.join(format!("page-{index:04}.tsv"));
    let mut guard = PartialOutput::new(staging.join(format!("page-{index:04}.tsv.partial")));
    let (pass2, bytes) = {
        let mut file = std::fs::File::create(guard.path()).map_err(|e| {
            crate::abort::infra::<()>(format!("could not create the page file: {e}")).unwrap_err()
        })?;
        let result = stream(runner, &sql, Some(&mut file))?;
        file.flush().map_err(|e| {
            crate::abort::infra::<()>(format!("could not flush the page: {e}")).unwrap_err()
        })?;
        result
    };

    assert_passes_agree(index, &pass1, &pass2)?;

    // Framing is checked on the `.partial`, before the rename. The rename is the completion
    // sentinel, so nothing unchecked may ever reach the final name.
    let mut shape = inspect(guard.path(), ctx)?;

    // A page longer than its own `LIMIT` is the server contradicting the query we sent. It was
    // silently tolerated: the extension gate below tested `rows == rows_per_page`, so an over-long
    // page skipped extension entirely and the cursor then advanced with strict `>` past a
    // partly-consumed key group, losing its tail with no check firing.
    if shape.rows > ctx.rows_per_page {
        return abort("the page returned more rows than its LIMIT allows").map_err(
            |e: SalvageError| {
                e.with("page", index)
                    .with("rows_per_page", ctx.rows_per_page)
                    .with("got", shape.rows)
                    .with(
                        "reason",
                        "the server ignored the LIMIT; every page is exactly rows_per_page \
                         except the last",
                    )
            },
        );
    }

    // Key-group extension. If every row in the page shares the last cursor tuple, the group is
    // wider than a page and no extension can help -- that is a pinned page size too small for the
    // data, not something to paper over.
    let mut appended = 0u64;
    if shape.rows >= ctx.rows_per_page && !shape.last_cursor.is_empty() {
        let literals = literals_for(ctx, &shape.last_cursor)?;
        if shape.trailing_group == shape.rows {
            return abort("a single key group is wider than one page").map_err(
                |e: SalvageError| {
                    e.with("page", index)
                        .with("rows_per_page", ctx.rows_per_page)
                        .with(
                            "reason",
                            "raise page_byte_budget or choose a longer cursor prefix; \
                         extending would be unbounded",
                        )
                },
            );
        }
        appended = extend_group(
            runner,
            ctx,
            guard.path(),
            &literals,
            &shape.last_cursor,
            shape.trailing_group,
        )?;
        if appended > 0 {
            shape = inspect(guard.path(), ctx)?;
        }
    }

    // The extension appends to the file, so both the streamed byte count and the two pass hashes
    // are stale once it runs. Recompute from the file itself -- that is the artifact that gets
    // packed and shipped, and a manifest whose hashes describe a prefix of what shipped is worse
    // than one with no hashes at all. The tail was independently double-read and diffed inside
    // `extend_group`, so the completeness signal still covers every byte here; both fields carry
    // the same value because after extension there is one agreed artifact, not two passes.
    let (pass1, pass2, bytes) = if appended > 0 {
        let final_bytes = std::fs::read(guard.path()).map_err(|e| {
            crate::abort::infra::<()>(format!("could not re-read the extended page: {e}"))
                .unwrap_err()
        })?;
        let digest = crate::export::diff::sha256_hex(&final_bytes);
        let len = u64::try_from(final_bytes.len()).or_overflow("page bytes")?;
        (digest.clone(), digest, len)
    } else {
        (pass1, pass2, bytes)
    };
    guard.commit_as(&final_path)?;

    let cursor_literals = if shape.last_cursor.is_empty() {
        Vec::new()
    } else {
        literals_for(ctx, &shape.last_cursor)?
    };

    Ok(PageOutcome {
        index,
        rows: shape.rows,
        bytes,
        tsv: final_path,
        pass1_sha256: pass1,
        pass2_sha256: pass2,
        cursor_end: shape.last_cursor,
        cursor_literals,
        // A short page ends the run. Any page that is neither full nor last is a finding, and the
        // three-number reconciliation is what catches a server returning an empty page early.
        short: shape.rows < ctx.rows_per_page,
    })
}

/// Fetch the whole key group at `literals` and append the rows we have not already emitted.
///
/// The total `ORDER BY` makes this deterministic: the group's first `already` rows are exactly the
/// ones at the end of the page, so everything after them is new. One extra bounded query, and only
/// when the boundary actually falls inside a group.
fn extend_group(
    runner: &dyn QueryRunner,
    ctx: &PageContext<'_>,
    page_path: &Path,
    literals: &[String],
    values: &[String],
    already: u64,
) -> Result<u64> {
    let sql = ctx.group_sql(literals)?;

    // Two passes, diffed -- the same rule the page body obeys. The extension used to read once and
    // append, so the tail of every extended page shipped with no completeness signal at all, while
    // the recorded `pass1_sha256`/`pass2_sha256` described only the prefix that had been diffed.
    let first = read_group(runner, &sql)?;
    let second = read_group(runner, &sql)?;
    if first != second {
        return abort("the key group differs between two reads").map_err(|e: SalvageError| {
            e.with("first_bytes", first.len())
                .with("second_bytes", second.len())
                .with(
                    "reason",
                    "the source is not deterministic under the pinned cutoff, or something is \
                     truncating non-deterministically",
                )
        });
    }
    let body = first;

    let mut lines = body.split(|b| *b == b'\n');
    // The header is verified, not discarded. A response missing it would silently cost the group
    // its first row; a response carrying a different one is a different result set.
    let header = lines
        .next()
        .ok_or_else(|| abort::<()>("the group extension returned no header").unwrap_err())?;
    let got: Vec<String> = tsv::split_row(header)
        .into_iter()
        .map(|f| String::from_utf8_lossy(f).into_owned())
        .collect();
    if got != ctx.header {
        return abort("the group extension header does not match the page projection").map_err(
            |e: SalvageError| {
                e.with("expected", ctx.header.join("\t"))
                    .with("got", got.join("\t"))
            },
        );
    }
    let rows: Vec<&[u8]> = lines.filter(|l| !l.is_empty()).collect();

    let skip = usize::try_from(already).unwrap_or(usize::MAX);
    if rows.len() < skip {
        return abort("the key group shrank between the page and its extension")
            .map_err(|e: SalvageError| e.with("in_page", already).with("in_group", rows.len()));
    }
    // The extension query is bounded by `max_rows_per_page`. Coming back exactly at the bound
    // means the group may have been clipped, and appending a clipped group would advance the
    // cursor past rows that were never read.
    let cap = usize::try_from(ctx.overrides.limits.max_rows_per_page).unwrap_or(usize::MAX);
    if rows.len() >= cap {
        return abort("the key group may have been truncated by its own row cap").map_err(
            |e: SalvageError| {
                e.with("cap", ctx.overrides.limits.max_rows_per_page)
                    .with("got", rows.len())
            },
        );
    }

    // Every appended row must actually belong to the group we asked for. Without this the cursor
    // is recomputed from the whole file afterwards, so a response ending in a larger key would
    // advance the cursor arbitrarily and skip everything in between with no check firing.
    let key_at = cursor_positions(ctx)?;
    for (i, row) in rows.iter().enumerate() {
        let fields = tsv::split_row(row);
        if fields.len() != ctx.header.len() {
            return abort("a group extension row has the wrong field count").map_err(
                |e: SalvageError| {
                    e.with("row", i)
                        .with("expected", ctx.header.len())
                        .with("got", fields.len())
                },
            );
        }
        for (pos, expected) in key_at.iter().zip(values) {
            let raw = fields.get(*pos).copied().unwrap_or(&[]);
            let decoded = tsv::decode_field(raw)?;
            let actual = decoded.bytes().ok_or_else(|| {
                abort::<()>("a group extension row has a NULL cursor value").unwrap_err()
            })?;
            if actual != expected.as_bytes() {
                return abort("a group extension row is not in the requested key group").map_err(
                    |e: SalvageError| {
                        e.with("row", i).with(
                            "reason",
                            "the server answered an equality predicate with rows that do not \
                             satisfy it",
                        )
                    },
                );
            }
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(page_path)
        .map_err(|e| {
            crate::abort::infra::<()>(format!("could not append the group tail: {e}")).unwrap_err()
        })?;
    let mut appended = 0u64;
    for row in rows.into_iter().skip(skip) {
        file.write_all(row).map_err(|e| {
            crate::abort::infra::<()>(format!("could not append a group row: {e}")).unwrap_err()
        })?;
        file.write_all(b"\n").map_err(|e| {
            crate::abort::infra::<()>(format!("could not append a newline: {e}")).unwrap_err()
        })?;
        appended = appended.saturating_add(1);
    }
    file.flush().map_err(|e| {
        crate::abort::infra::<()>(format!("could not flush the group tail: {e}")).unwrap_err()
    })?;
    Ok(appended)
}

/// Read one group-extension response fully into memory, under the page byte cap.
fn read_group(runner: &dyn QueryRunner, sql: &str) -> Result<Vec<u8>> {
    let query = Query {
        sql: sql.to_owned(),
        settings: &EXPORT_SETTINGS,
        kind: QueryKind::Page,
    };
    let mut body = Vec::new();
    let mut reader = runner.stream(&query)?;
    std::io::Read::read_to_end(&mut reader, &mut body).map_err(|e| {
        crate::abort::infra::<()>(format!("group extension read failed: {e}")).unwrap_err()
    })?;
    Ok(body)
}

/// Where each cursor column sits in the projection.
fn cursor_positions(ctx: &PageContext<'_>) -> Result<Vec<usize>> {
    ctx.cursor
        .iter()
        .map(|key| {
            ctx.header
                .iter()
                .position(|h| h == key.as_str())
                .ok_or_else(|| {
                    abort::<()>("a cursor column is absent from the projection")
                        .unwrap_err()
                        .with("column", key.as_str())
                })
        })
        .collect()
}

/// Render a cursor tuple as SQL literals, each screened again on the way out.
fn literals_for(ctx: &PageContext<'_>, values: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(values.len());
    for (key, value) in ctx.cursor.iter().zip(values) {
        let column = ctx
            .ddl
            .column(key.as_str())
            .ok_or_else(|| abort::<()>("cursor column vanished").unwrap_err())?;
        out.push(cursor_literal(&column.ty, value)?);
    }
    Ok(out)
}

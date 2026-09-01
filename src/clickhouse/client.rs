//! The ClickHouse HTTP client. Hand-written over `reqwest`; no ClickHouse crate is used.
//!
//! Section 13 prefers the HTTP interface: *"the native interface has carried control-flow bugs
//! (CVE-2024-6873, fixed 24.5)"* and HTTP is the smaller parser surface. Hand-rolling it keeps
//! three guarantees as properties rather than as settings to be audited on a dependency:
//! compression is never enabled, nothing deserializes on our behalf, and the pinned `SETTINGS`
//! block is rendered by us so there is no allowlist to defeat.
//!
//! # The composition rule
//!
//! [`Query::sql`] carries **neither `SETTINGS` nor `FORMAT`**. This client appends both, and
//! refuses a statement that already contains either. That makes two invariants structural instead
//! of matters of review:
//!
//! - No query leaves without the pinned throw-mode block (addition A1). Left off even once, the
//!   ordinary settings path can return a **successful partial result** -- valid gzip, correct
//!   trailer, every downstream control satisfied, rows silently missing.
//! - No query leaves without an explicit output format. Importing a headered file as plain
//!   `TabSeparated` consumes the header as data (section 9), and the mirror of that mistake on the
//!   read side is just as quiet.
//!
//! # `wait_end_of_query=1`
//!
//! Not in the source plan, and it closes a real hole in the HTTP interface. If an exception is
//! raised *after* the response has begun streaming, ClickHouse cannot retract the `200` it already
//! sent -- it appends the exception text to the body instead. A client that stops reading when it
//! has enough bytes sees a complete-looking, silently truncated result.
//!
//! Buffering server-side turns that into a proper HTTP error with
//! `X-ClickHouse-Exception-Code` set. It costs one page of memory on the compromised host, which
//! is their disk and their problem, and pages are budgeted at tens of megabytes. We still check the
//! header *and* still let the parser abort on the trailing garbage: three independent catches,
//! because this is the exact failure the plan's truncation analysis is about.
//!
//! # Trust
//!
//! Every query text is written to a local log **before it is sent**. Section 4's `system.query_log`
//! on the source is attacker-controlled and is collected as context, never as evidence; this file
//! is the record of what we asked.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::abort::{PartialOutput, Result, SalvageError, abort, infra};
use crate::clickhouse::{Query, QueryRunner};
use crate::limits::{BUDGET_ERROR_PREFIX, BoundedReader, TransferBudget};

/// Output format for a paged read. Section 9 imports with the matching
/// `input_format_with_names_use_header=1`, so the header is a checked artifact, not decoration.
const PAGE_FORMAT: &str = "TabSeparatedWithNames";

/// Output format for a single scalar. No header: one row, one field.
const SCALAR_FORMAT: &str = "TabSeparated";

/// Cap on a scalar response. A `count()` is a handful of bytes; anything larger is not a scalar.
const MAX_SCALAR_BYTES: u64 = 64 * 1024;

/// A ClickHouse HTTP endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// `http://host:8123`, from pinned configuration and never from data.
    pub base_url: String,
    pub database: String,
    pub user: String,
    pub password: Option<String>,
}

/// The real runner.
#[derive(Debug)]
pub struct HttpRunner {
    client: reqwest::blocking::Client,
    endpoint: Endpoint,
    budget: TransferBudget,
    query_log: PathBuf,
}

impl HttpRunner {
    /// `query_log`'s parent directory must exist. Construct once in `main` and pass `&dyn
    /// QueryRunner` down: `reqwest::blocking` spins its own runtime thread.
    pub fn new(
        endpoint: Endpoint,
        budget: TransferBudget,
        query_log: impl Into<PathBuf>,
    ) -> Result<Self> {
        // Every codec explicitly off. With all four features disabled reqwest never writes an
        // `Accept-Encoding` header, but Cargo feature unification lets any other dependency turn
        // `reqwest/gzip` on behind our back -- and a transparently decompressed body means the
        // bytes we hash are not the bytes the server sent.
        let client = reqwest::blocking::Client::builder()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| {
                infra::<()>(format!("could not build the HTTP client: {e}")).unwrap_err()
            })?;

        Ok(Self {
            client,
            endpoint,
            budget,
            query_log: query_log.into(),
        })
    }

    /// The full statement as it will be sent: caller's SQL, then the pinned settings, then the
    /// format.
    ///
    /// Public so `--dry-run` can print exactly what would go over the wire without a server. A dry
    /// run that skipped composition would prove nothing about the thing most worth reviewing.
    pub fn compose(query: &Query, format: &str) -> Result<String> {
        // Token-wise, not substring: a table with a column called `format_version` is ordinary,
        // and refusing to export it because its name contains a keyword would be a bug of our own.
        let upper = query.sql.to_ascii_uppercase();
        let tokens: Vec<&str> = upper
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .collect();
        // A caller splicing its own settings or format is the one way the invariants above can be
        // bypassed, so it is refused rather than merged. `Usage`, not `Abort`: this is our bug.
        for banned in ["SETTINGS", "FORMAT"] {
            if tokens.contains(&banned) {
                return Err(crate::abort::usage::<()>(
                    "query text must not carry its own SETTINGS or FORMAT",
                )
                .unwrap_err()
                .with("clause", banned)
                .with("sql", query.sql.escape_debug()));
            }
        }
        Ok(format!(
            "{}\n{}\nFORMAT {format}",
            query.sql.trim_end().trim_end_matches(';'),
            query.settings.render()
        ))
    }

    /// Append the exact statement to the local log, before it is sent.
    fn log(&self, statement: &str, kind: crate::clickhouse::QueryKind) -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.query_log)
            .map_err(|e| {
                infra::<()>(format!("could not open the query log: {e}"))
                    .unwrap_err()
                    .with("path", self.query_log.display())
            })?;
        // Failing to record a query is a hard failure, not a warning. The log is the only
        // trustworthy account of what we asked a compromised server to do.
        writeln!(file, "-- kind={kind:?}\n{statement};\n")
            .map_err(|e| infra::<()>(format!("could not write the query log: {e}")).unwrap_err())
    }

    fn url(&self) -> String {
        format!(
            "{}/?database={}&wait_end_of_query=1",
            self.endpoint.base_url.trim_end_matches('/'),
            self.endpoint.database
        )
    }

    fn send(&self, statement: String) -> Result<reqwest::blocking::Response> {
        let mut req = self
            .client
            .post(self.url())
            .header("X-ClickHouse-User", &self.endpoint.user)
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .body(statement);
        if let Some(password) = &self.endpoint.password {
            req = req.header("X-ClickHouse-Key", password);
        }

        let resp = req
            .send()
            .map_err(|e| infra::<()>(format!("query failed in transport: {e}")).unwrap_err())?;

        // A ClickHouse-level exception. This is a finding rather than an infrastructure error, and
        // the distinction gates `--resume`: a settings constraint or an unknown setting name means
        // the source refused to answer honestly, and retrying could quietly succeed a different
        // way. Addition A1's whole design is that we either win the setting or the query errors --
        // this is the branch where we lose it, and it must not be resumable.
        if let Some(code) = resp.headers().get("X-ClickHouse-Exception-Code") {
            let code = String::from_utf8_lossy(code.as_bytes()).into_owned();
            let detail = read_capped(resp, 8192);
            return abort("the source server refused the query")
                .map_err(|e: SalvageError| e.with("exception_code", code).with("detail", detail));
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail = read_capped(resp, 8192);
            return infra("query returned a non-success status")
                .map_err(|e: SalvageError| e.with("status", status).with("detail", detail));
        }

        // Belt and braces with the disabled codecs. If anything decompressed for us, the bytes we
        // hash are not the bytes the server sent, and the two-pass diff compares the wrong things.
        if let Some(enc) = resp.headers().get(reqwest::header::CONTENT_ENCODING) {
            let enc = String::from_utf8_lossy(enc.as_bytes()).into_owned();
            return abort("response carried a Content-Encoding")
                .map_err(|e: SalvageError| e.with("encoding", enc));
        }

        Ok(resp)
    }

    fn deadline(&self) -> Instant {
        Instant::now()
            .checked_add(self.budget.wall_clock)
            .unwrap_or_else(Instant::now)
    }
}

impl QueryRunner for HttpRunner {
    fn stream(&self, query: &Query) -> Result<Box<dyn std::io::Read + Send>> {
        let statement = Self::compose(query, PAGE_FORMAT)?;
        self.log(&statement, query.kind)?;
        let resp = self.send(statement)?;
        // Bounded at the seam rather than by the caller. Nothing in the HTTP stack provides a
        // total budget -- `reqwest::blocking` has no `read_timeout`, and `.timeout()` recomputes
        // per `read()` -- so an unbounded reader here would be an unbounded read from a server the
        // attacker controls.
        Ok(Box::new(BoundedReader::new(
            resp,
            self.budget,
            self.deadline(),
        )))
    }

    fn scalar(&self, query: &Query) -> Result<String> {
        let statement = Self::compose(query, SCALAR_FORMAT)?;
        self.log(&statement, query.kind)?;
        let resp = self.send(statement)?;

        let budget = TransferBudget {
            wall_clock: self.budget.wall_clock,
            max_bytes: MAX_SCALAR_BYTES,
        };
        let mut out = Vec::new();
        crate::limits::copy_bounded(resp, &mut out, budget, self.deadline())?;

        let text = String::from_utf8(out)
            .map_err(|_| abort::<()>("scalar response is not UTF-8").unwrap_err())?;
        let text = text.trim_end_matches('\n');
        // Exactly one row, exactly one field. A "scalar" that is really a result set means the
        // query was not what we thought, and guessing which value was meant is not a thing this
        // tool does.
        if text.contains('\n') || text.contains('\t') {
            return abort("scalar query returned more than one value").map_err(
                |e: SalvageError| {
                    e.with("sql", query.sql.escape_debug())
                        .with("bytes", text.len())
                },
            );
        }
        Ok(text.to_owned())
    }
}

/// Read at most `cap` bytes of an error body, best effort. Used only on paths already failing.
fn read_capped(resp: reqwest::blocking::Response, cap: u64) -> String {
    let mut out = Vec::new();
    let budget = TransferBudget {
        wall_clock: Duration::from_secs(30),
        max_bytes: cap,
    };
    let deadline = Instant::now()
        .checked_add(budget.wall_clock)
        .unwrap_or_else(Instant::now);
    let _ = crate::limits::copy_bounded(resp, &mut out, budget, deadline);
    String::from_utf8_lossy(&out).trim().to_owned()
}

/// Whether an [`std::io::Error`] from a [`BoundedReader`] is a budget overrun rather than an
/// ordinary I/O fault.
///
/// The caller needs this to choose an exit code: a hostile server that overran the cap is a
/// finding, a dropped socket is resumable infrastructure.
#[must_use]
pub fn is_budget_overrun(e: &std::io::Error) -> bool {
    e.to_string().contains(BUDGET_ERROR_PREFIX)
}

/// Write the query log's header. Called once per run so the file says what it is.
pub fn open_query_log(path: &Path) -> Result<PartialOutput> {
    let guard = PartialOutput::new(path.to_path_buf());
    std::fs::write(
        guard.path(),
        "-- Queries this run sent to the source cluster, written before each was sent.\n\
         -- Section 4: the source's own system.query_log is attacker-controlled and is context,\n\
         -- never evidence. This file is the record.\n\n",
    )
    .map_err(|e| {
        infra::<()>(format!("could not create the query log: {e}"))
            .unwrap_err()
            .with("path", path.display())
    })?;
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clickhouse::QueryKind;
    use crate::clickhouse::settings::EXPORT_SETTINGS;

    fn query(sql: &str) -> Query {
        Query {
            sql: sql.to_owned(),
            settings: &EXPORT_SETTINGS,
            kind: QueryKind::Page,
        }
    }

    #[test]
    fn every_composed_statement_carries_the_pinned_throw_mode_block() {
        let s = HttpRunner::compose(&query("SELECT `a` FROM `db`.`t`"), PAGE_FORMAT).unwrap();
        // Addition A1. Left off even once, the ordinary settings path returns a successful partial
        // result that satisfies every downstream control.
        for pinned in [
            "read_overflow_mode = 'throw'",
            "result_overflow_mode = 'throw'",
            "sort_overflow_mode = 'throw'",
            "apply_deleted_mask = 1",
            "select_sequential_consistency = 1",
            "use_query_cache = 0",
        ] {
            assert!(s.contains(pinned), "missing {pinned} in:\n{s}");
        }
        assert!(s.ends_with("FORMAT TabSeparatedWithNames"), "{s}");
    }

    #[test]
    fn a_caller_splicing_its_own_settings_or_format_is_refused() {
        // The one way the invariant above can be bypassed, so it is refused rather than merged.
        for sql in [
            "SELECT a FROM t SETTINGS max_rows_to_read = 1",
            "SELECT a FROM t FORMAT JSON",
            "SELECT a FROM t settings foo = 1",
        ] {
            let err = HttpRunner::compose(&query(sql), PAGE_FORMAT).unwrap_err();
            assert_eq!(err.exit_code(), crate::abort::ExitCode::Usage, "{sql}");
        }
    }

    #[test]
    fn a_trailing_semicolon_does_not_orphan_the_settings_clause() {
        // `SELECT a FROM t; SETTINGS ...` would send a second statement, and ClickHouse's HTTP
        // interface would reject it -- loudly, but for the wrong reason and after the log entry
        // claimed we asked something we did not.
        let s = HttpRunner::compose(&query("SELECT `a` FROM `db`.`t`;"), PAGE_FORMAT).unwrap();
        assert!(!s.contains(";"), "{s}");
        assert!(s.contains("SETTINGS"), "{s}");
    }

    #[test]
    fn a_scalar_and_a_page_get_different_formats() {
        let page = HttpRunner::compose(&query("SELECT count()"), PAGE_FORMAT).unwrap();
        let scalar = HttpRunner::compose(&query("SELECT count()"), SCALAR_FORMAT).unwrap();
        assert!(page.ends_with("FORMAT TabSeparatedWithNames"));
        assert!(scalar.ends_with("FORMAT TabSeparated"));
        // Section 9's mirror image: importing a headered file as plain TabSeparated consumes the
        // header as data. Reading one where none is expected is the same mistake reversed.
        assert_ne!(page, scalar);
    }

    #[test]
    fn the_url_pins_the_database_and_buffers_server_side() {
        let runner = HttpRunner::new(
            Endpoint {
                base_url: "http://dirty:8123/".to_owned(),
                database: "events".to_owned(),
                user: "ro".to_owned(),
                password: None,
            },
            TransferBudget {
                wall_clock: Duration::from_secs(60),
                max_bytes: 1024,
            },
            std::env::temp_dir().join("salvage-test-queries.log"),
        )
        .unwrap();
        let url = runner.url();
        assert!(url.contains("database=events"), "{url}");
        // Without this, an exception raised after streaming began is appended to a 200 body and a
        // truncated result looks complete.
        assert!(url.contains("wait_end_of_query=1"), "{url}");
        assert!(
            !url.contains("//?"),
            "the base URL's trailing slash must not double: {url}"
        );
    }

    #[test]
    fn the_query_log_records_the_statement_that_was_actually_composed() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("queries.log");
        let runner = HttpRunner::new(
            Endpoint {
                base_url: "http://dirty:8123".to_owned(),
                database: "events".to_owned(),
                user: "ro".to_owned(),
                password: Some("s3cret".to_owned()),
            },
            TransferBudget {
                wall_clock: Duration::from_secs(60),
                max_bytes: 1024,
            },
            &log,
        )
        .unwrap();

        let q = query("SELECT `a` FROM `db`.`t`");
        let statement = HttpRunner::compose(&q, PAGE_FORMAT).unwrap();
        runner.log(&statement, q.kind).unwrap();

        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("SELECT `a` FROM `db`.`t`"), "{text}");
        assert!(text.contains("kind=Page"), "{text}");
        assert!(
            text.contains("read_overflow_mode"),
            "the settings are part of the record"
        );
        // The log is a forensic artifact that may be shared; the credential must not be in it.
        assert!(
            !text.contains("s3cret"),
            "the password leaked into the query log"
        );
    }

    #[test]
    fn a_budget_overrun_is_distinguishable_from_a_dropped_socket() {
        // The distinction gates the exit code, and therefore `--resume`: an overrun is a finding
        // about a hostile peer, a dropped socket is resumable.
        let overrun = std::io::Error::other(format!("{BUDGET_ERROR_PREFIX}too many bytes"));
        let dropped = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset by peer");
        assert!(is_budget_overrun(&overrun));
        assert!(!is_budget_overrun(&dropped));
    }
}

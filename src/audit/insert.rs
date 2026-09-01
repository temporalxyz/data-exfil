//! The pre-flight insert test: load into a disposable ClickHouse and see what a real parser says.
//!
//! Section 7's purpose for it, verbatim -- and the list is the argument for having it at all:
//!
//! > catch, on our side of the boundary, what only appears when a real parser meets the data --
//! > values that satisfy a regex but that ClickHouse unescapes differently, fields under the
//! > length cap but over a block limit, header or column mismatches, settings whose behaviour
//! > differs from what the contract assumed.
//!
//! # Why this subprocesses `clickhouse-client`
//!
//! Everything else in this tool speaks HTTP, which section 13 prefers. This does not, and the
//! reason is narrow: section 9's flag set is a list of `--input_format_*` switches, and passing
//! them **verbatim** to the binary that documents them is safer than translating each into an HTTP
//! setting name and hoping the mapping is exact. A mistranslation here would silently re-enable
//! the coercion the whole quarantine design exists to prevent.
//!
//! `input_format_skip_unknown_fields` **defaults to 1**: left alone, extra columns are silently
//! discarded and schema drift passes undetected. The explicit `=0` is what enforces "zero skipped".

use std::path::Path;

use crate::abort::{Result, SalvageError, abort, infra};
use crate::clickhouse::settings::IMPORT_FLAGS;

/// How to reach the disposable database.
#[derive(Debug, Clone)]
pub struct InsertTarget {
    /// `docker`, `podman`, or `local` for a `clickhouse-client` already on PATH.
    pub runner: String,
    /// Pinned **by digest**, never by tag. Section 3: images are independently built and verified,
    /// not pulled from the compromised environment's registry -- and a tag is mutable, so a tag is
    /// not a pin. Choose from section 3's supported list (26.7, 26.6, 26.5, 26.3, 25.8); never
    /// 25.3, which is the compromised cluster's own end-of-support build.
    pub image: String,
    pub host: String,
    pub max_memory_usage: u64,
    pub max_insert_block_size: u64,
}

/// The exact argv, so `--dry-run` can print what would run where no runtime exists.
///
/// A dry run that skipped building this would prove nothing, and this is the single most
/// review-worthy command in the tool: every flag in it is load-bearing.
#[must_use]
pub fn insert_argv(target: &InsertTarget, staging_table: &str, columns: &[String]) -> Vec<String> {
    let mut argv = vec![
        "clickhouse-client".to_owned(),
        format!("--host={}", target.host),
        format!(
            "--query=INSERT INTO {staging_table} ({}) FORMAT TabSeparatedWithNames",
            columns
                .iter()
                .map(|c| format!("`{c}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ];
    // Section 9's set, verbatim and in order.
    for flag in IMPORT_FLAGS {
        argv.push((*flag).to_owned());
    }
    argv.push(format!("--max_memory_usage={}", target.max_memory_usage));
    argv.push(format!(
        "--max_insert_block_size={}",
        target.max_insert_block_size
    ));
    argv
}

/// The `CREATE TABLE` argv for the per-file staging table.
#[must_use]
pub fn create_argv(target: &InsertTarget, ddl: &str) -> Vec<String> {
    vec![
        "clickhouse-client".to_owned(),
        format!("--host={}", target.host),
        format!("--query={ddl}"),
    ]
}

/// Drop the whole per-file staging table.
///
/// Section 9: *"On any failure, drop the entire per-file staging table and abort the batch. No
/// shared partition is touched -- no partial state to reason about, no retry landing on a
/// half-load."*
#[must_use]
pub fn drop_argv(target: &InsertTarget, staging_table: &str) -> Vec<String> {
    vec![
        "clickhouse-client".to_owned(),
        format!("--host={}", target.host),
        format!("--query=DROP TABLE IF EXISTS {staging_table} SYNC"),
    ]
}

/// Run the insert test.
///
/// The only phase permitted to return `Infra` for "no container runtime": on a laptop there is no
/// ClickHouse, and a missing runtime is genuinely "we never got to look" rather than a finding.
pub fn run_insert_test(
    target: &InsertTarget,
    staging_table: &str,
    quarantine_ddl: &str,
    columns: &[String],
    tsv: &Path,
    dry_run: bool,
) -> Result<()> {
    let create = create_argv(target, quarantine_ddl);
    let insert = insert_argv(target, staging_table, columns);
    let drop = drop_argv(target, staging_table);

    if dry_run {
        tracing::info!(argv = ?create, "would create the staging table");
        tracing::info!(argv = ?insert, "would insert");
        tracing::info!(argv = ?drop, "would drop the staging table");
        return Ok(());
    }

    if which(&target.runner).is_none() {
        return infra("no container runtime for the insert test").map_err(|e: SalvageError| {
            e.with("runner", target.runner.clone()).with(
                "reason",
                "this is the one phase where a missing runtime is infrastructure and not a \
                     finding",
            )
        });
    }

    exec(&create).map_err(|e| e.with("phase", "create staging table"))?;

    let outcome = exec_with_stdin(&insert, tsv);
    if outcome.is_err() {
        // Drop first, then report. A staging table left behind after a failed load is exactly the
        // "partial state to reason about" section 9 rules out.
        let _ = exec(&drop);
        return outcome.map_err(|e| e.with("phase", "insert"));
    }

    exec(&drop).map_err(|e| e.with("phase", "drop staging table"))
}

fn which(binary: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

fn exec(argv: &[String]) -> Result<()> {
    let (head, rest) = argv
        .split_first()
        .ok_or_else(|| abort::<()>("empty argv").unwrap_err())?;
    let output = std::process::Command::new(head)
        .args(rest)
        .output()
        .map_err(|e| infra::<()>(format!("could not run {head}: {e}")).unwrap_err())?;
    check(&output, head)
}

fn exec_with_stdin(argv: &[String], stdin_path: &Path) -> Result<()> {
    use std::process::Stdio;
    let (head, rest) = argv
        .split_first()
        .ok_or_else(|| abort::<()>("empty argv").unwrap_err())?;
    let file = std::fs::File::open(stdin_path)
        .map_err(|e| infra::<()>(format!("could not open the page: {e}")).unwrap_err())?;
    let output = std::process::Command::new(head)
        .args(rest)
        .stdin(Stdio::from(file))
        .output()
        .map_err(|e| infra::<()>(format!("could not run {head}: {e}")).unwrap_err())?;
    check(&output, head)
}

fn check(output: &std::process::Output, what: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    // A non-zero exit from the insert is a finding, not infrastructure: the real parser rejected
    // data our validator accepted, which means the contract is wrong.
    let stderr = String::from_utf8_lossy(&output.stderr);
    abort("the insert test failed").map_err(|e: SalvageError| {
        e.with("command", what.to_owned())
            .with("status", output.status.code().unwrap_or(-1))
            .with("stderr", stderr.chars().take(400).collect::<String>())
    })
}

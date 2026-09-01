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

/// Everything one insert test needs.
#[derive(Debug, Clone)]
pub struct InsertPlan {
    pub staging_table: String,
    pub quarantine_ddl: String,
    pub columns: Vec<String>,
    pub tsv: std::path::PathBuf,
}

/// The seam, so the audit pipeline can be exercised without a container runtime.
///
/// There is deliberately **no "skip" implementation**. A missing runtime is `Infra` -- exit 3, "we
/// never got to look" -- and not a phase that quietly passes. Section 7 puts this test *before*
/// anything reaches the clean bucket, and with no Q3 in this topology (deviation D2) it is the only
/// point where a real ClickHouse parser meets the data before the consumer's does. A tool that
/// shrugged and promoted anyway would have removed the last real-parser check in the chain and
/// still reported success.
pub trait InsertTester {
    fn test(&self, plan: &InsertPlan) -> Result<()>;
}

/// The real one: subprocess `clickhouse-client` against a disposable instance.
#[derive(Debug, Clone)]
pub struct SubprocessTester {
    pub target: InsertTarget,
    pub dry_run: bool,
}

impl InsertTester for SubprocessTester {
    fn test(&self, plan: &InsertPlan) -> Result<()> {
        run_insert_test(
            &self.target,
            &plan.staging_table,
            &plan.quarantine_ddl,
            &plan.columns,
            &plan.tsv,
            self.dry_run,
        )
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> InsertTarget {
        InsertTarget {
            runner: "local".to_owned(),
            image: "clickhouse/clickhouse-server@sha256:deadbeef".to_owned(),
            host: "127.0.0.1".to_owned(),
            max_memory_usage: 1_073_741_824,
            max_insert_block_size: 65_536,
        }
    }

    #[test]
    fn the_argv_carries_section_9s_flag_set_verbatim() {
        let argv = insert_argv(
            &target(),
            "staging.`t__b1__0`",
            &["a".to_owned(), "b".to_owned()],
        );
        let joined = argv.join(" ");

        // Every flag, in the source's own spelling. The set is passed to the binary that documents
        // it rather than translated into HTTP settings, because a mistranslation here silently
        // re-enables the coercion the quarantine design exists to prevent.
        for flag in [
            "--input_format_with_names_use_header=1",
            "--input_format_skip_unknown_fields=0",
            "--input_format_null_as_default=0",
            "--input_format_tsv_empty_as_default=0",
            "--input_format_defaults_for_omitted_fields=0",
            "--input_format_allow_errors_num=0",
            "--input_format_allow_errors_ratio=0",
            "--input_format_parallel_parsing=0",
            "--async_insert=0",
        ] {
            assert!(joined.contains(flag), "missing {flag} in:\n{joined}");
        }
        assert!(joined.contains("--max_memory_usage=1073741824"), "{joined}");
        assert!(joined.contains("--max_insert_block_size=65536"), "{joined}");
    }

    #[test]
    fn skip_unknown_fields_is_explicitly_zero_because_its_default_is_one() {
        // Left alone it defaults to 1: extra columns are silently discarded and schema drift
        // passes undetected. The explicit =0 is what enforces "zero skipped".
        let argv = insert_argv(&target(), "staging.`t__b1__0`", &["a".to_owned()]);
        assert!(
            argv.iter()
                .any(|a| a == "--input_format_skip_unknown_fields=0")
        );
        assert!(
            !argv
                .iter()
                .any(|a| a == "--input_format_skip_unknown_fields=1")
        );
    }

    #[test]
    fn the_format_and_the_header_flag_agree() {
        // Importing a headered file as plain TabSeparated consumes the header as data. The format
        // and the flag have to be chosen together or the first row is silently lost.
        let argv = insert_argv(&target(), "staging.`t__b1__0`", &["a".to_owned()]);
        let query = argv.iter().find(|a| a.starts_with("--query=")).unwrap();
        assert!(query.contains("FORMAT TabSeparatedWithNames"), "{query}");
        assert!(
            argv.iter()
                .any(|a| a == "--input_format_with_names_use_header=1")
        );
    }

    #[test]
    fn the_column_list_is_explicit_and_quoted() {
        let argv = insert_argv(
            &target(),
            "staging.`t__b1__0`",
            &["ts".to_owned(), "events.kind".to_owned()],
        );
        let query = argv.iter().find(|a| a.starts_with("--query=")).unwrap();
        // Never `INSERT INTO t VALUES` positionally: the header check is only meaningful against a
        // named list, and flattened names carry a dot that must be quoted.
        assert!(query.contains("(`ts`, `events.kind`)"), "{query}");
    }

    #[test]
    fn the_drop_is_synchronous_so_a_retry_cannot_land_on_a_half_dropped_table() {
        let argv = drop_argv(&target(), "staging.`t__b1__0`");
        assert!(argv.iter().any(|a| a.contains("DROP TABLE IF EXISTS")));
        assert!(argv.iter().any(|a| a.contains("SYNC")), "{argv:?}");
    }

    #[test]
    fn a_dry_run_builds_every_command_and_executes_none() {
        // A dry run that skipped the code path would prove nothing, and this is the single most
        // review-worthy command in the tool.
        let dir = tempfile::tempdir().unwrap();
        let tsv = dir.path().join("page.tsv");
        std::fs::write(&tsv, b"a\n1\n").unwrap();
        let tester = SubprocessTester {
            target: target(),
            dry_run: true,
        };
        tester
            .test(&InsertPlan {
                staging_table: "staging.`t__b1__0`".to_owned(),
                quarantine_ddl: "CREATE TABLE staging.`t__b1__0` (`a` String) ENGINE = MergeTree ORDER BY tuple()".to_owned(),
                columns: vec!["a".to_owned()],
                tsv,
            })
            .unwrap();
    }

    #[test]
    fn a_missing_runtime_is_infrastructure_and_never_a_quiet_pass() {
        let dir = tempfile::tempdir().unwrap();
        let tsv = dir.path().join("page.tsv");
        std::fs::write(&tsv, b"a\n1\n").unwrap();
        let mut t = target();
        t.runner = "definitely-not-a-real-binary-9f3a".to_owned();
        let err = SubprocessTester {
            target: t,
            dry_run: false,
        }
        .test(&InsertPlan {
            staging_table: "staging.`t__b1__0`".to_owned(),
            quarantine_ddl: "CREATE TABLE x (a String) ENGINE = MergeTree ORDER BY tuple()"
                .to_owned(),
            columns: vec!["a".to_owned()],
            tsv,
        })
        .unwrap_err();

        // Exit 3, not exit 0. With no Q3 in this topology, skipping this test would remove the
        // last point at which a real parser sees the data.
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Infra);
    }
}

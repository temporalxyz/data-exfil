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

use crate::abort::{Result, SalvageError, abort, infra, usage};
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

/// ClickHouse builds section 3 lists as supported. Never 25.3 -- the compromised cluster's own
/// end-of-support build, which is what makes it the one version that must not be reused here.
const REFUSED_BUILD: &str = "25.3";

impl InsertTarget {
    /// Whether this target launches a container at all.
    #[must_use]
    pub fn containerised(&self) -> bool {
        self.runner == "docker" || self.runner == "podman"
    }

    /// Refuse an image that is not a real pin.
    ///
    /// The field carried a doc comment saying "pinned **by digest**, never by tag" directly above
    /// a `default_value` that was a tag -- and nothing read the field at all, so neither half was
    /// ever true. A tag resolves at run time and can be moved; a digest cannot.
    pub fn check_image(&self) -> Result<()> {
        if !self.containerised() {
            return Ok(());
        }
        let Some((repo, digest)) = self.image.split_once("@sha256:") else {
            return usage("the ClickHouse image must be pinned by digest, not by tag").map_err(
                |e: SalvageError| {
                    e.with("image", self.image.clone()).with(
                        "reason",
                        "section 3: images are independently built and verified; a tag is mutable \
                         and resolves at run time, so a tag is not a pin",
                    )
                },
            );
        };
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return usage("the image digest is not a sha256 hex digest")
                .map_err(|e: SalvageError| e.with("digest", digest.to_owned()));
        }
        if repo.contains(REFUSED_BUILD) || self.image.contains(REFUSED_BUILD) {
            return usage("25.3 is the compromised cluster's own end-of-support build").map_err(
                |e: SalvageError| {
                    e.with("image", self.image.clone())
                        .with("supported", "26.7, 26.6, 26.5, 26.3, 25.8")
                },
            );
        }
        Ok(())
    }

    /// The `docker`/`podman` prefix that runs one `clickhouse-client` invocation in a throwaway,
    /// network-isolated, resource-capped container.
    ///
    /// Section 7: the loader T is disposable, has no route to clean storage, runs under the OS
    /// limits of section 6, and is destroyed after the test. `--rm` is the destruction, and it
    /// fires on the error path too because the runtime owns it rather than our error handling.
    #[must_use]
    fn container_prefix(&self) -> Vec<String> {
        vec![
            self.runner.clone(),
            "run".to_owned(),
            "--rm".to_owned(),
            "-i".to_owned(),
            // No route anywhere: not to the clean bucket, not to the compromised cluster.
            "--network=none".to_owned(),
            "--read-only".to_owned(),
            "--cap-drop=ALL".to_owned(),
            "--security-opt=no-new-privileges".to_owned(),
            format!("--memory={}", self.max_memory_usage),
            "--cpus=1".to_owned(),
            "--pids-limit=256".to_owned(),
            self.image.clone(),
        ]
    }

    /// Wrap a `clickhouse-client` argv so it runs inside the disposable container.
    #[must_use]
    fn wrap(&self, argv: Vec<String>) -> Vec<String> {
        if !self.containerised() {
            return argv;
        }
        let mut out = self.container_prefix();
        out.extend(argv);
        out
    }
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
    target.wrap(argv)
}

/// The `CREATE TABLE` argv for the per-file staging table.
#[must_use]
pub fn create_argv(target: &InsertTarget, ddl: &str) -> Vec<String> {
    target.wrap(vec![
        "clickhouse-client".to_owned(),
        format!("--host={}", target.host),
        // The staging database must exist before the table. Without it the very first CREATE on a
        // fresh disposable server returns UNKNOWN_DATABASE, which `check` reports as a *finding* --
        // pointing the operator at the data when the problem is the server.
        format!("--query=CREATE DATABASE IF NOT EXISTS staging; {ddl}"),
    ])
}

/// Drop the whole per-file staging table.
///
/// Section 9: *"On any failure, drop the entire per-file staging table and abort the batch. No
/// shared partition is touched -- no partial state to reason about, no retry landing on a
/// half-load."*
#[must_use]
pub fn drop_argv(target: &InsertTarget, staging_table: &str) -> Vec<String> {
    target.wrap(vec![
        "clickhouse-client".to_owned(),
        format!("--host={}", target.host),
        format!("--query=DROP TABLE IF EXISTS {staging_table} SYNC"),
    ])
}

/// Count what actually landed. Section 9's pass criteria are not "the client exited zero".
#[must_use]
pub fn count_argv(target: &InsertTarget, staging_table: &str) -> Vec<String> {
    target.wrap(vec![
        "clickhouse-client".to_owned(),
        format!("--host={}", target.host),
        format!("--query=SELECT count() FROM {staging_table}"),
    ])
}

/// Everything one insert test needs.
#[derive(Debug, Clone)]
pub struct InsertPlan {
    pub staging_table: String,
    pub quarantine_ddl: String,
    pub columns: Vec<String>,
    pub tsv: std::path::PathBuf,
    /// How many rows the page held. Section 9 requires the loaded count to be checked against
    /// this after the insert, not merely that the client exited zero.
    pub expected_rows: u64,
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
            plan.expected_rows,
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
    expected_rows: u64,
    dry_run: bool,
) -> Result<()> {
    // Refuse a mutable image pin before anything is launched. This is checked here rather than at
    // parse time because it only applies to the containerised runners.
    target.check_image()?;

    let create = create_argv(target, quarantine_ddl);
    let insert = insert_argv(target, staging_table, columns);
    let count = count_argv(target, staging_table);
    let drop = drop_argv(target, staging_table);

    if dry_run {
        tracing::info!(argv = ?create, "would create the staging table");
        tracing::info!(argv = ?insert, "would insert");
        tracing::info!(argv = ?count, "would verify the loaded row count");
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

    // A leftover table from a crashed run would make the next CREATE fail as TABLE_ALREADY_EXISTS,
    // which `check` reports as a finding. Drop first so the only failures left are real ones.
    let _ = exec(&drop);

    if let Err(e) = exec(&create) {
        // Section 9: on **any** failure, drop the entire per-file staging table. A CREATE that
        // partially succeeded used to leave its table behind, because the drop only ran on the
        // insert path.
        drop_or_warn(&drop, staging_table);
        return Err(e.with("phase", "create staging table"));
    }

    if let Err(e) = exec_with_stdin(&insert, tsv) {
        drop_or_warn(&drop, staging_table);
        return Err(e.with("phase", "insert"));
    }

    // Section 9's pass criteria are three, and only the first was implemented: *"every file loads
    // with zero skipped, malformed or defaulted rows; **row counts match the manifest**; contract
    // assertions return zero."* Exit status alone would pass a load that silently dropped a row --
    // and since the frame counted rows *before* regeneration, nothing else in the pipeline could
    // catch it. This is the only stage where a real parser meets the data before the consumer's
    // does, so it is the only place the count can be taken.
    let loaded = match exec_capture(&count) {
        Ok(text) => text,
        Err(e) => {
            drop_or_warn(&drop, staging_table);
            return Err(e.with("phase", "count loaded rows"));
        }
    };
    let loaded: u64 = loaded.trim().parse().map_err(|_| {
        drop_or_warn(&drop, staging_table);
        abort::<()>("the loaded row count did not parse")
            .unwrap_err()
            .with("got", loaded.chars().take(80).collect::<String>())
    })?;
    if loaded != expected_rows {
        drop_or_warn(&drop, staging_table);
        return abort("the loaded row count does not match the page").map_err(|e: SalvageError| {
            e.with("expected", expected_rows)
                .with("loaded", loaded)
                .with("table", staging_table.to_owned())
        });
    }

    exec(&drop).map_err(|e| e.with("phase", "drop staging table"))
}

/// Drop the staging table, and say so loudly if the drop itself failed.
///
/// The failure was previously discarded with `let _`, so a drop that failed -- most likely when
/// the server was already unhealthy, which is exactly when the insert failed too -- left a
/// half-loaded table with no record anywhere that it had been left.
fn drop_or_warn(drop: &[String], staging_table: &str) {
    if let Err(e) = exec(drop) {
        tracing::error!(
            table = staging_table,
            error = %e,
            "the per-file staging table could not be dropped; it must be removed by hand before \
             the disposable instance is destroyed"
        );
    }
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

/// Run and return stdout. Used for the post-load count, which is a value and not just a status.
fn exec_capture(argv: &[String]) -> Result<String> {
    let (head, rest) = argv
        .split_first()
        .ok_or_else(|| abort::<()>("empty argv").unwrap_err())?;
    let output = std::process::Command::new(head)
        .args(rest)
        .output()
        .map_err(|e| infra::<()>(format!("could not run {head}: {e}")).unwrap_err())?;
    check(&output, head)?;
    String::from_utf8(output.stdout)
        .map_err(|_| abort::<()>("the query result is not UTF-8").unwrap_err())
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
                expected_rows: 1,
            })
            .unwrap();
    }

    #[test]
    fn a_containerised_run_isolates_and_destroys_the_disposable_instance() {
        // `--runner docker` used to differ from `--runner local` in exactly one way: it checked
        // that a binary named `docker` was on PATH, and then ran `clickhouse-client` from the host
        // against `--host`. No container, no `--network=none`, no caps, nothing destroyed -- and
        // the operator who passed a digest believed otherwise.
        let mut t = target();
        t.runner = "docker".to_owned();
        let argv = insert_argv(&t, "staging.`t__b1__0`", &["a".to_owned()]);

        assert_eq!(argv[0], "docker");
        assert_eq!(argv[1], "run");
        for required in [
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=256",
        ] {
            assert!(argv.iter().any(|a| a == required), "missing {required}");
        }
        assert!(
            argv.iter()
                .any(|a| a == &format!("--memory={}", t.max_memory_usage))
        );
        // The image sits immediately before the command it runs.
        let image_at = argv.iter().position(|a| a == &t.image).unwrap();
        assert_eq!(argv[image_at + 1], "clickhouse-client");

        // `local` stays a bare client, which is what makes it usable where no runtime exists.
        let bare = insert_argv(&target(), "staging.`t__b1__0`", &["a".to_owned()]);
        assert_eq!(bare[0], "clickhouse-client");
    }

    #[test]
    fn a_tag_is_refused_as_an_image_pin_and_so_is_the_compromised_build() {
        let mut t = target();
        t.runner = "docker".to_owned();

        t.image = "clickhouse/clickhouse-server:26.7".to_owned();
        let err = t
            .check_image()
            .err()
            .unwrap_or_else(|| panic!("a tag must be refused"));
        assert!(err.to_string().contains("not by tag"), "{err}");

        t.image = "clickhouse/clickhouse-server@sha256:nothex".to_owned();
        assert!(
            t.check_image().is_err(),
            "a malformed digest must be refused"
        );

        // 25.3 is the compromised cluster's own end-of-support build.
        t.image = format!(
            "clickhouse/clickhouse-server-25.3@sha256:{}",
            "a".repeat(64)
        );
        let err = t
            .check_image()
            .err()
            .unwrap_or_else(|| panic!("25.3 must be refused by name"));
        assert!(err.to_string().contains("25.3"), "{err}");

        // A real digest passes.
        t.image = format!("clickhouse/clickhouse-server@sha256:{}", "b".repeat(64));
        t.check_image().unwrap();

        // And `local` needs no image at all, so it is not held to the rule.
        let mut l = target();
        l.image = String::new();
        l.runner = "local".to_owned();
        l.check_image().unwrap();
    }

    #[test]
    fn the_loaded_row_count_is_verified_rather_than_assumed() {
        // Section 9's pass criteria are three; only "the client exited zero" was implemented. A
        // regeneration bug that dropped one row per page would ship with a manifest overstating
        // the count, and this is the only stage that could ever have noticed -- the frame counts
        // rows *before* regeneration.
        let t = target();
        let argv = count_argv(&t, "staging.`t__b1__0`");
        assert!(
            argv.iter()
                .any(|a| a.contains("SELECT count() FROM staging.`t__b1__0`")),
            "{argv:?}"
        );
    }

    #[test]
    fn the_staging_database_is_created_before_the_table() {
        // Without it the first CREATE on a fresh disposable server returns UNKNOWN_DATABASE, which
        // is reported as a *finding* -- pointing the operator at the data when the server is the
        // problem.
        let argv = create_argv(&target(), "CREATE TABLE staging.`x` (a String)");
        assert!(
            argv.iter()
                .any(|a| a.contains("CREATE DATABASE IF NOT EXISTS staging")),
            "{argv:?}"
        );
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
            expected_rows: 1,
        })
        .unwrap_err();

        // Exit 3, not exit 0. With no Q3 in this topology, skipping this test would remove the
        // last point at which a real parser sees the data.
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Infra);
    }
}

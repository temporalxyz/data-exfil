//! The fail-closed harness.
//!
//! This file stays for the life of the project. Every phase currently exits 3 ("we never got to
//! look"); as each build step lands, its assertion here flips from "not implemented" to a real
//! one. That progression is the progress metric.
//!
//! The property being defended is narrow and absolute: **no subcommand may ever exit 0 for work it
//! did not do.** A stub that succeeds is worse than no stub.

// Crate lints apply to integration tests too, and inner attributes do not inherit across files.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use assert_cmd::Command;

fn salvage() -> Command {
    Command::cargo_bin("salvage").expect("the `salvage` binary should build")
}

/// A scratch work dir, so a test that reaches store construction does not create `./work` in the
/// repo. The `TempDir` must outlive the assertion, hence returning it.
fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

#[test]
fn help_succeeds() {
    salvage().arg("--help").assert().code(0);
}

#[test]
fn every_subcommand_has_help() {
    for sub in [
        "plan",
        "export",
        "audit",
        "audit-parquet",
        "secrets",
        "teardown",
    ] {
        salvage().args([sub, "--help"]).assert().code(0);
    }
}

#[test]
fn help_carries_the_proves_and_does_not_prove_framing() {
    // Section 2 of the source plan lives in the binary, not only in a document that can go stale.
    let out = salvage().args(["export", "--help"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("PROVES:"), "{text}");
    assert!(text.contains("DOES NOT PROVE:"), "{text}");
    assert!(text.contains("ABORTS ON:"), "{text}");
}

#[test]
fn a_missing_table_is_a_usage_error() {
    salvage().arg("export").assert().code(2);
}

#[test]
fn a_missing_batch_is_a_usage_error() {
    salvage()
        .args(["export", "--table", "events.hits"])
        .assert()
        .code(2);
}

#[test]
fn a_malformed_table_ref_is_a_usage_error() {
    // Validated at the boundary: this string reaches SQL and object names.
    salvage()
        .args([
            "export",
            "--table",
            "events.hits; DROP TABLE x",
            "--batch",
            "b1",
        ])
        .assert()
        .code(2);
}

#[test]
fn a_malformed_batch_id_is_a_usage_error() {
    salvage()
        .args(["export", "--table", "events.hits", "--batch", "has space"])
        .assert()
        .code(2);
}

#[test]
fn an_unknown_audit_mode_is_a_usage_error_not_a_default() {
    // There must be no "unrecognised mode, assuming enforce" path.
    salvage()
        .args([
            "audit",
            "--table",
            "events.hits",
            "--batch",
            "b1",
            "--mode",
            "whatever",
        ])
        .assert()
        .code(2);
}

#[test]
fn audit_requires_an_explicit_mode() {
    salvage()
        .args(["audit", "--table", "events.hits", "--batch", "b1"])
        .assert()
        .code(2);
}

// -- Phases not yet built. Each of these flips as its build step lands. ------------------------

#[test]
fn plan_derives_a_reviewable_contract_without_touching_the_cluster() {
    // The acceptance criterion for the whole validation core: the exact bound for every column is
    // readable before anything touches the compromised cluster.
    let work = scratch();
    salvage()
        .args(["plan", "--table", "typematrix.typematrix", "--work"])
        .arg(work.path())
        .assert()
        .code(0);

    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(work.path().join("plan.json")).unwrap())
            .unwrap();

    assert_eq!(doc["table"], "typematrix.typematrix");
    // An unverified plan and a verified one are otherwise indistinguishable on disk.
    assert_eq!(doc["cluster_cross_checked"], false);
    assert_eq!(doc["cursor_columns"], serde_json::json!(["ts", "id"]));
    assert_eq!(doc["cutoff_predicate"], "`ts` < '2026-08-25 00:00:00'");

    // Section 8.7: removal is by column and recorded, never by editing the DDL.
    let dropped = doc["dropped_columns"].as_array().unwrap();
    assert_eq!(dropped.len(), 4);

    // Every non-dropped column carries its rules verbatim, which is the point of rules being data.
    let columns = doc["columns"].as_array().unwrap();
    assert!(columns.len() > 40);
    let body = columns.iter().find(|c| c["name"] == "body").unwrap();
    assert_eq!(body["class"], "open");
    let ident = columns.iter().find(|c| c["name"] == "ident").unwrap();
    assert_eq!(ident["class"], "closed");
}

#[test]
fn plan_refuses_a_table_with_no_pinned_ddl() {
    // Section 4: the allowlist comes from source control. A table nobody pinned has no contract,
    // and inventing one from the server is precisely what this tool must not do.
    let work = scratch();
    salvage()
        .args(["plan", "--table", "events.hits", "--work"])
        .arg(work.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("source control"));
}

#[test]
fn plan_emits_the_whole_document_under_json() {
    let work = scratch();
    let out = salvage()
        .args([
            "plan",
            "--table",
            "typematrix.typematrix",
            "--json",
            "--work",
        ])
        .arg(work.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // The Nested projections must address their own columns, not the parent.
    let events = doc["columns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "events")
        .unwrap();
    let sql: Vec<&str> = events["export_sql"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(sql[0].contains("`events.kind`"), "{sql:?}");
    assert!(sql[1].contains("`events.at`"), "{sql:?}");
    assert!(sql[2].contains("`events.note`"), "{sql:?}");
}

#[test]
fn export_refuses_without_a_cluster_rather_than_guessing_one() {
    let work = scratch();
    salvage()
        .args([
            "export",
            "--table",
            "typematrix.typematrix",
            "--batch",
            "b1",
        ])
        .args(["--bucket", "raw-bucket", "--work"])
        .arg(work.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--clickhouse-url"));
}

#[test]
fn a_missing_bucket_is_a_usage_error_not_a_default() {
    // There is no safe default destination for data pulled off a compromised cluster, so the
    // absence of `--bucket` is exit 2 rather than a guess. Exit 3 would be wrong too: that class
    // is resumable, and this is not something a retry fixes.
    // A table that *is* pinned, so the run gets far enough to reach the bucket check rather than
    // failing earlier on a missing contract.
    let work = scratch();
    for (args, expected) in [
        (
            vec![
                "export",
                "--table",
                "typematrix.typematrix",
                "--batch",
                "b1",
            ],
            // Export needs both; it names the cluster first because nothing can be exported
            // without one, bucket or no bucket.
            "--clickhouse-url",
        ),
        (
            vec![
                "audit",
                "--table",
                "typematrix.typematrix",
                "--batch",
                "b1",
                "--mode",
                "enforce",
            ],
            "--bucket",
        ),
    ] {
        salvage()
            .args(&args)
            .arg("--work")
            .arg(work.path())
            .assert()
            .code(2)
            .stderr(predicates::str::contains(expected));
    }
}

#[test]
fn audit_refuses_a_batch_whose_ledger_lists_no_pages() {
    // `PAGES.json` is the completion sentinel. A ledger with no pages is an export that never
    // finished, and the audit refuses it before pulling a single object.
    let work = scratch();
    let batch = work.path().join("b1");
    std::fs::create_dir_all(&batch).unwrap();
    std::fs::write(
        batch.join("PAGES.json"),
        serde_json::json!({
            "table": "typematrix.typematrix",
            "batch": "b1",
            "contract_version": "test",
            "git_commit": "test",
            "cutoff_predicate": "1",
            "total_rows": 0,
            "server_count": 0,
            "server_parts_rows": 0,
            "pages": []
        })
        .to_string(),
    )
    .unwrap();

    salvage()
        .args([
            "audit",
            "--table",
            "typematrix.typematrix",
            "--batch",
            "b1",
            "--mode",
            "enforce",
        ])
        .args([
            "--bucket",
            "raw-bucket",
            "--clean-bucket",
            "clean-bucket",
            "--work",
        ])
        .arg(work.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("no pages"));
}

#[test]
fn audit_without_a_clean_bucket_is_a_usage_error_not_a_shared_bucket() {
    // Section 5 puts clean in a separate account. Defaulting it to the raw bucket would produce a
    // run that passes every validation and then dies at the create-only push, having read the
    // whole batch off a compromised cluster for nothing.
    let work = tempfile::tempdir().unwrap();
    salvage()
        .args([
            "audit",
            "--table",
            "typematrix.typematrix",
            "--batch",
            "b1",
            "--mode",
            "enforce",
        ])
        .args(["--bucket", "raw-bucket", "--work"])
        .arg(work.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--clean-bucket is required"));
}

#[test]
fn secrets_writes_a_rotation_inventory_from_pinned_ddl_alone() {
    // The first subcommand off exit 3. It reads `ddl/` and `overrides/` and touches no cluster,
    // no bucket and no data, which is what lets it run first at incident time.
    let work = scratch();
    salvage()
        .arg("secrets")
        .arg("--work")
        .arg(work.path())
        .assert()
        .code(0);

    let report = work.path().join("SECRETS-ROTATION.md");
    let text = std::fs::read_to_string(&report).expect("SECRETS-ROTATION.md should exist");

    // Addition A3's scoping rule, which is the part that is easy to get wrong: the attacker had
    // root, so dropped columns are in scope too.
    assert!(text.contains("could* hold"), "{text}");
    assert!(
        text.contains("source_url"),
        "a dropped column must still be listed"
    );
    // Section A3 names Q1's own read-only user, which is in nobody's schema.
    assert!(text.contains("read-only user"), "{text}");
    assert!(text.contains("ROTATION_SIGNOFF"), "{text}");
}

#[test]
fn secrets_refuses_rather_than_reporting_nothing_when_the_ddl_dir_is_missing() {
    // An empty inventory and an unreadable one look identical downstream, and only one of them
    // means "no secrets". This is exit 2: no retry fixes a path that is not there.
    let work = scratch();
    salvage()
        .arg("secrets")
        .args(["--ddl-dir", "/nonexistent/pinned"])
        .arg("--work")
        .arg(work.path())
        .assert()
        .code(2);
}

#[test]
fn secrets_emits_machine_readable_counts_under_json() {
    let work = scratch();
    let out = salvage()
        .args(["secrets", "--json", "--work"])
        .arg(work.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    assert!(doc["summary"]["tables"].as_u64().unwrap() >= 1);
    assert!(
        doc["report"]
            .as_str()
            .unwrap()
            .ends_with("SECRETS-ROTATION.md")
    );
}

#[test]
fn teardown_refuses_before_acceptance_and_demands_a_named_owner() {
    let work = scratch();
    // Missing --disposition and --owner is a clap usage error: there is no default for either.
    salvage()
        .args([
            "teardown",
            "--table",
            "typematrix.typematrix",
            "--batch",
            "b1",
        ])
        .args(["--bucket", "raw-bucket", "--work"])
        .arg(work.path())
        .assert()
        .code(2);

    // Present but unaccepted: the source is kept until acceptance so there is a second attempt.
    salvage()
        .args([
            "teardown",
            "--table",
            "typematrix.typematrix",
            "--batch",
            "b1",
        ])
        .args(["--disposition", "wipe", "--owner", "R. Okonkwo"])
        .args(["--bucket", "raw-bucket", "--work"])
        .arg(work.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("second attempt"));
}

#[test]
fn no_subcommand_ever_exits_zero_for_work_it_did_not_do() {
    // Every phase is now built, so this no longer asserts "not implemented". It asserts the
    // property that survived all of them becoming real: given inputs it cannot satisfy, no
    // subcommand reports success. A stub that succeeded was always the one failure mode this
    // project could not tolerate; so is a finished phase that succeeds vacuously.
    let work = scratch();
    let cases: [&[&str]; 4] = [
        // No pinned DDL for this table.
        &["plan", "--table", "events.hits"],
        // No cluster.
        &[
            "export",
            "--table",
            "typematrix.typematrix",
            "--batch",
            "b1",
        ],
        // No ledger.
        &[
            "audit",
            "--table",
            "typematrix.typematrix",
            "--batch",
            "b1",
            "--mode",
            "enforce",
        ],
        // Not accepted.
        &[
            "teardown",
            "--table",
            "typematrix.typematrix",
            "--batch",
            "b1",
            "--disposition",
            "retain",
            "--owner",
            "someone",
        ],
    ];
    for args in cases {
        let out = salvage()
            .args(args)
            .args(["--bucket", "raw-bucket", "--work"])
            .arg(work.path())
            .output()
            .unwrap();
        assert_ne!(
            out.status.code(),
            Some(0),
            "{args:?} reported success without doing the work"
        );
    }
}

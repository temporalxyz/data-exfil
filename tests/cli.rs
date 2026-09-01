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
    for sub in ["plan", "export", "audit", "secrets", "teardown"] {
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
fn plan_is_not_implemented_and_says_so() {
    salvage()
        .args(["plan", "--table", "events.hits"])
        .assert()
        .code(3)
        .stderr(predicates::str::contains("not implemented"));
}

#[test]
fn export_is_not_implemented_and_says_so() {
    let work = scratch();
    salvage()
        .args(["export", "--table", "events.hits", "--batch", "b1"])
        .args(["--bucket", "raw-bucket", "--work"])
        .arg(work.path())
        .assert()
        .code(3)
        .stderr(predicates::str::contains("not implemented"));
}

#[test]
fn a_missing_bucket_is_a_usage_error_not_a_default() {
    // There is no safe default destination for data pulled off a compromised cluster, so the
    // absence of `--bucket` is exit 2 rather than a guess. Exit 3 would be wrong too: that class
    // is resumable, and this is not something a retry fixes.
    for args in [
        vec!["export", "--table", "events.hits", "--batch", "b1"],
        vec![
            "audit",
            "--table",
            "events.hits",
            "--batch",
            "b1",
            "--mode",
            "enforce",
        ],
    ] {
        salvage()
            .args(&args)
            .assert()
            .code(2)
            .stderr(predicates::str::contains("--bucket"));
    }
}

#[test]
fn audit_is_not_implemented_and_says_so() {
    let work = scratch();
    salvage()
        .args([
            "audit",
            "--table",
            "events.hits",
            "--batch",
            "b1",
            "--mode",
            "enforce",
        ])
        .args(["--bucket", "raw-bucket", "--work"])
        .arg(work.path())
        .assert()
        .code(3)
        .stderr(predicates::str::contains("not implemented"));
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
fn teardown_is_not_implemented_and_says_so() {
    salvage()
        .args(["teardown", "--table", "events.hits", "--batch", "b1"])
        .assert()
        .code(3)
        .stderr(predicates::str::contains("not implemented"));
}

#[test]
fn no_subcommand_ever_exits_zero_for_work_it_did_not_do() {
    // The invariant behind all of the above, asserted directly so it survives the individual
    // assertions being flipped one at a time.
    // `secrets` left this list at step 4: it now does its work and exits 0 for it. That is the
    // progress metric -- the list shrinks as phases become real, and never because an assertion
    // was relaxed.
    let cases: [&[&str]; 4] = [
        &["plan", "--table", "events.hits"],
        &["export", "--table", "events.hits", "--batch", "b1"],
        &[
            "audit",
            "--table",
            "events.hits",
            "--batch",
            "b1",
            "--mode",
            "enforce",
        ],
        &["teardown", "--table", "events.hits", "--batch", "b1"],
    ];
    for args in cases {
        let out = salvage().args(args).output().unwrap();
        assert_ne!(
            out.status.code(),
            Some(0),
            "{args:?} reported success without doing the work"
        );
    }
}

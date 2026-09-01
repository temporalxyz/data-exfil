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
    salvage()
        .args(["export", "--table", "events.hits", "--batch", "b1"])
        .assert()
        .code(3)
        .stderr(predicates::str::contains("not implemented"));
}

#[test]
fn audit_is_not_implemented_and_says_so() {
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
        .assert()
        .code(3)
        .stderr(predicates::str::contains("not implemented"));
}

#[test]
fn secrets_is_not_implemented_and_says_so() {
    salvage()
        .arg("secrets")
        .assert()
        .code(3)
        .stderr(predicates::str::contains("not implemented"));
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
    let cases: [&[&str]; 5] = [
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
        &["secrets"],
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

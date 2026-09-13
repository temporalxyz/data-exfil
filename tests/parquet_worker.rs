//! Exercise the actual worker executable and Linux resource boundary, not the in-process seam.
#![cfg(target_os = "linux")]

use std::sync::Arc;
use std::time::Duration;

use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use parquet::arrow::ArrowWriter;
use salvage::models::Overrides;
use salvage::parquet_audit::{atomic_json, file::Job};

fn fixture(value: &str) -> (tempfile::TempDir, Job) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("raw.parquet");
    let schema = Arc::new(Schema::new(vec![Field::new("body", DataType::Utf8, false)]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(StringArray::from(vec![value]))],
    )
    .unwrap();
    let mut writer =
        ArrowWriter::try_new(std::fs::File::create(&input).unwrap(), schema, None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    let mut overrides: Overrides =
        toml::from_str(include_str!("../overrides/typematrix.typematrix.toml")).unwrap();
    overrides.columns.clear();
    overrides.limits.wall_clock_secs = 10;
    let job = Job {
        input,
        work: dir.path().into(),
        ddl: "CREATE TABLE db.events (body String) ENGINE = MergeTree ORDER BY tuple()".into(),
        native_policy: Some(Default::default()),
        stop_path: None,
        overrides,
        source_object: "s3://raw/2026/09/01/events/part.parquet".into(),
        batch: "linux-test".into(),
        imported_at: "2026-09-13T00:00:00Z".into(),
        file_index: 0,
        survey: false,
        batch_rows: 8192,
        row_group_bytes: 64 * 1024 * 1024,
        chunk_bytes: 512 * 1024 * 1024,
        memory_bytes: 1024 * 1024 * 1024,
        output_budget: 16 * 1024 * 1024,
    };
    (dir, job)
}

fn command(job: &Job) -> assert_cmd::Command {
    let path = job.work.join("job.json");
    atomic_json(&path, job).unwrap();
    let mut command = assert_cmd::Command::cargo_bin("salvage").unwrap();
    command
        .arg("parquet-worker")
        .arg(path)
        .timeout(Duration::from_secs(15));
    command
}

#[test]
fn linux_worker_regenerates_native_parquet_under_memory_limit() {
    let (_dir, job) = fixture("safe");
    command(&job).assert().success();
    let checked: salvage::parquet_audit::file::Checked =
        serde_json::from_reader(std::fs::File::open(job.work.join("checked.json")).unwrap())
            .unwrap();
    assert_eq!(checked.rows, 1);
    assert_eq!(checked.findings, 0);
    assert_eq!(checked.outputs.len(), 1);
}

#[test]
fn linux_worker_rejects_encoded_injection_and_records_finding() {
    let (_dir, job) = fixture("%3Cscript%3E");
    command(&job).assert().code(1);
    assert!(!job.work.join("checked.json").exists());
    assert!(
        std::fs::metadata(job.work.join("findings.jsonl"))
            .unwrap()
            .len()
            > 0
    );
    assert!(job.work.join("worker-error.json").exists());
}

#[test]
fn linux_worker_cannot_report_success_when_address_space_is_exhausted() {
    let (_dir, mut job) = fixture("safe");
    job.memory_bytes = 1;
    command(&job).assert().failure();
    assert!(!job.work.join("checked.json").exists());
}

#[test]
fn linux_worker_respects_existing_worker_lock() {
    let (_dir, job) = fixture("safe");
    let lock = std::fs::File::create(job.work.join("worker.lock")).unwrap();
    lock.lock().unwrap();
    command(&job).assert().code(3);
    assert!(!job.work.join("checked.json").exists());
}

#[test]
fn linux_worker_obeys_global_stop_before_reading_data() {
    let (_dir, mut job) = fixture("safe");
    let stop = job.work.join("STOP.json");
    std::fs::write(&stop, b"stopped").unwrap();
    job.stop_path = Some(stop);
    command(&job).assert().code(1);
    assert!(!job.work.join("checked.json").exists());
    assert!(!job.work.join("part-000000.parquet").exists());
}

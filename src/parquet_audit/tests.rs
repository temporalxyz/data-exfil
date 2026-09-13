use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use arrow_array::builder::{ListBuilder, StringBuilder};
use arrow_array::*;
use arrow_schema::{DataType, Field, Schema};
use futures::future::BoxFuture;
use parquet::arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder};

use super::*;

fn overrides() -> Overrides {
    let mut o: Overrides =
        toml::from_str(include_str!("../../overrides/typematrix.typematrix.toml")).unwrap();
    o.columns.clear();
    o.limits.max_expansion_ratio = 1000;
    o
}

fn batch(fields: Vec<Field>, arrays: Vec<ArrayRef>) -> RecordBatch {
    RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays).unwrap()
}

fn text_batch(values: &[&str]) -> RecordBatch {
    batch(
        vec![Field::new("body", DataType::Utf8, false)],
        vec![Arc::new(StringArray::from(values.to_vec()))],
    )
}

fn parquet_bytes(batch: &RecordBatch) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut bytes, batch.schema(), None).unwrap();
    writer.write(batch).unwrap();
    writer.close().unwrap();
    bytes
}

fn job(dir: &Path, definition: &str, batch: &RecordBatch) -> file::Job {
    std::fs::create_dir_all(dir).unwrap();
    let input = dir.join("raw.parquet");
    std::fs::write(&input, parquet_bytes(batch)).unwrap();
    file::Job {
        input,
        work: dir.into(),
        ddl: format!("CREATE TABLE db.events ({definition}) ENGINE = MergeTree ORDER BY tuple()"),
        overrides: overrides(),
        source_object: "s3://raw/2026/09/01/events/part.parquet".into(),
        batch: "test".into(),
        imported_at: "2026-09-13T00:00:00Z".into(),
        file_index: 0,
        survey: false,
        batch_rows: 2,
        row_group_bytes: 1024 * 1024,
        chunk_bytes: 16 * 1024 * 1024,
        memory_bytes: 512 * MIB,
        output_budget: 32 * MIB,
    }
}

#[test]
fn native_values_nulls_and_provenance_round_trip_without_tsv() {
    let dir = tempfile::tempdir().unwrap();
    let source = batch(
        vec![
            Field::new("id", DataType::UInt64, false),
            Field::new("body", DataType::Utf8, true),
            Field::new("amount", DataType::Decimal128(12, 2), false),
            Field::new(
                "ts",
                DataType::Timestamp(arrow_schema::TimeUnit::Millisecond, None),
                false,
            ),
        ],
        vec![
            Arc::new(UInt64Array::from(vec![u64::MAX, 4, 5])),
            Arc::new(StringArray::from(vec![Some("hello"), None, Some("")])),
            Arc::new(
                Decimal128Array::from(vec![12345, 0, 234])
                    .with_precision_and_scale(12, 2)
                    .unwrap(),
            ),
            Arc::new(TimestampMillisecondArray::from(vec![
                1_700_000_000_123,
                1_700_000_000_000,
                1_700_000_000_999,
            ])),
        ],
    );
    let job = job(
        dir.path(),
        "id UInt64, body Nullable(String), amount Decimal(12,2), ts DateTime64(3)",
        &source,
    );
    let checked = file::check(&job).unwrap();
    assert_eq!(checked.rows, 3);
    assert_eq!(checked.findings, 0);
    assert_eq!(checked.outputs.len(), 1);
    let reader = ParquetRecordBatchReaderBuilder::try_new(
        std::fs::File::open(dir.path().join(&checked.outputs[0].name)).unwrap(),
    )
    .unwrap()
    .with_batch_size(100)
    .build()
    .unwrap();
    let output = reader.collect::<std::result::Result<Vec<_>, _>>().unwrap();
    assert_eq!(output.len(), 1);
    for i in 0..4 {
        assert_eq!(output[0].column(i).to_data(), source.column(i).to_data());
    }
    for i in 4..7 {
        assert_eq!(output[0].column(i).null_count(), 0);
    }
    assert_eq!(output[0].schema().field(4).name(), "_source_object");
    assert!(
        !std::fs::read_dir(dir.path()).unwrap().any(|e| e
            .unwrap()
            .path()
            .extension()
            .is_some_and(|e| e == "tsv"))
    );
}

#[test]
fn injection_catalogue_rejects_native_strings_and_encoded_payloads() {
    for value in [
        "<script>alert(1)</script>",
        "$(curl evil)",
        "%3Cscript%3E",
        "${jndi:ldap://evil}",
        "UNION SELECT password",
        "https://169.254.169.254/",
        "\u{202e}hidden",
        "e\u{301}",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let j = job(dir.path(), "body String", &text_batch(&["safe", value]));
        let error = file::check(&j).unwrap_err();
        assert_eq!(error.exit_code(), ExitCode::Abort, "{value}");
        let findings = std::fs::read_to_string(dir.path().join("findings.jsonl")).unwrap();
        assert!(!findings.is_empty(), "{value}");
        assert!(!dir.path().join("checked.json").exists());
    }
}

#[test]
fn nested_payloads_are_checked_as_values_not_container_punctuation() {
    for (values, should_pass) in [
        (vec!["safe", "also_safe"], true),
        (vec!["safe", "%3Cscript%3E"], false),
    ] {
        let mut builder = ListBuilder::new(StringBuilder::new());
        for value in values {
            builder.values().append_value(value);
        }
        builder.append(true);
        let array = builder.finish();
        let b = batch(
            vec![Field::new("tags", array.data_type().clone(), false)],
            vec![Arc::new(array)],
        );
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            file::check(&job(dir.path(), "tags Array(String)", &b)).is_ok(),
            should_pass
        );
    }
}

#[test]
fn hex_override_does_not_hide_native_binary_injection() {
    let dir = tempfile::tempdir().unwrap();
    let b = batch(
        vec![Field::new("body", DataType::Binary, false)],
        vec![Arc::new(BinaryArray::from(vec![b"<script>".as_slice()]))],
    );
    let mut j = job(dir.path(), "body String", &b);
    j.overrides.columns.insert(
        "body".into(),
        crate::models::ColumnOverride {
            class: crate::models::FreedomClass::Closed,
            drop: false,
            max_len: None,
            pattern: None,
            enum_ids: None,
            hex: true,
            rotation_owner: None,
        },
    );
    assert_eq!(file::check(&j).unwrap_err().exit_code(), ExitCode::Abort);
}

#[test]
fn schema_nullability_enum_and_timestamp_violations_reject() {
    let cases = vec![
        ("body UInt64", text_batch(&["12"])),
        (
            "body String",
            batch(
                vec![Field::new("other", DataType::Utf8, false)],
                vec![Arc::new(StringArray::from(vec!["safe"]))],
            ),
        ),
        (
            "body String",
            batch(
                vec![Field::new("body", DataType::Utf8, true)],
                vec![Arc::new(StringArray::from(vec![None::<&str>]))],
            ),
        ),
        (
            "body Enum8('ok'=1)",
            batch(
                vec![Field::new("body", DataType::Int8, false)],
                vec![Arc::new(Int8Array::from(vec![2]))],
            ),
        ),
        (
            "body DateTime64(3)",
            batch(
                vec![Field::new(
                    "body",
                    DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, None),
                    false,
                )],
                vec![Arc::new(TimestampMicrosecondArray::from(vec![
                    1_700_000_000_000_001,
                ]))],
            ),
        ),
    ];
    for (definition, b) in cases {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            file::check(&job(dir.path(), definition, &b))
                .unwrap_err()
                .exit_code(),
            ExitCode::Abort,
            "{definition}"
        );
    }
}

#[test]
fn survey_accumulates_findings_but_produces_no_parquet_output() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = job(
        dir.path(),
        "body String",
        &text_batch(&["<script>", "$(curl x)", "safe"]),
    );
    j.survey = true;
    let checked = file::check(&j).unwrap();
    assert_eq!(checked.rows, 3);
    assert_eq!(checked.findings, 2);
    assert!(checked.outputs.is_empty());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("findings.jsonl"))
            .unwrap()
            .lines()
            .count(),
        2
    );
}

#[test]
fn pinned_drops_remove_payload_columns_and_chunking_preserves_every_row() {
    let dir = tempfile::tempdir().unwrap();
    let b = batch(
        vec![
            Field::new("id", DataType::UInt64, false),
            Field::new("body", DataType::Utf8, false),
        ],
        vec![
            Arc::new(UInt64Array::from(vec![1, 2, 3, 4, 5])),
            Arc::new(StringArray::from(vec!["<script>"; 5])),
        ],
    );
    let mut j = job(dir.path(), "id UInt64, body String", &b);
    j.overrides.columns.insert(
        "body".into(),
        crate::models::ColumnOverride {
            class: crate::models::FreedomClass::Closed,
            drop: true,
            max_len: None,
            pattern: None,
            enum_ids: None,
            hex: false,
            rotation_owner: None,
        },
    );
    j.chunk_bytes = 1;
    let checked = file::check(&j).unwrap();
    assert_eq!(checked.outputs.len(), 3);
    assert_eq!(checked.outputs.iter().map(|o| o.rows).sum::<u64>(), 5);
    assert!(checked.schema.fields().iter().all(|f| f.name() != "body"));
}

#[test]
fn malformed_footer_and_resource_limits_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = job(dir.path(), "body String", &text_batch(&["safe"]));
    j.output_budget = 1;
    assert_eq!(file::check(&j).unwrap_err().exit_code(), ExitCode::Infra);
    std::fs::write(&j.input, b"PAR1xxxx\xff\xff\xff\xffPAR1").unwrap();
    assert_eq!(file::check(&j).unwrap_err().exit_code(), ExitCode::Abort);
}

#[test]
fn profiles_use_bounded_storage_for_high_cardinality() {
    let values: Vec<_> = (0..5000).map(|i| format!("safe{i}")).collect();
    let b = text_batch(&values.iter().map(String::as_str).collect::<Vec<_>>());
    let mut profile = profile::Profile::new(std::iter::once("body".into()));
    profile.add(&b, &[0]).unwrap();
    let p = profile.finish();
    assert_eq!(p.rows, 5000);
    assert_eq!(p.columns[0].frequent.len(), 16);
    assert!(p.columns[0].distinct_estimate > 3000);
    assert!(p.method.contains("estimate"));
}

#[test]
fn nested_total_field_bytes_and_element_caps_are_enforced() {
    for max_elements in [1, 10] {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = ListBuilder::new(StringBuilder::new());
        builder.values().append_value("safe");
        builder.values().append_value("also_safe");
        builder.append(true);
        let list = builder.finish();
        let b = batch(
            vec![Field::new("tags", list.data_type().clone(), false)],
            vec![Arc::new(list)],
        );
        let mut j = job(dir.path(), "tags Array(String)", &b);
        j.overrides.limits.max_array_elements = max_elements;
        j.overrides.limits.max_field_bytes = 10;
        assert_eq!(file::check(&j).unwrap_err().exit_code(), ExitCode::Abort);
    }
}

#[test]
fn map_and_tuple_fields_receive_the_injection_checks() {
    use arrow_array::builder::MapBuilder;
    for payload in ["safe", "%3Cscript%3E"] {
        let mut map = MapBuilder::new(None, StringBuilder::new(), StringBuilder::new());
        map.keys().append_value("key");
        map.values().append_value(payload);
        map.append(true).unwrap();
        let map = map.finish();
        let fields = vec![
            Field::new("number", DataType::UInt64, false),
            Field::new("text", DataType::Utf8, false),
        ];
        let tuple = StructArray::new(
            fields.into(),
            vec![
                Arc::new(UInt64Array::from(vec![1])),
                Arc::new(StringArray::from(vec![payload])),
            ],
            None,
        );
        for (name, definition, array) in [
            (
                "labels",
                "labels Map(String,String)",
                Arc::new(map) as ArrayRef,
            ),
            (
                "pair",
                "pair Tuple(UInt64,String)",
                Arc::new(tuple) as ArrayRef,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let b = batch(
                vec![Field::new(name, array.data_type().clone(), false)],
                vec![array],
            );
            assert_eq!(
                file::check(&job(dir.path(), definition, &b)).is_ok(),
                payload == "safe",
                "{definition}"
            );
        }
    }
}

#[test]
fn interrupted_day_with_a_durable_finding_cannot_resume_past_it() {
    let dir = tempfile::tempdir().unwrap();
    let track = Arc::new(Tracker::default());
    let raw = Arc::new(FakeStore::new(track.clone()));
    let clean = Arc::new(FakeStore::new(track.clone()));
    let days = vec![add_day(&raw, 1, &["safe"])];
    let day_dir = dir.path().join("2026-09-01");
    std::fs::create_dir_all(day_dir.join("file-000000")).unwrap();
    atomic_json(
        &day_dir.join("status.json"),
        &Status {
            state: "checking".into(),
            reason: String::new(),
        },
    )
    .unwrap();
    std::fs::write(
        day_dir.join("file-000000/findings.jsonl"),
        b"{\"reason\":\"a previously observed finding\"}\n",
    )
    .unwrap();
    let mut p = pipeline(dir.path(), track, raw, clean.clone());
    p.resume = true;
    assert_eq!(
        runtime().block_on(p.run(&days)).unwrap_err().exit_code(),
        ExitCode::Abort
    );
    assert!(clean.data.lock().unwrap().is_empty());
    assert_eq!(
        read_json::<Status>(&day_dir.join("status.json"))
            .unwrap()
            .state,
        "failed"
    );
}

#[test]
fn cancellation_preserves_the_original_resource_error() {
    struct ResourceFailure;
    impl Worker for ResourceFailure {
        fn check(&self, _job: file::Job) -> BoxFuture<'_, Result<file::Checked>> {
            Box::pin(async { infra("original worker resource failure") })
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let track = Arc::new(Tracker::default());
    let raw = Arc::new(FakeStore::new(track.clone()));
    let clean = Arc::new(FakeStore::new(track.clone()));
    let days = vec![add_day(&raw, 1, &["a", "b", "c", "d", "e", "f"])];
    let mut p = pipeline(dir.path(), track, raw, clean);
    p.worker = Arc::new(ResourceFailure);
    assert_eq!(
        runtime().block_on(p.run(&days)).unwrap_err().exit_code(),
        ExitCode::Infra
    );
    let report: BTreeMap<String, Status> = read_json(&dir.path().join("report.json")).unwrap();
    assert_eq!(
        report["2026-09-01"].reason,
        "original worker resource failure"
    );
}

#[test]
fn empty_files_and_reordered_columns_keep_pinned_output_schema() {
    let dir = tempfile::tempdir().unwrap();
    let b = batch(
        vec![
            Field::new("body", DataType::Utf8, false),
            Field::new("id", DataType::UInt64, false),
        ],
        vec![
            Arc::new(StringArray::from(Vec::<&str>::new())),
            Arc::new(UInt64Array::from(Vec::<u64>::new())),
        ],
    );
    let checked = file::check(&job(dir.path(), "id UInt64, body String", &b)).unwrap();
    assert_eq!(checked.rows, 0);
    assert_eq!(checked.outputs.len(), 1);
    assert_eq!(checked.schema.field(0).name(), "id");
}

#[test]
fn resource_configuration_is_validated_and_concurrency_is_reduced() {
    use clap::Parser;
    let cli = crate::cli::Cli::try_parse_from([
        "salvage",
        "audit-parquet",
        "--table",
        "db.events",
        "--batch",
        "b1",
        "--source",
        "s3://raw",
        "--destination",
        "s3://clean",
        "--from",
        "2026-09-01",
        "--through",
        "2026-09-03",
        "--mode",
        "survey",
        "--memory-bytes",
        "2415919104",
        "--scratch-bytes",
        "134217728",
        "--max-day-scratch-bytes",
        "67108864",
        "--check-concurrency",
        "50",
    ])
    .unwrap();
    let crate::cli::Command::AuditParquet(mut args) = cli.command else {
        unreachable!()
    };
    let tuning = Tuning::resolve(&args).unwrap();
    assert_eq!(tuning.days, 2);
    assert_eq!(tuning.checks, 1);
    args.download_concurrency = 0;
    assert_eq!(
        Tuning::resolve(&args).unwrap_err().exit_code(),
        ExitCode::Usage
    );
    args.download_concurrency = 1;
    args.scratch_bytes = 1;
    assert!(Tuning::resolve(&args).is_err());
}

#[derive(Default)]
struct Tracker {
    events: Mutex<Vec<String>>,
    downloads: AtomicUsize,
    peak_downloads: AtomicUsize,
    checks: AtomicUsize,
    peak_checks: AtomicUsize,
    uploads: AtomicUsize,
    peak_uploads: AtomicUsize,
}
fn enter(current: &AtomicUsize, peak: &AtomicUsize) {
    let n = current.fetch_add(1, Ordering::SeqCst) + 1;
    peak.fetch_max(n, Ordering::SeqCst);
}

struct FakeStore {
    data: Mutex<BTreeMap<String, Vec<u8>>>,
    track: Arc<Tracker>,
    fail_upload: AtomicUsize,
}
impl FakeStore {
    fn new(track: Arc<Tracker>) -> Self {
        Self {
            data: Mutex::new(BTreeMap::new()),
            track,
            fail_upload: AtomicUsize::new(0),
        }
    }
}
impl Store for FakeStore {
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<Source>>> {
        Box::pin(async move {
            Ok(self
                .data
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, bytes)| Source {
                    key: key.clone(),
                    size: bytes.len() as u64,
                    version: Some("1".into()),
                    etag: crate::export::diff::sha256_hex(bytes),
                })
                .collect())
        })
    }
    fn download<'a>(&'a self, source: &'a Source, path: &'a Path) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            enter(&self.track.downloads, &self.track.peak_downloads);
            self.track
                .events
                .lock()
                .unwrap()
                .push(format!("download:{}", source.key));
            tokio::time::sleep(Duration::from_millis(15)).await;
            let bytes = self.data.lock().unwrap().get(&source.key).unwrap().clone();
            self.track.downloads.fetch_sub(1, Ordering::SeqCst);
            if crate::export::diff::sha256_hex(&bytes) != source.etag {
                return abort("source changed");
            }
            std::fs::write(path, &bytes).map_err(infrastructure)?;
            Ok(crate::export::diff::sha256_hex(&bytes))
        })
    }
    fn upload<'a>(
        &'a self,
        key: &'a str,
        path: &'a Path,
        sha: &'a str,
        _: &'a Path,
    ) -> BoxFuture<'a, Result<Receipt>> {
        Box::pin(async move {
            enter(&self.track.uploads, &self.track.peak_uploads);
            self.track
                .events
                .lock()
                .unwrap()
                .push(format!("upload:{key}"));
            tokio::time::sleep(Duration::from_millis(25)).await;
            self.track.uploads.fetch_sub(1, Ordering::SeqCst);
            if self.fail_upload.swap(0, Ordering::SeqCst) > 0 {
                return infra("injected upload failure");
            }
            let bytes = std::fs::read(path).map_err(infrastructure)?;
            assert_eq!(crate::export::diff::sha256_hex(&bytes), sha);
            let mut data = self.data.lock().unwrap();
            if let Some(existing) = data.get(key) {
                if existing != &bytes {
                    return abort("existing output conflict");
                }
            } else {
                data.insert(key.into(), bytes);
            }
            Ok(Receipt {
                version: Some("1".into()),
                etag: sha.into(),
            })
        })
    }
}

struct TestWorker(Arc<Tracker>);
impl Worker for TestWorker {
    fn check(&self, job: file::Job) -> BoxFuture<'_, Result<file::Checked>> {
        Box::pin(async move {
            enter(&self.0.checks, &self.0.peak_checks);
            self.0
                .events
                .lock()
                .unwrap()
                .push(format!("check:{}", job.source_object));
            tokio::time::sleep(Duration::from_millis(20)).await;
            let source = job.source_object.clone();
            let result = tokio::task::spawn_blocking(move || file::check(&job))
                .await
                .unwrap();
            self.0.checks.fetch_sub(1, Ordering::SeqCst);
            self.0
                .events
                .lock()
                .unwrap()
                .push(format!("checked:{source}"));
            result
        })
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn pipeline(
    dir: &Path,
    track: Arc<Tracker>,
    raw: Arc<FakeStore>,
    clean: Arc<FakeStore>,
) -> Pipeline {
    let identity = Identity {
        format: FORMAT.into(),
        table: "db.events".into(),
        batch: "b1".into(),
        source: "s3://raw".into(),
        destination: "s3://clean".into(),
        from: "2026-09-01".into(),
        through: "2026-09-03".into(),
        contract_sha256: "contract".into(),
        survey: false,
        dry_run: false,
        retain_days: 0,
        batch_rows: 2,
        row_group_bytes: MIB,
        chunk_bytes: 16 * MIB,
    };
    let tuning = Tuning {
        days: 2,
        downloads: 2,
        checks: 2,
        uploads: 2,
        memory_bytes: 2 * 1024 * MIB,
        worker_memory_bytes: 512 * MIB,
        scratch_bytes: 128 * MIB,
        day_scratch_bytes: 64 * MIB,
        batch_rows: 2,
        row_group_bytes: MIB,
        chunk_bytes: 16 * MIB,
    };
    Pipeline::new(
        identity,
        dir.into(),
        Location::parse("s3://clean").unwrap(),
        "CREATE TABLE db.events (body String) ENGINE = MergeTree ORDER BY tuple()".into(),
        overrides(),
        tuning,
        "2026-09-13T00:00:00Z".into(),
        false,
        raw,
        clean,
        Arc::new(TestWorker(track)),
    )
}

fn add_day(raw: &FakeStore, day: usize, values: &[&str]) -> Day {
    let prefix = format!("2026/09/{day:02}/events");
    let mut sources = Vec::new();
    for (i, value) in values.iter().enumerate() {
        let key = format!("{prefix}/part-{i}.parquet");
        let bytes = parquet_bytes(&text_batch(&[value]));
        sources.push(Source {
            key: key.clone(),
            size: bytes.len() as u64,
            version: Some("1".into()),
            etag: crate::export::diff::sha256_hex(&bytes),
        });
        raw.data.lock().unwrap().insert(key, bytes);
    }
    Day {
        date: format!("2026-09-{day:02}"),
        prefix,
        sources,
    }
}

#[test]
fn day_barrier_parallel_pools_and_manifest_last() {
    let dir = tempfile::tempdir().unwrap();
    let track = Arc::new(Tracker::default());
    let raw = Arc::new(FakeStore::new(track.clone()));
    let clean = Arc::new(FakeStore::new(track.clone()));
    let days = vec![
        add_day(&raw, 1, &["a", "b"]),
        add_day(&raw, 2, &["c", "d"]),
        add_day(&raw, 3, &["e", "f"]),
    ];
    let p = pipeline(dir.path(), track.clone(), raw, clean.clone());
    runtime().block_on(p.run(&days)).unwrap();
    assert_eq!(track.peak_downloads.load(Ordering::SeqCst), 2);
    assert_eq!(track.peak_checks.load(Ordering::SeqCst), 2);
    assert!(track.peak_uploads.load(Ordering::SeqCst) <= 2);
    let events = track.events.lock().unwrap();
    for day in &days {
        let last_check = events
            .iter()
            .rposition(|e| e.starts_with("checked:") && e.contains(&day.prefix))
            .unwrap();
        let first_upload = events
            .iter()
            .position(|e| e.starts_with("upload:") && e.contains(&day.prefix))
            .unwrap();
        assert!(last_check < first_upload, "{events:?}");
        let last_upload = events
            .iter()
            .rfind(|e| e.starts_with("upload:") && e.contains(&day.prefix))
            .unwrap();
        assert!(last_upload.ends_with("MANIFEST.json"));
        let manifest: Manifest = serde_json::from_slice(
            clean
                .data
                .lock()
                .unwrap()
                .get(&format!("b1/{}/MANIFEST.json", day.prefix))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.rows, 2);
        assert_eq!(manifest.objects.len(), 2);
        assert!(!manifest.clickhouse_insert_tested);
    }
}

#[test]
fn one_injection_rejects_whole_day_but_other_days_finish() {
    let dir = tempfile::tempdir().unwrap();
    let track = Arc::new(Tracker::default());
    let raw = Arc::new(FakeStore::new(track.clone()));
    let clean = Arc::new(FakeStore::new(track.clone()));
    let days = vec![
        add_day(&raw, 1, &["safe", "<script>"]),
        add_day(&raw, 2, &["safe"]),
    ];
    let mut p = pipeline(dir.path(), track, raw, clean.clone());
    assert_eq!(
        runtime().block_on(p.run(&days)).unwrap_err().exit_code(),
        ExitCode::Abort
    );
    assert!(
        clean
            .data
            .lock()
            .unwrap()
            .keys()
            .all(|k| !k.contains("2026/09/01/"))
    );
    assert!(
        clean
            .data
            .lock()
            .unwrap()
            .keys()
            .any(|k| k.ends_with("2026/09/02/events/MANIFEST.json"))
    );
    p.resume = true;
    assert_eq!(
        runtime()
            .block_on(p.run(&days[..1]))
            .unwrap_err()
            .exit_code(),
        ExitCode::Abort
    );
}

#[test]
fn interrupted_upload_has_no_manifest_and_resumes_deterministically() {
    let dir = tempfile::tempdir().unwrap();
    let track = Arc::new(Tracker::default());
    let raw = Arc::new(FakeStore::new(track.clone()));
    let clean = Arc::new(FakeStore::new(track.clone()));
    let days = vec![add_day(&raw, 1, &["safe"])];
    clean.fail_upload.store(1, Ordering::SeqCst);
    let mut p = pipeline(dir.path(), track, raw, clean.clone());
    assert_eq!(
        runtime().block_on(p.run(&days)).unwrap_err().exit_code(),
        ExitCode::Infra
    );
    assert!(
        clean
            .data
            .lock()
            .unwrap()
            .keys()
            .all(|k| !k.ends_with("MANIFEST.json"))
    );
    p.resume = true;
    runtime().block_on(p.run(&days)).unwrap();
    runtime().block_on(p.run(&days)).unwrap();
    assert!(
        clean
            .data
            .lock()
            .unwrap()
            .keys()
            .any(|k| k.ends_with("MANIFEST.json"))
    );
}

#[test]
fn changed_source_and_schema_drift_prevent_publication() {
    let dir = tempfile::tempdir().unwrap();
    let track = Arc::new(Tracker::default());
    let raw = Arc::new(FakeStore::new(track.clone()));
    let clean = Arc::new(FakeStore::new(track.clone()));
    let day = add_day(&raw, 1, &["safe"]);
    raw.data.lock().unwrap().insert(
        day.sources[0].key.clone(),
        parquet_bytes(&text_batch(&["changed"])),
    );
    let p = pipeline(dir.path(), track, raw, clean.clone());
    assert_eq!(
        runtime().block_on(p.run(&[day])).unwrap_err().exit_code(),
        ExitCode::Abort
    );
    assert!(clean.data.lock().unwrap().is_empty());
}

#[test]
fn dates_are_inclusive_and_layout_is_explicit() {
    assert_eq!(dates("2024-02-28", "2024-03-01").unwrap().len(), 3);
    assert!(dates("2026-02-29", "2026-03-01").is_err());
    assert!(dates("2026-09-03", "2026-09-01").is_err());
    assert_eq!(
        Location::parse("s3://raw/prefix/")
            .unwrap()
            .key("2026/09/01/events/"),
        "prefix/2026/09/01/events/"
    );
    assert!(Location::parse("https://raw/path").is_err());
}

/// Run on the intended Linux server with `cargo test parquet_throughput --release -- --ignored --nocapture`.
#[test]
#[ignore = "throughput benchmark; run explicitly on the target server"]
fn parquet_throughput_serial_vs_parallel() {
    let rt = runtime();
    for concurrency in [1, 2, 4] {
        let dir = tempfile::tempdir().unwrap();
        let track = Arc::new(Tracker::default());
        let raw = Arc::new(FakeStore::new(track.clone()));
        let clean = Arc::new(FakeStore::new(track.clone()));
        let values: Vec<_> = (0..100_000).map(|i| format!("message{i}")).collect();
        let bytes = parquet_bytes(&text_batch(
            &values.iter().map(String::as_str).collect::<Vec<_>>(),
        ));
        let mut days = Vec::new();
        for d in 1..=8 {
            let mut day = add_day(&raw, d, &["placeholder"]);
            raw.data
                .lock()
                .unwrap()
                .insert(day.sources[0].key.clone(), bytes.clone());
            day.sources[0].size = bytes.len() as u64;
            day.sources[0].etag = crate::export::diff::sha256_hex(&bytes);
            days.push(day);
        }
        let mut p = pipeline(dir.path(), track, raw, clean);
        p.tuning.days = concurrency;
        p.tuning.checks = concurrency;
        p.checks = Semaphore::new(concurrency);
        p.tuning.batch_rows = 8192;
        let start = Instant::now();
        rt.block_on(p.run(&days)).unwrap();
        eprintln!(
            "checks={concurrency}, rows=800000, seconds={:.3}, rows/sec={:.0}",
            start.elapsed().as_secs_f64(),
            800_000.0 / start.elapsed().as_secs_f64()
        );
    }
}

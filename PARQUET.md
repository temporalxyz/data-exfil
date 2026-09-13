# Auditing S3 Parquet for ClickHouse

`salvage audit-parquet` processes one table per invocation, with several days in flight.
Inputs live under `s3://RAW/PREFIX/YYYY/MM/DD/table/*.parquet`. The terminal directory is the
unqualified table name; `--table db.table` identifies its pinned DDL and overrides.
Outputs live under `s3://CLEAN/PREFIX/BATCH/YYYY/MM/DD/table/` in a **different bucket**.

## Checks and output contract

Every retained value goes through the existing column bounds, anchored patterns, freedom-class
and injection/payload catalogue checks. Encoded payloads and Unicode normalization are checked by
the same scanner used by the TSV audit. Arrays, tuples, maps and Nested values are checked
recursively; generated container punctuation is not scanned as if it were a field value. Blob
bytes are scanned even when the pinned validator uses a hex representation. One finding rejects
the entire day. No row is silently repaired, defaulted, dropped or deduplicated.

Parquet schemas must match pinned ClickHouse DDL, including excluded columns. Columns marked
`drop = true` are omitted from decoding and output after schema validation. All other columns
retain their native values/types and nulls; the audit adds `_source_object`, `_batch` and
`_imported_at` as String columns. Source key-value metadata is discarded. Output is newly encoded
Parquet with Zstandard level 1, not a copy of the original bytes. No TSV files are produced.

Supported mappings include signed/unsigned integers through 64 bits, Float32/64, Bool,
Decimal128/256 with matching precision/scale, strings/binary, FixedString, Date/Date32,
UTC or timezone-free timestamps, UUID, IPv4/IPv6, enums, lists, structs and maps.
Native `Nested` uses a list of structs. Integer128/256 encodings and flattened Nested layouts
are refused rather than guessed; add an explicitly tested mapping for those inputs before a run.
Timestamp values must fit the pinned precision exactly. An unsupported mapping is a finding,
not permission to coerce the data. Parquet storage types such as UTF-8 offset width are determined
by the Parquet reader; native values and logical types are preserved.

**No real ClickHouse load test runs.** The manifest records `clickhouse_insert_tested: false` and
`consumer_must_revalidate: true`. This audit detects structural violations and suspicious field
payloads; it cannot establish factual correctness or recover rows missing from the source export.
The old export's double-read and server row reconciliation claims do not apply to existing files.

## Run

Build on Linux with the pinned Rust toolchain and lockfile:

```sh
SALVAGE_GIT_COMMIT=$(git rev-parse HEAD) cargo build --release --locked
```

Fill in `ddl/db.table.sql` and `overrides/db.table.toml` first. Input object limits use the existing
`max_compressed_bytes`, `max_uncompressed_bytes`, `max_rows_per_page`, field, nesting, expansion,
and time limits. Set these for actual **Parquet files**, not for an entire day.

This example reserves 16 GiB for the pipeline, 512 GiB of scratch, and at most 128 GiB per day:

```sh
./target/release/salvage audit-parquet \
  --table db.table --batch survey-001 --mode survey \
  --source s3://raw-bucket/export-prefix \
  --destination s3://clean-bucket/audited \
  --from 2026-08-01 --through 2026-08-31 \
  --memory-bytes 17179869184 \
  --scratch-bytes 549755813888 \
  --max-day-scratch-bytes 137438953472 \
  --work /scratch/salvage -v
```

Survey records exact finding totals and bounded hex diagnostic samples but uploads nothing.
Read the per-day `SHAPE-REVIEW.json`, `PAYLOAD-INVENTORY.json`, and per-file `findings.jsonl`.
Samples are limited to 1 MiB per file; aggregate counts still include all findings. Structural
damage that prevents further decoding stops that day. Shape statistics use bounded KMV-256
distinct/duplicate estimates and SpaceSaving-16 frequent-value estimates, explicitly labeled;
row counts, null counts and validation remain exact.

After scope review and rotation, run with a **new batch id**, `--mode enforce`,
`--shape-review-signoff` and `--rotation-signoff`. `--dry-run` performs the local audit and
regeneration without writing to clean S3. It still reads source S3.

The AWS SDK uses its credential/region provider chain, including instance roles.
`--source-profile` and `--destination-profile` select separate configured profiles. Source access
needs listing and pinned reads; clean access needs HEAD/GET for collision verification, create
writes and multipart operations (including ListParts and AbortMultipartUpload). No credentials
are passed to the validation worker as arguments. `--retain-days N` applies S3 Object Lock
**GOVERNANCE**, requiring a bucket configured for Object Lock and the corresponding permissions.
Zero means no retention. This command does not provision buckets or IAM.

## Throughput and resource controls

| Flag | Default | Meaning |
| --- | --- | --- |
| `--day-concurrency` | 4 | Active day reservations |
| `--download-concurrency` | 8 | Global concurrent source downloads; also inventory HEAD concurrency |
| `--check-concurrency` | available cores | Global validation worker processes |
| `--upload-concurrency` | 4 | Global uploads, including reports and manifests; multipart requests also bounded |
| `--worker-memory-bytes` | 1 GiB | Per-worker Linux address-space ceiling |
| `--batch-rows` | 8192 | Rows per decoded batch |
| `--row-group-bytes` | 64 MiB | Approximate uncompressed output row-group target |
| `--output-chunk-bytes` | 512 MiB | Approximate decoded output chunk target |

Concurrency is reduced to fit configured memory and scratch reservations; the resolved counts
are printed before processing. Every active day reserves its full scratch allowance. Raw files
and generated outputs share it; output allowances are distributed across files in proportion to
compressed input size, with a separate diagnostic allowance. A skewed file can exhaust its share;
increase the day budget before retrying. Quotas apply during writes, including file footers.
Ensure the filesystem actually has the declared free space, and leave room for retained reports
from previous runs. Failed/interrupted days release data scratch and retain diagnostics/checkpoints.

Validation runs in isolated Linux processes with address-space and CPU ceilings. Oversized
row groups or batches fail with a resource error rather than disabling bounds. Non-Linux hosts
can run the offline tests but cannot run production validation workers. The parent keeps a
separate controller/transfer reservation; `--memory-bytes` is a scheduling budget, not a host-wide
cgroup limit. Use a service/container memory limit as well if the server requires a total RSS cap.

Each day downloads and checks multiple files through shared pools. **Nothing from a day uploads
until every file in that day passes**. Its uploads overlap downloads/checks for other days. A
manifest is uploaded only after all data and supporting artifacts are complete. Other days
continue if one fails; the command returns nonzero if any selected day fails or is absent.

With `-v`, logs report effective concurrency, transfer/check timings, queue waits, bytes, rows,
and day throughput. Start with defaults, then compare the same representative days at increasing
concurrency; stop increasing workers once CPU, network or scratch I/O saturates. There is no
fixed throughput guarantee without measuring the server and representative data.

## Resume and consumption

The initial inventory pins each object by version ID when available, otherwise ETag. It is
persisted before processing and reused on resume. Source days must already be closed: additions
after inventory are intentionally outside the run. Missing dates are reported as errors.
Only safe ASCII object names are accepted for provenance; source names never become local paths.

Use the same command and `--resume` after an infrastructure interruption. Source/destination,
table, dates, schema/override fingerprint, mode, batch, and output settings must match. Resource
budgets may be increased. Regenerated bytes are hashed before upload, existing clean objects are
rehash-verified before reuse, and multipart part checkpoints avoid repeating completed transfers.
Scratch reclaimed after an interruption is regenerated from the pinned raw inventory. A recorded
finding makes that day non-resumable; fix the reviewed scope and use a new batch id.

Consumers must read **only files listed in a completed day `MANIFEST.json`**, pin the listed
version/ETag, verify SHA-256, and independently validate. Never load an S3 wildcard: an interrupted
upload can leave objects without a manifest. Preserve provenance through subsequent ClickHouse
loading/promotion. This is a separate native-Parquet contract; the TSV quarantine DDL is not its
import schema. Use the manifest schema and pinned ClickHouse DDL, and validate conversion before
loading production. No importer or production promotion is performed here.

## Tests and performance rehearsal

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
cargo test --release --locked parquet_throughput -- --ignored --nocapture
```

The regular tests use generated Parquet fixtures, instrumented local stores, and AWS SDK HTTP
replay responses: no AWS account, network, or ClickHouse is needed. The explicit throughput
rehearsal compares serial and parallel validation on synthetic data; measure real S3 and the
production worker process on the target Linux server before selecting final concurrency.

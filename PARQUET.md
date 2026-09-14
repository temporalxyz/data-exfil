# Auditing S3 Parquet for ClickHouse

`salvage audit-parquet` processes a table or discovers a whole database, with several table/day
partitions in flight under shared resource limits.

## Whole database

For the source layout `analytics/table/YYYY/MM/DD/*.parquet`, use `--database analytics`
and point `--source` at the database prefix. Tables and existing dates are discovered from S3;
gaps in dates are allowed. Optional `--from` / `--through` restrict the inclusive date range.
For publication, the destination is the clean bucket/root, **without** appending `analytics`
yourself. Start with this verification run, which does not need a destination:

```sh
./target/release/salvage audit-parquet \
  --database analytics --verify \
  --source s3://br-ch-exfil/analytics/ --source-profile source \
  --batch analytics-verify-001 \
  --day-concurrency 16 --download-concurrency 16 \
  --check-concurrency 16 --upload-concurrency 16 \
  --memory-bytes 137438953472 --worker-memory-bytes 6442450944 \
  --scratch-bytes 1099511627776 --max-day-scratch-bytes 68719476736 \
  --work ./work -v
```

For the 48-core / 185 GB RAM / 1.5 TB disk server, this sets a 128 GiB pipeline memory
budget and 1 TiB scratch budget (64 GiB per active partition), with 6 GiB per worker. Workers stream files; a multi-GiB input need not fit in memory.
All tables share day admission, download, validation, upload and multipart limits.

**No DDL or mandatory per-table files are required.** Parquet supplies the native type schema.
The first completed file's complete schema is pinned per table in `SOURCE-SCHEMA.json` and all
other files/days must agree, including dropped columns. Optional `--audit-policy audit.toml`
adds semantic constraints and incident indicators; see [field-audit coverage](PARQUET-AUDIT-COVERAGE.md).
Defaults admit files up to 32 GiB compressed / 256 GiB uncompressed, with a 100:1 ratio cap.

Use **`--verify`** for the full local download/audit/regeneration path with S3 writes disabled.
It requires neither `--destination` nor destination credentials. `--mode` defaults to `enforce`.
`--mode survey` also writes nothing forward, but does not regenerate output chunks.
**Both stop at the first finding**, as do worker panics, unsupported types, schema drift, resource
failures and other uncertainty. Other active work is cancelled and no new partitions start.
`STOP.json` records the cause; a stopped run cannot be resumed. Resolve the cause and use a new
batch. This supersedes the original plan's survey exception that continued to inventory findings.
Already committed partitions are not deleted; requests already accepted by S3 may complete during
cancellation. Consumers must use completed manifests, and never treat a stopped run as successful.

After verification, scope review and rotation, use a new batch without `--verify`, with `--destination s3://CLEAN_BUCKET --destination-profile destination` and
`--mode enforce --shape-review-signoff --rotation-signoff` to publish.
The clean paths are `s3://CLEAN/analytics/TABLE/YYYY/MM/DD/BATCH-file-N-part-N.parquet`.
The database/table/date layout and native Parquet representation are retained. File names and
chunk boundaries change; dropped columns and provenance follow the audit contract below.
Each successful partition gets `MANIFEST.json` last. Consumers must read the manifest's files,
not glob every Parquet object; an interrupted attempt can leave unpublished chunks.
Writes are create-only: existing committed partitions are not overwritten. To publish a new
version, choose a new destination root. Resume an interrupted run with the identical arguments
and `--resume`; discovery stays pinned and newly arrived source files require a new batch.
Database reports and inventory live in `WORK/parquet-database/DATABASE/BATCH/`.

## Single table

Inputs live under `s3://RAW/PREFIX/YYYY/MM/DD/table/*.parquet`. The terminal directory is the
unqualified table name; `--table db.table` selects the table and any optional semantic rules.
For `PREFIX/table/YYYY/MM/DD/*.parquet`, pass `--source-layout table-date` with
`--source s3://RAW/PREFIX`. For example, `--source s3://br-ch-exfil/analytics`
and `--table analytics.banshee_markouts` select the table under that database prefix.
The default is `--source-layout date-table`. The layout is pinned for resume.
Outputs live under `s3://CLEAN/PREFIX/BATCH/YYYY/MM/DD/table/` in a **different bucket**.

## Checks and output contract

Every retained value goes through the existing column bounds, anchored patterns, freedom-class
and injection/payload catalogue checks. Encoded payloads and Unicode normalization are checked by
the same scanner used by the TSV audit. Arrays, tuples, maps and Nested values are checked
recursively; generated container punctuation is not scanned as if it were a field value. Blob
bytes are scanned even when the pinned validator uses a hex representation. One finding stops
the entire run. No row is silently repaired, defaulted, dropped or deduplicated.

Parquet schemas must match the observed per-table schema, including excluded columns. Columns marked
`drop = true` are omitted from decoding and output after schema validation. All other columns
retain their native values/types and nulls; the audit adds `_source_object`, `_batch` and
`_imported_at` as String columns. Source key-value metadata is discarded. Output is newly encoded
Parquet with Zstandard level 1, not a copy of the original bytes. No TSV files are produced.

Supported mappings include signed/unsigned integers through 64 bits, Float32/64, Bool,
Decimal128/256 with matching precision/scale, strings/binary, FixedString, Date/Date32,
UTC or timezone-free timestamps, lists, structs and maps. UUID, IPv4/IPv6 and enum membership
checks require optional semantic rules when that meaning is not encoded in the native type.
Native `Nested` uses a list of structs. Parquet has no native integer128/256 type: a binary or decimal encoding is validated as the
type the file declares, never guessed to be the original ClickHouse wide integer. Similarly,
flattened arrays are not guessed to form a ClickHouse Nested group.
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

Input object limits use the existing
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

Read `RESULT.json` and `report.json` at the run root. On failure read `STOP.json`, per-file
`findings.jsonl` and `worker-error.json`. Successful partitions retain `FIELD-AUDIT.json`,
`SHAPE-REVIEW.json`, and `PAYLOAD-INVENTORY.json`. Counts stop at the first finding; they are
not an exhaustive inventory of the remaining source.
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

With `-vv`, logs report effective concurrency, transfer/check timings, queue waits, bytes, rows,
and day throughput. Start with defaults, then compare the same representative days at increasing
concurrency; stop increasing workers once CPU, network or scratch I/O saturates. There is no
fixed throughput guarantee without measuring the server and representative data.

## Resume and consumption

The initial inventory pins each object by version ID when available, otherwise ETag. It is
persisted before processing and reused on resume. Source days must already be closed: additions
after inventory are intentionally outside the run. Missing dates are reported as errors.
Only safe ASCII object names are accepted for provenance; source names never become local paths.

A run with STOP.json or an incomplete attempted partition cannot resume. Otherwise source/destination,
table, dates, schema/override fingerprint, mode, batch, and output settings must match. Resource
budgets may be increased. Regenerated bytes are hashed before upload, existing clean objects are
rehash-verified before reuse, and multipart part checkpoints avoid repeating completed transfers.
Scratch reclaimed after an interruption is not proof of a completed audit. A stopped or incomplete
native partition requires investigation and a new batch. `--resume` is only for runs with no stop
marker and no incomplete previously attempted partitions; completed partitions remain pinned.

Consumers must read **only files listed in a completed day `MANIFEST.json`**, pin the listed
version/ETag, verify SHA-256, and independently validate. Never load an S3 wildcard: an interrupted
upload can leave objects without a manifest. Preserve provenance through subsequent ClickHouse
loading/promotion. This is a separate native-Parquet contract; the TSV quarantine DDL is not its
import schema. Use the manifest schema and independently reviewed destination definitions, and validate conversion before
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

### Progress logging

With `-vv`, the controller logs partition starts and download/audit/upload stage starts and
finishes, plus a heartbeat every 15 seconds while a stage is running. Downloads also report
bytes received, total bytes and average MiB/s every 15 seconds when data is flowing. Audit
completion reports validated rows and output chunks; upload completion reports chunk bytes
and rows. Database partition completion includes completed/selected partitions, rows in
completed partitions and elapsed time. Audit heartbeats indicate liveness, not row-level
completion; row totals are reported when the file audit finishes. Logs do not include field
values. `--verify` produces no upload events because S3 writes are disabled.

### Reusing completed database publications

Add `--skip-published` to an enforce-mode **database upload** command with a new batch ID.
The source inventory is still listed and pinned. For each selected table/day, the pipeline
checks the stable clean `database/table/YYYY/MM/DD/MANIFEST.json` before downloading source
data. No manifest means normal auditing and publication. A committed manifest is read with
pinned version/ETag and checked against its SHA-256 metadata. Its source keys, sizes, ETags,
and versions must exactly cover the current partition; row totals and output keys must agree.
Every referenced output is checked with HEAD for size, ETag, version and SHA-256 metadata;
the three audit reports must also exist with valid hash metadata. Missing or inconsistent
committed objects, changed sources, permission failures and schema disagreements stop the run.

This trusts the clean bucket and the prior audit revision. It does **not** re-download clean
Parquet, hash its bytes again, or claim that the current binary re-audited those rows. Custom
field/type/incident policies or dropped columns are not eligible, and recorded audit limits
must match. No previous STOP marker is removed, and no clean object is overwritten/deleted.
Incomplete partitions without a manifest are not skipped; existing partial publication can
still cause the normal create-only collision checks to stop the run.

`report.json` marks reused partitions as `reused`; `RESULT.json` includes `reused_partitions`
and `newly_completed_partitions`. Total completed counts include both. Each reused partition
has a local `REUSED.json` recording its original batch, code revision, contract and row count.
The flag cannot be combined with `--verify`, `--dry-run`, `--resume`, or single-table mode.
Start a new batch after a stopped attempt. Progress is visible with `-vv`.

### Audit throughput

Native audits reuse Arrow display formatters once per batch/column and reuse the profiling
string buffer, borrow source string/blob bytes, and avoid redundant base58 re-encoding.
A thread-local cache holds at most 4096 successfully decoded public keys; it caches only
representation decoding, never a field's audit decision. Explicit patterns, length limits,
incident indicators and all other field checks still run. Shape statistics retain their
existing algorithms and results. Download and upload concurrency are unchanged.

`file audit complete` logs and local `checked.json` include `decode_secs`, `validation_secs`,
`profile_secs`, and `write_secs`. These measure the batch-processing stages; initial hashing,
footer parsing and physical narrow-integer prechecks are outside these individual counters.

Run the repeatable local audit benchmark (fixture generation is excluded from timing):

```bash
cargo test --release --locked --lib parquet_native_audit_throughput -- --ignored --nocapture
SALVAGE_BENCH_UNIQUE=1 cargo test --release --locked --lib parquet_native_audit_throughput -- --ignored --nocapture
```

The fixture has 100,000 rows, UTC timestamps, repeated addresses, a signature, UInt64 and Float64
columns. The second command uses unique signatures. This measures local audit/profile/output
throughput, not S3 throughput or production completion time.

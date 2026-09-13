# Field auditing against the ClickHouse exfil plan

Compared with **Downloads/Clickhouse Exfil Procedure .pdf**, “Selective ClickHouse Data Salvage
Plan”, v-final, 25 August 2026, particularly sections 8.0–8.7 and 12. This implementation uses
one machine, native Parquet and no ClickHouse insert test. The source Parquet schema is now the
type authority, as requested; no SQL DDL is read by the Parquet CLI.

## Coverage and limits

| Plan requirement | Native Parquet behavior |
| --- | --- |
| 8.0 stop on a finding | First field finding, schema/physical-type failure, worker panic, resource/transfer failure or uncertainty latches STOP.json for the entire invocation. Active work is cancelled and new partitions do not start. No silent resume of stopped or incomplete attempts. |
| 8.0.1 survey | Changed by explicit instruction: survey also stops immediately. `--verify` downloads, checks and regenerates locally without any clean S3 client. Neither mode produces an exhaustive inventory after a failure. |
| 8.1 framing | Valid magic/footer, bounded metadata, internal column chunk offsets, no external chunk files, row group/file/decoded row agreement, full Arrow array validation. Pin the complete observed source schema across files/days and resumes. |
| 8.2 TSV escapes | Not applicable to native Parquet. Null, empty and literal backslash-N remain distinct; no TSV conversion or unescaping. Source metadata is discarded and new Parquet is written. |
| 8.3 integers | Validate supported native signed/unsigned widths. Check physical INT32 values before the library narrows to 8/16 bits, rejecting overflow rather than wrapping. Unsigned32/64 retain their native bit interpretation. |
| 8.3 decimal | Exact precision/scale and magnitude checks on Decimal128/256; no floating-point conversion or rounding. Negative scale and unsupported mappings stop. |
| 8.3 float/bool | Preserve IEEE Float32/64 bits including NaN, infinities and negative zero. Bool is native Boolean. |
| 8.3 date/time | Native Date32 validated against the supported ClickHouse Date32 range; UTC/timezone-free timestamps checked at their declared second/milli/micro/nanosecond precision and supported ClickHouse range. No truncation/clamping. Other timezones/types stop. |
| 8.3 strings/nulls | UTF-8, prohibited control-byte checks, byte caps; native nullability is enforced at every nested level. Optional anchored patterns, length caps and semantic refinements are enforced. |
| 8.3 fixed bytes/blobs | Native fixed width preserved, variable bytes bounded, original bytes scanned in addition to the internal hex validator representation. Binary is retained by default and listed as opaque in FIELD-AUDIT.json; this differs from the plan's default blob exclusion. Use `drop = true` for excluded columns. Binary is not asserted to be safe to deserialize. |
| 8.3 containers | Recurse into list, struct, map keys/values with nesting/element/aggregate field-byte caps. Map entries and keys cannot be null; entries structurally align keys/values. Struct-list Nested values remain aligned structurally. No guessed relationships between separate flattened arrays; map ordering is preserved. |
| 8.5 freedom classes | Numeric/typed fields use their native contracts. Unclassified text/bytes are explicitly Open, not misleadingly labeled Closed. Closed/Constrained strings need an explicit anchored pattern (or explicit hex rule). Reports enumerate the effective leaf rules. |
| 8.6 catalogue | SQL, shell, HTML/JS, spreadsheet, template, JNDI, traversal, URL/SSRF, deserialization, XML, LDAP, NoSQL, prompt injection, Unicode, plus configurable incident IoC/canary literals. Existing credential/secret patterns also apply. |
| 8.6 decoded variants | Raw, NFC and NFKC, percent, relevant named/numeric HTML entities, Unicode escapes including surrogate pairs, and standard/URL-safe base64 runs. Scan every plausible run, including short payloads; cap rounds, aggregate bytes and candidate counts. |
| 8.7 no value repair | No stripping, coercion, row dropping or deduplication. Only explicit column drops; original typed values are used to regenerate output. |
| Rejection accounting | Hex-only samples and first finding's column/row/reason; successful partition field rules and profile, and run RESULT.json/report.json. A stopped run is not a complete payload inventory. |

Native type assurance is **not original ClickHouse semantic assurance**. Parquet Int16 does not
supply an enum allowlist, UTF-8 does not declare “UUID” or “identifier”, and fixed binary does not
unambiguously mean UInt128/UUID/serialized state. Dictionary encoding is compression, not an
enum allowlist. We do not infer those meanings from column names or sampled values. Optional
semantic rules recover these checks without DDL; without them the manifest does not claim them.
Unsupported Parquet logical types stop rather than becoming generic JSON/text. Content in a
String that originated as JSON/Object/Dynamic cannot be identified as such from the string type.

## Optional policy (not DDL)

```toml
# Omit this file entirely for native types + default field and payload checks.
iocs = ["incident-specific-canary"]

[limits]
max_compressed_bytes = 34359738368
max_uncompressed_bytes = 274877906944
max_field_bytes = 1048576
max_decode_rounds = 2

[tables."analytics.example".types]
user_id = "UUID"
address = "IPv4"

[tables."analytics.example".columns.symbol]
class = "closed"
pattern = "^[A-Z0-9_]{1,32}$"
max_len = 32

[tables."analytics.example".columns.status]
class = "closed"
enum_ids = [1, 3, 7]

[tables."analytics.example".columns.blob]
class = "open"
drop = true
```

Pass `--audit-policy path/to/audit.toml`. Policy typos, zero disabling limits, unknown field names
and incompatible semantic types fail. Effective per-table policy/limits are hashed in inventory;
changing them cannot silently alter a resumed run. SOURCE-SCHEMA.json and the manifest's schema
hash bind the observed schema. FIELD-AUDIT.json identifies Open/opaque leaves, patterns and enum
sets; manifests also include effective limits and the incident indicator count.

## Intentionally absent or different

No independent Q2a/Q2b/Q3 trust boundaries or ClickHouse test insert exist. No AV/YARA engine is
run; the built-in catalogue and configured IoCs are the scanners here. No original-server engine,
DDL/default/TTL/row-policy or query-time column checks apply to existing Parquet. Parquet schemas
are trusted for type definitions, not proof that the source types or values were truthful.

Publication remains per table/day, not an atomic whole-database transaction. STOP prevents new
work; previously committed partitions remain and S3 requests accepted before cancellation may
complete. A consumer must use manifests and a successful run result, not wildcard discovery.

Shape reports contain exact rows/nulls and approximate distinct/duplicate/frequency statistics
and display-length extrema. They do not implement the plan's full numeric quantiles, per-key
uniqueness expectations or temporal continuity review. Data correctness, completeness, unknown
payloads and downstream safe handling are not proven by a passing run.

## Regression evidence

Tests exercise every catalogue class through native Parquet in raw, percent and base64 forms;
short/hidden base64, named HTML syntax entities, Unicode surrogate/NFKC combinations and decoded
NFC differences; native null/empty/literal backslash-N and IEEE bit round trips; semantic UUID,
enum, pattern and length checks; decimal/date/physical-integer bounds; nested/binary leaf scans;
schema drift across days and fresh controllers; global panic/finding stop and resume refusal;
and verification against a clean-store implementation that rejects every operation. Linux
integration tests execute the actual isolated worker, including memory-limit failures.

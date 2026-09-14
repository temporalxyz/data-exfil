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

Payload catalogue scanning and decoded variants apply to source text and binary fields,
subject to the explicit Solana contracts below. Native numeric, Boolean and temporal scalars
retain type/range, nullability, byte caps and explicit pattern/length checks, but their generated
validator representations are not speculatively decoded as text. Explicit incident indicators
are still checked against those representations. In particular, a Float64's generated hex bits
must not be interpreted as base64 payload text; output preserves the original float bits.

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

## Solana signature columns

By operator instruction, every top-level column named exactly `signature` uses the
`SolanaSignature` contract in every native Parquet table, without a policy file. Nonempty values must
be strings containing canonical base58 or standard/URL-safe base64 (padded or unpadded), decoding
to exactly 64 bytes. Native nullability, field caps, optional patterns/length limits and explicit
incident indicators still apply. Malformed encoding, wrong length, non-string schemas or a
conflicting semantic override stop the run. Original encoded values are preserved.

General SQL/shell and other text payload patterns are not applied to these opaque signature
bytes or to speculative decodings of their encoded text. The general recognition rule below
also applies to other native string fields.
This checks signature representation, not cryptographic validity or transaction authenticity.
Use `SolanaSignature` in optional `types` rules for signature fields with other names.

## Solana token public keys

Every top-level `token_a`, `token_b` and `fee_payer` column uses `SolanaPublicKey` across native Parquet
tables. Nonempty values must be native strings containing canonical base58 that decodes to exactly
32 bytes. Base64-only values, malformed encodings, wrong lengths and conflicting semantic
overrides stop the run. Native nullability, byte caps, explicit patterns/length limits and
configured incident indicators on the original and decoded bytes still apply. Original
values are preserved in the output Parquet.

These opaque public keys skip generic text payload scanning and speculative base64 decoding:
a valid base58 address may also parse as base64 and produce unrelated punctuation bytes.
The reported `GRp3fBQ9DAt4J34Cduqrb4eWuUQfN7UutoMNxYai4RYg` is covered by a regression test.
This validates representation only; it does not establish ownership or require an on-curve
address. Use `SolanaPublicKey` in optional `types` rules for other public-key column names.

## Recognition independent of column name

By operator instruction, each native string value, including nested string leaves, is checked
for canonical base58 encoding of exactly 32 bytes (Solana address), or canonical base58 or
standard/URL-safe base64 encoding of exactly 64 bytes (Solana signature). Matching values are
assumed to be opaque Solana data and skip generic payload scanning regardless of column name.
This includes `pool_id`; names do not need to be added individually. The original value is
preserved. FIELD-AUDIT.json identifies eligible string fields with `recognizes_solana_encodings`.

All declared validators, nullability, field caps, explicit patterns and semantic refinements
still apply. Incident indicators are checked against both the original and decoded bytes.
Nonmatching values keep the full scanner; malformed values in explicitly typed Solana columns
still stop. Binary fields and the legacy TSV audit do not use this heuristic.

This is an accepted representation assumption, not proof of authenticity or absence of a
payload: an attacker could encode a payload with a matching decoded length. Length alone does
not establish safety, and short base64 payloads can contain SQL or shell syntax. Tests cover
reported addresses, opaque signature representations, explicit constraints/indicators and
short encoded injections that remain findings.

## Empty encoded values

By operator instruction, empty strings are allowed in every `SolanaSignature` and
`SolanaPublicKey` field, including automatic named columns and explicit semantic policies.
They are preserved as empty strings, never converted to NULL or a zero-filled key/signature.
Nonempty values still require their exact encoding and decoded length; whitespace is not
empty. Native NULL constraints and explicit field patterns/length limits/incident indicators
remain enforced. FIELD-AUDIT.json records `allows_empty_encoded_value` for these contracts;
this does not override an explicit pattern that requires a nonempty value.

## Assumed UInt128 binary fields

By operator instruction, the exact top-level names `mid_a_to_b_num`,
`mid_a_to_b_denom`, `mid_b_to_a_num` and `mid_b_to_a_denom` use the
`UInt128Bytes` contract across native Parquet tables. They must have native
fixed-size binary type of exactly 16 bytes. Every bit pattern is accepted as
an opaque UInt128 representation, with bytes and native nullability preserved.
The source schema establishes width only: unsigned integer meaning is an
operator assumption, and no byte order is inferred or changed.

Generic text payload scans, including speculative base64 decoding of generated
hex, do not apply to these fields. Explicit incident indicators, patterns,
length limits and field byte budgets still apply. Wrong schemas and conflicting
semantic/hex/enum overrides stop the run. Empty values do not satisfy this
contract. FIELD-AUDIT.json records the contract; other binary fields retain
their existing full payload scans. Optional `types` policies may explicitly
assign `UInt128Bytes` to other columns. The legacy TSV path is unchanged.

## Raw Solana public-key bytes

Top-level binary columns named `address` use `SolanaPublicKeyBytes`, requiring
native fixed-size binary of exactly 32 bytes. This covers the confirmed
`analytics.solana_program_labels.address` schema. Bytes are preserved unchanged,
without speculative text/base64 scans of their generated hex display. Any 32-byte
value is a possible public-key representation; this does not prove authenticity,
ownership, or consistency with a separate `address_str` field.

Native nullability, byte budgets, explicit patterns/length limits and incident
indicators remain enforced. Wrong widths, variable binary schemas and conflicting
overrides stop the run. Empty binary values are not allowed. Other binary column
names retain their existing scanner unless an explicit `SolanaPublicKeyBytes`
type policy is supplied. String columns named `address` retain their existing
string audit behavior; `label` and `address_str` are also audited as before.

## Reviewed program-label allowlist

The operator approved the 148 exact UTF-8 labels pinned in
[src/parquet_audit/approved_program_labels.txt](src/parquet_audit/approved_program_labels.txt).
This list applies only to `analytics.solana_program_labels.label`. Non-null values
not present in the list stop the run for review, including case changes, empty
strings, and added whitespace. The column must retain its native string schema.

For approved values, only speculative base64 catalogue scanning is skipped.
Raw catalogue checks, Unicode normalization, percent/entity/Unicode-escape
decoding, native nullability, byte budgets, explicit patterns and length limits
remain active. Explicit incident indicators still scan all representations,
including base64. Values are preserved without normalization or rewriting.

Other tables and columns receive no exception. FIELD-AUDIT.json records the
complete list in `approved_base64_exempt_values`. Table identity is supplied by
the controller to the isolated worker, not inferred from source field data.
Jobs without a table identity receive no exception. General and TSV scanners
retain their original behavior. Tests cover all 148 values, exact output
preservation, unknown values, schema rejection, scope, and explicit constraints.

## Reviewed memefi asset exception

The exact native string `ge87` is operator-approved only in
`analytics.memefi_fv.asset`. It skips speculative base64 catalogue scanning;
raw/Unicode/non-base64 decoding checks, type/nullability, byte caps and explicit
field constraints remain active. Explicit incident indicators still inspect all
decoded forms, including base64. Output retains the exact original string.
FIELD-AUDIT.json records `ge87` in `approved_base64_exempt_values`.

This is a single-value exception, not a closed asset allowlist. Other asset values
retain their complete audit. Other tables, columns, and altered values receive
no exception. The program-label allowlist remains separate and closed.

## Packed oracle curves

By operator approval after a scan of 50 source files (1,598,148 nonempty values,
all decoding to 994 bytes, plus 8,500,314 empty values),
`analytics.memefi_oracle_updates.curve_packed` uses a scoped opaque-binary
representation contract. The native column must be a string. Empty strings are
allowed; otherwise canonical standard padded base64 must decode to exactly
994 bytes (1328 encoded ASCII bytes). Wrong sizes, malformed/noncanonical
encodings, whitespace, and conflicting semantic/hex/enum policies stop the run.

The decoded binary and its base64 text skip generic payload catalogue scanning.
Explicit incident indicators still inspect both representations. Native
nullability, field byte budgets, explicit length limits and patterns still
apply, including to empty values. Original strings and NULLs are preserved.
Decoding uses a fixed stack buffer, without per-value heap allocation.
FIELD-AUDIT.json records `PackedCurve(base64,994 bytes)` and its empty-value policy.

This validates encoding and size only, not the unavailable internal curve
layout or numerical correctness. Other columns (including `tox_data`) and other
tables retain their existing audits. The TSV path is unchanged.

## Packed oracle toxicity data

The operator approved empty strings or exactly 35/70 decoded bytes for
`analytics.memefi_oracle_updates.tox_data`, following a 50-file scan:
5,869,363 empty values, 3,347,497 values of 70 bytes and 881,602 of 35 bytes.
Nonempty values must be canonical standard padded base64. Other encodings and
lengths stop the run. This is scoped to the exact table and column; the curve
column still requires 994 bytes.

The same packed-binary checks apply: native string schema and nullability,
field budgets, explicit patterns/length limits, and incident indicators on raw
text and the exact decoded bytes. Generic payload scanning is skipped for these
opaque representations. Output preserves original strings and NULLs; the
decoded binary is never executed. FIELD-AUDIT.json records
`PackedTox(base64,35|70 bytes)` and the empty-value policy. Validation covers
encoding and size, not the undocumented internal structure.

## Operator-approved mint names

By operator instruction, `analytics.mint_infos.name` and
`analytics.mint_infos.symbol` are free display-name fields. Every valid source
string is preserved and accepted; generic payload
catalogue scanning, including raw, normalized, and decoded forms, is disabled
for this exact table and column. Type/nullability, byte budgets, explicit
patterns and length limits remain enforced. Explicit incident indicators still
match the stored value directly. Other tables and columns retain their normal
payload checks. FIELD-AUDIT.json records this with
`operator_approved_free_text: true`.

`analytics.mint_infos.symbol` also permits an embedded NUL byte (`0x00`) so
that malformed-but-valid UTF-8 source symbols can be preserved byte-for-byte.
All other forbidden control bytes remain rejected. FIELD-AUDIT.json records
this as `allows_nul: true`.

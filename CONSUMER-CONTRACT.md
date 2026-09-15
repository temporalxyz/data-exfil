# Consumer contract

This document describes the existing TSV quarantine output. Native output from `audit-parquet`
uses the separate [Parquet contract](PARQUET.md), including native types, day manifests, and no
ClickHouse insert preflight. Independent revalidation and preservation of provenance still apply.

**Read this before loading a salvaged table.**

This data came out of a cluster on which an attacker had root. It has been structurally validated,
canonically regenerated, and checked against a pinned contract. None of that makes it true, and
none of it makes it your last line of defence — because in this topology, **you are the last line
of defence.**

---

## 1. You must independently re-validate. This is not advice.

The source plan specifies an independent importer, Q3, that repeats every structural, escape,
length, type, range and payload-class check before anything reaches a database. Section 9 calls it
*"the single most important control in the plan — it removes Q2 as a point of trust."*

**This topology does not have one** (deviation D2). Every manifest says so, in two fields that
cannot be edited to say otherwise:

```json
"deviations": {
  "consumer_must_revalidate": true,
  "independent_revalidation": false
}
```

The control has not been dropped. It has been **transferred to you**, and this document is the
transfer.

## 2. What to do if your re-validation finds something

Section 8.0 is explicit about the response, and it is not "fix it forward":

> A finding at Q3 that Q2b passed is a second, more serious failure — Q2b's validation is wrong or
> Q2b is compromised. **Discard the batch, destroy and rebuild Q2b, restart from raw S3, never from
> clean S3.**

Translated to this topology: tell us, discard the batch, and we rebuild the quarantine host and
re-run **from the raw bucket**. Do not re-derive from the clean bucket — it is downstream of the
thing that failed.

## 3. Load into quarantine first, as text

- Columns are `String` / `Nullable(String)`. Do not create them typed.
  Section 10: *"a `Date` column accepts `2300-01-01` and silently clamps it, a `String` column
  cannot coerce anything."* Text is what delivers "zero defaulted rows".
- `MergeTree ORDER BY tuple()`. No defaults, materialized expressions, TTLs, projections, row
  policies, materialized views, UDFs or dictionaries.
- Use the exact import flag set shipped with the batch. `input_format_skip_unknown_fields` **defaults
  to 1**: left alone, extra columns are silently discarded and schema drift passes undetected.
- **Materialized views are not enabled until backfill is complete.** An MV attached earlier fires
  during import, double-counts, and propagates unreviewed data.
- The generated `quarantine.sql` in the batch is the DDL we tested against. Use it.

## 3a. Padded columns, when a table was migrated

If a batch was produced with `--prod-schema-dir`, every partition of a table shares one schema even
where the source did not, because the table was altered partway through the range. A column added
by that migration is written as **all nulls** in the partitions that predate it.

- `MANIFEST.json` lists them per partition in `padded_columns`, and `FIELD-AUDIT.json` marks them
  `padded: true`. `target_schema_sha256` identifies the schema the partition was published against.
- **A null in a padded column is not a null that was in the source.** It means the column did not
  exist yet. Do not read it as an observed absence, aggregate over it, or treat it as a default.
- A column added by a migration is published `Nullable` even where production declares it
  `NOT NULL`, so that the old and new partitions share one type. Production's nullability holds
  for every column the range always had.
- Nothing validated those nulls, because there was no value to validate. Every other column went
  through the full audit as usual.
- Partitions from a projected run carry `schema_source: "parquet+target"` rather than `"parquet"`.

## 4. Provenance columns are not optional

Every row carries `_source_object`, `_batch` and `_imported_at`, supplied as literals. **Keep them
through promotion into production.** They are the mechanism by which a batch found bad six months
from now can be retracted without redoing a salvage whose source has since been wiped.

## 5. Sink-side handling, per column

The payload inventory (`PAYLOAD-INVENTORY.json`, from the survey pass) records which catalogue
classes matched which columns. **That file, not this paragraph, is the authoritative list.**
Section 11: *"A consumer of a column with HTML matches must encode; a consumer of a column with URL
matches must not fetch."*

Regardless of what matched:

- Parameterized SQL everywhere. Never concatenate a salvaged value into a query.
- HTML-encode free text when rendering it.
- **Never automatically fetch a stored URL.** A stored URL that something auto-fetches is
  credential theft — `169.254.169.254` is in the catalogue for a reason.
- Never execute a stored template, script, expression or serialized object.
- Replace operational filenames and paths with generated identifiers.
- Protect CSV and Excel exports against formula injection **at export time**. A leading `=`, `+`,
  `-`, `@`, tab or CR turns a cell into a formula.
- Review materialized views and other consumers before enabling them.
- Promote only from quarantine, via reviewed conversion SQL with explicit range and format guards
  that all return zero.

## 6. What the controls do and do not prove

| Control | Proves | Does not prove |
| --- | --- | --- |
| Structural audit | The file frames to the declared shape | Anything about what the fields contain |
| Canonical regeneration | Format smuggling is removed | That parser exploits are gone, or that free text is benign |
| Contract validation | Values match a declared shape and range | That values are true, or safe to render |
| Generation + checksum | The bytes are the approved bytes | That the producing host was uncompromised |
| Payload detection | Nothing in the batch matched the catalogue | That a column is clean — patterns are bypassable by design |
| Fail-closed abort | This batch had zero findings | That a batch which aborted was malicious |
| Shape review | Clumsy fabrication is likely to be noticed | That data is untampered — careful work passes |

## 7. Three things nobody checked

Out of scope by the source plan's own decision (section 0), and unchanged here:

1. **Data correctness.** Tampered, deleted, back-dated and fabricated rows are not detected.
2. **Evidence preservation.** No disk images or state snapshots were taken.
3. **Completeness.** *"Nothing verifies that what came back is all of what existed."*

The two-pass diff and the three-number reconciliation (addition A2) narrow the third — they catch
every accident and any lie that is not fully consistent. They do not close it. A root attacker who
lies consistently is undetectable from the client.

**Whoever consumes this data owns the correctness risk. Mark salvaged tables as salvaged.**

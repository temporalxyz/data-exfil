# salvage

Fail-closed extraction of critical tables from a compromised ClickHouse cluster.

Implements the **Selective ClickHouse Data Salvage Plan (v-final, 25 Aug 2026)** for a two-host
topology. Read `DEVIATIONS.md` before trusting anything here to match the source document, and
`CONSUMER-CONTRACT.md` before loading the output.

## The shape of it

```
compromised cluster ──> Q1 (export) ──> raw bucket ──> Q2 (audit) ──> clean bucket ──> consumer
```

One table per invocation. Tables are independent runs, and a table is read in keyset-paginated
pages — a ~100 GB table cannot be sorted whole, held on one disk, or re-run whole after an abort.

```
salvage secrets                                    # rotation inventory. Run FIRST, at incident time
salvage plan     --table <db>.<tbl>                # derive the contract; reads no table data
salvage export   --table <db>.<tbl> --batch <id> --bucket RAW --clickhouse-url URL
salvage audit    --table <db>.<tbl> --batch <id> --mode survey|enforce \
                 --bucket RAW --clean-bucket CLEAN --pages-generation N \
                 --shape-review-signoff --rotation-signoff        # both gate the push
salvage teardown --table <db>.<tbl> --batch <id> --disposition <d> --owner <name> \
                 --accepted --rotation-complete                   # both are gates
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Clean |
| 1 | **ABORT** — a finding. The batch is dead. Never "partially succeeded" |
| 2 | Usage error |
| 3 | Infrastructure error — no cluster, no bucket, no runtime. *Distinct from a finding* |

The 1/3 split is load-bearing: `--resume` is honoured only after an exit 3. A resume that could
skip past a finding would silently deliver the subset section 8.0 forbids.

## Order of operations

1. **`salvage secrets` first.** It reads pinned DDL only — no cluster, no bucket, no data — and the
   rotation it starts proceeds whether or not the batch ever ships. The attacker had root, so the
   scope is every secret the cluster *could* hold, including columns you drop and tables you exclude.
2. **`salvage plan`**, and read the `plan.json` it emits. This is the review gate: the exact bound
   for every column is legible on a page **before anything touches the compromised cluster**. Run it
   without `--clickhouse-url` first to review the contract offline; run it again with one to
   cross-check the cluster.
3. **`salvage audit --mode survey`** on a real batch before `--mode enforce`. Halting on the first
   finding means discovering problems one at a time across many re-runs; the survey enumerates
   everything, writes nothing forward, and produces the payload inventory that fixes scope.
4. **`--mode enforce`**, which is expected to find nothing.

## Pinned inputs

| Path | What it is |
| --- | --- |
| `ddl/<db>.<table>.sql` | The `CREATE TABLE`. **This, not the server, is the authority** for what the table is |
| `overrides/<db>.<table>.toml` | Caps, cutoff, cursor, and the per-column freedom class |

The filename must match the table the DDL declares; a mismatch aborts. Both are source control:
section 4 is explicit that *"the allowlist comes from source control. The server's answer is a
cross-check, never the authority."*

### The per-column decision that cannot be automated

Section 8.5 assigns every column to **Closed** (exact pattern), **Constrained** (restricted set and
length), or **Open** (arbitrary UTF-8 under a cap). A column nobody classifies inherits Closed,
which is the fail-closed default.

> The count of Open columns is the actual injection exposure of the salvage, and it should be
> small, named, and justified per column.

That judgement is yours. `overrides/typematrix.typematrix.toml` is the worked example.

## Flags that are gates, not conveniences

| Flag | Why it has no default |
| --- | --- |
| `--bucket` / `--clean-bucket` | Two buckets, and the audit refuses a run where they resolve to the same destination. Section 5 puts clean in a separate account so the credential that wrote raw cannot reach it; sharing one also makes the consumer contract's "re-run from raw, never re-derive from clean" unenforceable. |
| `--pages-generation` | The Controller pins `PAGES.json`'s generation out of band. Without it the audit would resolve the live one, making the producer the authority over its own output. `--unpinned-ledger` proceeds without a pin and records that the run had none. |
| `--clickhouse-image` | Required for `--runner docker`/`podman`, and it must be `repo@sha256:<64 hex>`. A tag resolves at run time and can be moved, so a tag is not a pin. 25.3 is refused by name -- it is the compromised cluster's own end-of-support build. |
| `--retain-days` | Unlocked object retention, never Locked. Zero means none, and that is a choice rather than an accident. |
| `--shape-review-signoff`, `--rotation-signoff` | Both block the push. Neither is ever set by this code. |
| `--accepted`, `--rotation-complete` | Both block teardown. |

## Placeholders to fill before a run

`RAW_BUCKET`, `CLEAN_BUCKET`, the project ids, the Q1/Q2 service accounts, the source host and
read-only user, the retention period, `page_byte_budget`, the `[limits]` block, the dummy
ClickHouse image **digest** (from section 3's supported list — 26.7, 26.6, 26.5, 26.3 or 25.8;
never 25.3), the batch id format, the IoC and canary strings from the investigation, the rotation
owner per column, and the log sink project.

## Building

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

Release binaries target `x86_64-unknown-linux-gnu` and are built **on** Ubuntu 24.04, which is what
section 3 wants. macOS cannot produce a glibc binary.

Set `SALVAGE_GIT_COMMIT` at build time so the commit travels in every plan and manifest; it reads
`unpinned` otherwise.

## What this tool does not do

- **It does not freeze the source.** Stopping legitimate writers is operational, handled out of
  band at the network and IAM layer, never by logging in to the compromised host. The pinned cutoff
  predicate is what makes the page boundary stable, and it is a `WHERE` clause.
- **It does not provision anything.** Buckets, IAM, VPC and instances are built separately.
- **It does not hold cloud-admin credentials.** `teardown` releases object holds and prints a
  checklist; it does not delete instances, keys or buckets.
- **It does not verify correctness, preserve evidence, or prove completeness.** Section 0 rules all
  three out by decision. `CONSUMER-CONTRACT.md` says so to the people who need to know.

## Testing

`cargo test` runs everything with **zero network and zero ClickHouse**, against `FakeRunner`,
`HostileRunner` and `LocalStore`. `tests/rehearsal.rs` is the section 12 corpus; the items that need
a real host are `#[ignore]`d **by name** rather than omitted, so a passing suite does not read as
full coverage. Run those on Q2 with `cargo test -- --ignored`.

`SECRETS-ROTATION.md`, `SHAPE-REVIEW-NNNN.md`, `PAYLOAD-INVENTORY.json`, `plan.json`, `PAGES.json`,
`MANIFEST.json`, `report.json` and `TEARDOWN.md` are all generated. Do not hand-write them.

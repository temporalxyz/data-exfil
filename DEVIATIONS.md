# Deviations from the source plan

The Selective ClickHouse Data Salvage Plan (v-final, 25 Aug 2026) describes a four-host chain:
Q1 → raw → Q2a → intermediate → Q2b (+T) → clean → Q3 → quarantine. This implementation runs two
hosts and two buckets. Every difference is below, with what it costs and what carries the weight
instead.

Each deviation is also **machine-readable in every manifest**, under `deviations`, so a consumer
learns what was given up without reading this file.

---

## D1 — Q2a and Q2b are one host

**Source:** two separately built hosts, with Q2b unable to reach Q2a, raw S3, or the cluster.

**Here:** one quarantine host does both.

**Cost:** a compromise while parsing hostile input is no longer bounded by a host boundary. Section
6 assumes Q2a can be compromised — *"It runs a parser and scanners (ClamAV and YARA both carry CVE
histories) over attacker-authored bytes"* — and Q2b's separateness is what bounded it.

**Handling:** accepted. Q2 keeps section 6's OS limits, runs non-root, and has no route to the
cluster.

---

## D2 — There is no Q3

**Source:** an independent importer re-validates everything before anything reaches a database.
Section 9 calls it *"the single most important control in the plan — it removes Q2 as a point of
trust."*

**Here:** the pipeline ends at the clean bucket.

**Cost:** the largest deviation in this list. Nothing independently re-validates Q2's output.

**Handling:** transferred to the consumer **in writing**. `CONSUMER-CONTRACT.md` states the
obligation, and every manifest carries `consumer_must_revalidate: true` and
`independent_revalidation: false`. Both are typed so that **the wrong value is a parse error**, not
a configuration option — a hand-edited manifest cannot quietly revoke the transfer.

---

## D3 — One validator, run once

**Source:** the contract is applied independently at Q2a, Q2b and Q3, *"ideally a different
implementation."*

**Here:** one implementation, run once.

**Cost:** a logic flaw in the bounds is a single point of failure. Section 12 items 4 and 11 are
not runnable.

**Handling:** adversarial fixtures instead of independence — `tests/rehearsal.rs` plants one value
per catalogue class plus percent-encoded and base64-wrapped variants, and `HostileRunner` supplies
the shapes that defeat each control if it is written the obvious way. This is weaker than a second
implementation and is not claimed otherwise.

---

## D4 — No intermediate bucket

**Source:** raw → intermediate → clean, with the Controller pinning versions at each hop.

**Here:** raw → clean.

**Cost:** one fewer pinned checkpoint.

**Handling:** audit-to-repack is an in-process boundary rather than a bucket. Raw and clean
generations are still pinned and still approved out of band.

---

## D5 — GCS has no SHA-256 upload checksum

**Source:** `--checksum-algorithm SHA256` on upload; *"S3 version + checksum proves the bytes are
the approved bytes."*

**Here:** GCS offers CRC32C and MD5 only, and no MD5 on composite objects.

**Handling:** the producer computes SHA-256 and writes it to custom metadata; every consumer
recomputes it from the bytes. CRC32C is sent as `x-goog-hash` for transport integrity only. **The
ledger is the authority, never a GCS-reported hash.**

---

## D6 — Tarballs, which the source plan does not have

**Source:** bare `.tsv.gz` files.

**Here:** each page is a `.tar` of its `.tsv` plus its `.json`, in one gzip member.

**Cost:** a new smuggling surface — traversal, links, duplicate members, long-name records, lying
size fields.

**Handling:** `src/archive.rs` applies section 8.1-equivalent framing over raw tar headers. Regular
files only; no absolute paths; no `..`; no duplicate names; caps on member count, member size and
total size; ratio enforced streaming. The `tar` crate does no path rewriting on iteration, so
**rejection is the only behaviour available** — nothing sanitises behind us.

---

## D7 — The shape review happens on the quarantine host

**Source:** section 9 places it at Q3, on staging tables.

**Here:** Q2 profiles the values it parsed and emits `SHAPE-REVIEW-NNNN.md`.

**Handling:** push to clean blocks on `SHAPE_REVIEW_SIGNOFF`. The profile is computed from the
values that will actually ship rather than from a database we fed, and the equivalent SQL is
emitted so a reviewer can run it against staging and compare.

---

# Additions the source plan does not cover

| # | Addition | Why |
| --- | --- | --- |
| A1 | Throw-mode export `SETTINGS`, plus a check that every pinned name exists in `system.settings` | The plan never blocks the **ordinary settings path to a silent partial result**. See below. |
| A2 | Total `ORDER BY`, pinned cutoff predicate, two passes diffed by SHA-256 | Section 0 concedes *"nothing verifies that what came back is all of what existed."* This is the first completeness signal in the chain. |
| A3 | Secret classes, a rotation inventory, and a `ROTATION_SIGNOFF` gate | Section 8.6 has IoC/canary but nothing for *"this value is a live credential."* Rotation scope is the whole schema, not the matches. |
| A4 | Audit logging, local query logging, destination alerting | GCS Data Access logs are **off by default**; without them nothing records who read the salvage. |
| A5 | Unlocked (governance) retention, never Locked | Locked retention would hold the attacker's data immutably and indefinitely and block deleting the bucket at all. A liability, not a control. |
| A6 | `teardown`, including a **recorded** source disposition | The plan says the source is kept until acceptance and never says what happens next. With no evidence preserved, that makes it irreversible and unowned. |
| A7 | Per-table batches, keyset pagination sized from row bytes, per-table reconciliation, table-scoped all-or-nothing promotion | ~100 GB tables cannot be sorted whole, held on one disk, or re-run whole after an abort. |

## A1 in full — the truncation hole

Section 13 accepts that *"the source server chooses what to return and can filter or fabricate."*
What the document never says is that the ordinary settings path produces a **successful partial
result**: no error, valid gzip, correct trailer, `gzip -t` passes, and every downstream control
satisfied by it. Section 8.1 audits framing, 8.3 validates values, section 9 counts rows against a
manifest the producer wrote. Nothing compares what came back to what existed.

The attacker is root, so they own the read-only user's settings profile and any row policy on it.
`read_overflow_mode='break'`, `timeout_overflow_mode='break'`, `result_overflow_mode='break'`, the
`limit`/`offset` settings, `additional_table_filters`, `apply_deleted_mask`, the query cache, and a
stale replica without `select_sequential_consistency` all truncate **without erroring**.

Every export query therefore carries a pinned `SETTINGS` block that sets every overflow mode to
`throw` and every ceiling to zero. A profile constraint or `readonly=1` makes our override raise
`SETTING_CONSTRAINT_VIOLATION` or `READONLY`. **So either we win the setting and get a complete
result, or we lose it and the query errors. There is no branch where the query succeeds with a
quietly clipped result.**

This does not defeat a root attacker. It converts every config-based truncation into a loud
failure, forcing them into an active lie — a row policy, or a patched binary — which is the
residual risk section 13 already accepts.

## Not implemented, deliberately

**Freezing the source is not part of this tool.** Stopping legitimate writers is an operational
step handled out of band at the network and IAM layer, never by logging in to the compromised host.
Nothing here attempts it and nothing here verifies it. What makes the page boundary stable across
the two export passes is the **pinned cutoff predicate**, which is a `WHERE` clause and needs no
cooperation from the server.

//! Test doubles. Compiled unconditionally -- see the note on the `testkit` module in `lib.rs`.
//!
//! Three things live here, and each exists because the real thing cannot be reached from a test:
//!
//! - `FakeRunner` / `HostileRunner` -- a query source with no ClickHouse. The hostile variant is
//!   the oracle for several controls, most importantly "returns different bytes on the second
//!   identical call", which is what proves the two-pass diff actually diffs.
//! - `LocalStore` -- an object store with no GCP that **enforces the invariants**: a monotonic
//!   generation per name, a create-only refusal on any second write, and a generation mismatch on
//!   a pinned read. A code path that forgets `ifGenerationMatch=0` fails a test even though no
//!   packet moved.
//! - A byte-level tar builder. `.gitignore` excludes `*.tar` and `*.tar.gz`, so the adversarial
//!   archive corpus cannot be committed as fixtures and must be synthesised in code.
//!
//! Not yet implemented; see the plan's steps 5, 7 and 8.

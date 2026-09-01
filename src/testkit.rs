//! Test doubles. Compiled unconditionally -- see the note on the `testkit` module in `lib.rs`.
//!
//! Three things live here, and each exists because the real thing cannot be reached from a test:
//!
//! - [`LocalStore`] -- an object store with no GCP that **enforces the invariants** rather than
//!   recording calls. Built first, before `gcs::HttpStore`, precisely because it is the oracle
//!   that makes the HTTP side testable at all.
//! - `FakeRunner` / `HostileRunner` -- a query source with no ClickHouse. The hostile variant is
//!   the oracle for several controls, most importantly "returns different bytes on the second
//!   identical call", which is what proves the two-pass diff actually diffs. Step 5.
//! - A byte-level tar builder. `.gitignore` excludes `*.tar` and `*.tar.gz`, so the adversarial
//!   archive corpus cannot be committed as fixtures and must be synthesised in code. Step 8.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::abort::{Result, infra};
use crate::gcs::{Created, Generation, ObjectMeta, ObjectName, ObjectStat, ObjectStore};

/// One stored generation. Immutable once written, which is the point.
#[derive(Debug, Clone)]
struct Stored {
    generation: Generation,
    size: u64,
    sha256_hex: Option<String>,
    hold: bool,
    /// Modelled, not ignored. Every production call site passed `retain_until: None` while the
    /// retention code sat correct, tested and unreachable -- and no test could notice, because
    /// this store dropped the field. An oracle that ignores a control cannot fail a caller that
    /// forgets it.
    retain_until: Option<time::OffsetDateTime>,
    /// Whether this generation is the live one. Noncurrent generations still exist and are still
    /// readable by explicit generation -- that is what object versioning means.
    live: bool,
}

/// A tempdir-backed [`ObjectStore`] that enforces GCS's create-only and generation semantics.
///
/// # Why this is an oracle and not a mock
///
/// A recording mock would let a caller that forgot `ifGenerationMatch=0` pass its tests, because a
/// mock asserts what it was told to assert. This enforces the invariants instead:
///
/// - **Generations are monotonic and never reused.** A generation identifies bytes for all time.
/// - **A second write to a live name never overwrites.** It returns [`Created::Existed`], which is
///   the same signal a real 412 carries.
/// - **A pinned read of the wrong generation fails.** "Latest under prefix" is not reachable
///   through this type, because there is no method that offers it.
///
/// So a code path that drops the precondition fails a test **with no packet moving**. That is the
/// whole reason this exists before `HttpStore` rather than after it.
///
/// Bodies are stored flat under `root/<generation>.bin`. Object names never touch the filesystem,
/// so a name that somehow escaped [`ObjectName`]'s validation still cannot traverse out of `root`.
#[derive(Debug)]
pub struct LocalStore {
    root: PathBuf,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// Ordered so `list` is deterministic; a test that depends on hash order is a flaky test.
    objects: BTreeMap<String, Vec<Stored>>,
    next_generation: u64,
}

impl LocalStore {
    /// `root` must already exist. Tests pass a `tempfile::tempdir()` path -- `tempfile` is a
    /// dev-dependency and this module is in the library, so the store cannot create one itself.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            state: Mutex::new(State {
                objects: BTreeMap::new(),
                // Real GCS generations are microsecond timestamps. Starting from a plausible one
                // keeps fixtures readable and stops a test from passing on `Generation(0)`.
                next_generation: 1_700_000_000_000_000,
            }),
        }
    }

    fn body_path(&self, generation: Generation) -> PathBuf {
        self.root.join(format!("{}.bin", generation.0))
    }

    /// Make the live generation of `name` noncurrent, as a delete or an overwrite would.
    ///
    /// A test affordance, and a pointed one: `ifGenerationMatch=0` means "no **live** object", so
    /// after this call a create **succeeds** even though earlier generations still exist and are
    /// still readable. That is the trap the plan records, and it is reachable here so a test can
    /// prove the caller reconciles against the ledger rather than trusting the precondition.
    pub fn archive_live(&self, name: &ObjectName) -> Result<()> {
        let mut state = self.lock()?;
        let versions = state
            .objects
            .get_mut(name.as_str())
            .ok_or_else(|| infra::<()>("archive_live: no such object").unwrap_err())?;
        for v in versions.iter_mut() {
            v.live = false;
        }
        Ok(())
    }

    /// The retention instant recorded for the live generation of `name`, if any.
    ///
    /// Exists so a test can assert that a caller actually asked for retention. Addition A5 is a
    /// control the code could express and never invoked; without this accessor no test could tell
    /// the difference between "retention set" and "retention silently omitted".
    pub fn retain_until(&self, name: &ObjectName) -> Result<Option<time::OffsetDateTime>> {
        let state = self.lock()?;
        Ok(state
            .objects
            .get(name.as_str())
            .and_then(|vs| vs.iter().find(|v| v.live))
            .and_then(|v| v.retain_until))
    }

    /// Every generation ever written for a name, newest last. Noncurrent ones included.
    pub fn generations(&self, name: &ObjectName) -> Result<Vec<Generation>> {
        let state = self.lock()?;
        Ok(state
            .objects
            .get(name.as_str())
            .map(|vs| vs.iter().map(|v| v.generation).collect())
            .unwrap_or_default())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| infra::<()>("LocalStore mutex poisoned").unwrap_err())
    }

    fn stat_of(name: &ObjectName, v: &Stored) -> ObjectStat {
        ObjectStat {
            name: name.clone(),
            generation: v.generation,
            size: v.size,
            sha256_hex: v.sha256_hex.clone(),
            hold: v.hold,
        }
    }
}

impl ObjectStore for LocalStore {
    fn location(&self, prefix: &str) -> String {
        format!(
            "local://{}/{}",
            self.root.display(),
            prefix.trim_start_matches('/')
        )
    }

    fn create(&self, name: &ObjectName, body: &Path, meta: &ObjectMeta) -> Result<Created> {
        let mut state = self.lock()?;

        // The precondition, enforced server-side in the real thing and here. Note it tests for a
        // *live* object, not for any object: that asymmetry is the trap, and modelling it is the
        // reason this store is worth having.
        if let Some(existing) = state
            .objects
            .get(name.as_str())
            .and_then(|vs| vs.iter().find(|v| v.live))
        {
            return Ok(Created::Existed(Box::new(Self::stat_of(name, existing))));
        }

        let bytes = std::fs::read(body).map_err(|e| {
            infra::<()>(format!("could not read upload body: {e}"))
                .unwrap_err()
                .with("path", body.display())
        })?;

        let generation = Generation(state.next_generation);
        state.next_generation = state.next_generation.saturating_add(1);

        std::fs::write(self.body_path(generation), &bytes).map_err(|e| {
            infra::<()>(format!("could not stage object body: {e}"))
                .unwrap_err()
                .with("object", name)
        })?;

        state
            .objects
            .entry(name.as_str().to_owned())
            .or_default()
            .push(Stored {
                generation,
                size: bytes.len() as u64,
                sha256_hex: Some(meta.sha256_hex.clone()),
                hold: meta.hold,
                retain_until: meta.retain_until,
                live: true,
            });

        Ok(Created::Fresh(generation))
    }

    fn get_pinned(&self, name: &ObjectName, generation: Generation, dest: &Path) -> Result<()> {
        let state = self.lock()?;
        let found = state
            .objects
            .get(name.as_str())
            .and_then(|vs| vs.iter().find(|v| v.generation == generation));

        // A miss is deliberately not "fall back to the newest". There is no method on this type
        // that returns latest-under-prefix, because there is no code path in the tool allowed to
        // want one.
        if found.is_none() {
            return infra("no such generation").map_err(|e: crate::abort::SalvageError| {
                e.with("object", name).with("generation", generation)
            });
        }

        let bytes = std::fs::read(self.body_path(generation))
            .map_err(|e| infra::<()>(format!("could not read stored object: {e}")).unwrap_err())?;
        std::fs::write(dest, bytes).map_err(|e| {
            infra::<()>(format!("could not write destination: {e}"))
                .unwrap_err()
                .with("path", dest.display())
        })
    }

    fn stat(&self, name: &ObjectName) -> Result<Option<ObjectStat>> {
        let state = self.lock()?;
        Ok(state
            .objects
            .get(name.as_str())
            .and_then(|vs| vs.iter().find(|v| v.live))
            .map(|v| Self::stat_of(name, v)))
    }

    fn list(&self, prefix: &str) -> Result<Vec<ObjectStat>> {
        let state = self.lock()?;
        let mut out = Vec::new();
        for (key, versions) in &state.objects {
            if !key.starts_with(prefix) {
                continue;
            }
            let Some(live) = versions.iter().find(|v| v.live) else {
                continue;
            };
            // Round-tripping through the validator keeps `list` from inventing a name that
            // `create` would have refused.
            out.push(Self::stat_of(&ObjectName::new(key.clone())?, live));
        }
        Ok(out)
    }

    fn set_hold(&self, name: &ObjectName, generation: Generation, hold: bool) -> Result<()> {
        let mut state = self.lock()?;
        let found = state
            .objects
            .get_mut(name.as_str())
            .and_then(|vs| vs.iter_mut().find(|v| v.generation == generation));
        match found {
            Some(v) => {
                v.hold = hold;
                Ok(())
            }
            None => {
                infra("set_hold: no such generation").map_err(|e: crate::abort::SalvageError| {
                    e.with("object", name).with("generation", generation)
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abort::ExitCode;

    fn meta(sha: &str) -> ObjectMeta {
        ObjectMeta {
            sha256_hex: sha.to_owned(),
            retain_until: None,
            hold: true,
            content_type: "application/gzip",
        }
    }

    /// A store plus a scratch file holding `body`, ready to upload.
    fn fixture(body: &[u8]) -> (tempfile::TempDir, LocalStore, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::new(dir.path().join("store"));
        std::fs::create_dir_all(dir.path().join("store")).unwrap();
        let src = dir.path().join("page-0000.tar.gz");
        std::fs::write(&src, body).unwrap();
        (dir, store, src)
    }

    fn name(s: &str) -> ObjectName {
        ObjectName::new(s).unwrap()
    }

    #[test]
    fn a_second_write_to_a_live_name_never_overwrites() {
        let (_d, store, src) = fixture(b"page one");
        let n = name("events.hits/b1/page-0000.tar.gz");

        let first = store.create(&n, &src, &meta(&"aa".repeat(32))).unwrap();
        let Created::Fresh(g1) = first else {
            panic!("the first write must be fresh");
        };

        // The same name again, with different bytes and a different claimed hash. A store that
        // silently replaced would return Fresh with a new generation, and every downstream
        // guarantee about pinned generations would be worthless.
        std::fs::write(&src, b"page one, tampered").unwrap();
        let second = store.create(&n, &src, &meta(&"bb".repeat(32))).unwrap();

        match second {
            Created::Existed(stat) => {
                assert_eq!(stat.generation, g1, "the live generation must not move");
                assert_eq!(
                    stat.sha256_hex.as_deref(),
                    Some("aa".repeat(32).as_str()),
                    "the first write's metadata must survive the second attempt"
                );
            }
            Created::Fresh(_) => panic!("create-only was not enforced: the object was replaced"),
        }

        // And the bytes on disk are still the first write's.
        let dest = _d.path().join("readback");
        store.get_pinned(&n, g1, &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"page one");
    }

    #[test]
    fn generations_are_monotonic_and_never_reused() {
        let (_d, store, src) = fixture(b"x");
        let mut seen = Vec::new();
        for i in 0..5 {
            let n = name(&format!("t/b1/page-{i:04}.tar.gz"));
            let Created::Fresh(g) = store.create(&n, &src, &meta(&"00".repeat(32))).unwrap() else {
                panic!("each distinct name is a fresh write");
            };
            seen.push(g);
        }
        assert!(
            seen.windows(2).all(|w| w[0] < w[1]),
            "generations must increase: {seen:?}"
        );
        let mut deduped = seen.clone();
        deduped.dedup();
        assert_eq!(deduped.len(), seen.len(), "a generation was reused");
    }

    #[test]
    fn a_pinned_read_of_the_wrong_generation_fails_rather_than_falling_back() {
        let (d, store, src) = fixture(b"real bytes");
        let n = name("t/b1/page-0000.tar.gz");
        let Created::Fresh(g) = store.create(&n, &src, &meta(&"00".repeat(32))).unwrap() else {
            panic!()
        };

        let dest = d.path().join("out");
        let err = store
            .get_pinned(&n, Generation(g.0 + 1), &dest)
            .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::Infra);
        assert!(
            !dest.exists(),
            "a failed pinned read must not leave a file that looks like a successful one"
        );
    }

    /// The trap, made reachable so it can be tested against.
    ///
    /// `ifGenerationMatch=0` means "no **live** object". With versioning on, a name whose
    /// generations are all noncurrent accepts a create -- so a caller that treats a successful
    /// push as proof the name was untouched is wrong. Reconcile against the ledger.
    #[test]
    fn a_name_with_only_noncurrent_generations_still_accepts_a_create() {
        let (_d, store, src) = fixture(b"first");
        let n = name("t/b1/page-0000.tar.gz");

        let Created::Fresh(g1) = store.create(&n, &src, &meta(&"11".repeat(32))).unwrap() else {
            panic!()
        };
        store.archive_live(&n).unwrap();

        std::fs::write(&src, b"second").unwrap();
        let second = store.create(&n, &src, &meta(&"22".repeat(32))).unwrap();
        let Created::Fresh(g2) = second else {
            panic!("the precondition passes when nothing is live -- this is the documented trap")
        };

        assert_ne!(g1, g2);
        assert_eq!(
            store.generations(&n).unwrap(),
            vec![g1, g2],
            "the earlier generation still exists; it is merely not live"
        );
    }

    #[test]
    fn an_archived_generation_is_still_readable_by_generation() {
        let (d, store, src) = fixture(b"still here");
        let n = name("t/b1/page-0000.tar.gz");
        let Created::Fresh(g) = store.create(&n, &src, &meta(&"00".repeat(32))).unwrap() else {
            panic!()
        };
        store.archive_live(&n).unwrap();

        assert!(store.stat(&n).unwrap().is_none(), "nothing is live now");
        // But the ledger's pinned generation still resolves, which is exactly why the ledger and
        // not the live pointer is the authority.
        let dest = d.path().join("out");
        store.get_pinned(&n, g, &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"still here");
    }

    #[test]
    fn list_returns_only_live_objects_under_the_prefix() {
        let (_d, store, src) = fixture(b"x");
        for i in 0..3 {
            let n = name(&format!("t/b1/page-{i:04}.tar.gz"));
            store.create(&n, &src, &meta(&"00".repeat(32))).unwrap();
        }
        store
            .create(
                &name("t/b2/page-0000.tar.gz"),
                &src,
                &meta(&"00".repeat(32)),
            )
            .unwrap();
        store.archive_live(&name("t/b1/page-0001.tar.gz")).unwrap();

        let live: Vec<String> = store
            .list("t/b1/")
            .unwrap()
            .into_iter()
            .map(|s| s.name.as_str().to_owned())
            .collect();
        assert_eq!(
            live,
            vec![
                "t/b1/page-0000.tar.gz".to_owned(),
                "t/b1/page-0002.tar.gz".to_owned()
            ],
            "archived objects and other batches must not appear"
        );
    }

    #[test]
    fn a_hold_is_set_per_generation_and_defaults_on() {
        let (_d, store, src) = fixture(b"x");
        let n = name("t/b1/page-0000.tar.gz");
        let Created::Fresh(g) = store.create(&n, &src, &meta(&"00".repeat(32))).unwrap() else {
            panic!()
        };
        assert!(
            store.stat(&n).unwrap().unwrap().hold,
            "the fixture requests a hold and it must be recorded"
        );

        // Teardown releases it; nothing else in the pipeline may.
        store.set_hold(&n, g, false).unwrap();
        assert!(!store.stat(&n).unwrap().unwrap().hold);

        assert_eq!(
            store
                .set_hold(&n, Generation(g.0 + 99), false)
                .unwrap_err()
                .exit_code(),
            ExitCode::Infra,
            "a hold on a generation that does not exist is an error, not a silent no-op"
        );
    }

    #[test]
    fn stat_of_an_absent_name_is_none_not_an_error() {
        let (_d, store, _src) = fixture(b"x");
        // `--resume` calls this to decide verify-and-skip, so "absent" must be an ordinary answer.
        assert!(
            store
                .stat(&name("t/b1/never-written.tar.gz"))
                .unwrap()
                .is_none()
        );
        assert!(store.list("t/b1/").unwrap().is_empty());
    }
}

// -- query sources -------------------------------------------------------------------------------

use crate::clickhouse::{Query, QueryKind, QueryRunner};

/// One query as it was actually sent, settings and all.
///
/// The settings are recorded as rendered text rather than as a reference, because the assertion
/// that matters is *"this query carried the pinned throw-mode block"* -- and a test that checks a
/// pointer proves nothing about what went on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedQuery {
    pub sql: String,
    pub settings: String,
    pub kind: QueryKind,
}

/// A scripted query source with no ClickHouse.
///
/// Matching is by substring against the SQL and **non-consuming**: the same query asked twice gets
/// the same bytes twice. That is deliberate and is the contrast that makes
/// [`Hostility::DifferentOnSecondCall`] meaningful -- against this runner the two-pass diff agrees,
/// against that one it must not.
#[derive(Debug, Default)]
pub struct FakeRunner {
    responses: Vec<(String, Vec<u8>)>,
    log: Mutex<Vec<RecordedQuery>>,
}

impl FakeRunner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer any query containing `matcher` with `body`. First match wins, so register the more
    /// specific matcher first.
    #[must_use]
    pub fn on(mut self, matcher: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        self.responses.push((matcher.into(), body.into()));
        self
    }

    /// Every query this runner was asked, in order.
    pub fn recorded(&self) -> Vec<RecordedQuery> {
        self.log.lock().map(|l| l.clone()).unwrap_or_default()
    }

    /// Whether every query recorded so far carried the given settings text.
    ///
    /// The assertion `export` and `plan` actually need: addition A1 is worthless if one query
    /// slips out without the throw-mode block, and "worthless" here means a silently truncated
    /// result that passes every downstream check.
    pub fn every_query_carried(&self, needle: &str) -> bool {
        self.recorded().iter().all(|q| q.settings.contains(needle))
    }

    fn record(&self, query: &Query) -> Result<Vec<u8>> {
        if let Ok(mut log) = self.log.lock() {
            log.push(RecordedQuery {
                sql: query.sql.clone(),
                settings: query.settings.render(),
                kind: query.kind,
            });
        }
        self.responses
            .iter()
            .find(|(matcher, _)| query.sql.contains(matcher.as_str()))
            .map(|(_, body)| body.clone())
            .ok_or_else(|| {
                infra::<()>("FakeRunner has no scripted response for this query")
                    .unwrap_err()
                    .with("sql", query.sql.escape_debug())
            })
    }
}

impl QueryRunner for FakeRunner {
    fn stream(&self, query: &Query) -> Result<Box<dyn std::io::Read + Send>> {
        Ok(Box::new(std::io::Cursor::new(self.record(query)?)))
    }

    fn scalar(&self, query: &Query) -> Result<String> {
        let bytes = self.record(query)?;
        Ok(String::from_utf8_lossy(&bytes).trim().to_owned())
    }
}

/// What a [`HostileRunner`] does to its output.
///
/// One variant per control that would otherwise have no adversarial test. These are not
/// "malformed input" in general -- each is the specific shape that defeats a specific check if
/// that check is written the obvious way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hostility {
    /// A raw tab inside a field. Section 8.2 rejects it; a naive split on `\t` gains a column.
    EmbeddedTab,
    /// A raw newline inside a field, which gains a *row* rather than a column.
    EmbeddedNewline,
    /// A raw carriage return. Trimmed by a lenient parser, so the value round-trips differently.
    EmbeddedCarriageReturn,
    /// A backslash at end of field. Section 8.2: a `\` at EOF is an abort, never "a literal
    /// backslash".
    LoneBackslash,
    /// Bytes that are not UTF-8. The parser must work on `&[u8]` and never assume otherwise.
    InvalidUtf8,
    /// A field past `max_field_bytes`.
    OversizedField,
    /// A reader that never returns `Ok(0)`. Nothing in the HTTP stack bounds this; only our own
    /// deadline and byte cap do.
    NeverEnding,
    /// A body whose row count disagrees with the count the same runner reports for `count()`.
    /// This is addition A1b: the truncation the pinned settings exist to convert into a loud
    /// failure, arriving anyway.
    RowCountDisagrees,
    /// **The two-pass diff oracle.** The same query returns different bytes the second time it is
    /// asked. A `diff` phase that compares a hash to itself, or that re-reads a cached response,
    /// passes every other test and fails this one.
    DifferentOnSecondCall,
}

/// A query source that answers with exactly one adversarial shape.
#[derive(Debug)]
pub struct HostileRunner {
    mode: Hostility,
    header: String,
    rows: usize,
    calls: Mutex<BTreeMap<String, u32>>,
}

impl HostileRunner {
    #[must_use]
    pub fn new(mode: Hostility) -> Self {
        Self {
            mode,
            header: "id\tbody".to_owned(),
            rows: 3,
            calls: Mutex::new(BTreeMap::new()),
        }
    }

    /// Override the header line, for tests that pin a real column list.
    #[must_use]
    pub fn with_header(mut self, header: impl Into<String>) -> Self {
        self.header = header.into();
        self
    }

    /// How many times this exact SQL has been asked, counting the current call.
    fn bump(&self, sql: &str) -> u32 {
        let Ok(mut calls) = self.calls.lock() else {
            return 1;
        };
        let n = calls.entry(sql.to_owned()).or_insert(0);
        *n = n.saturating_add(1);
        *n
    }

    fn body(&self, sql: &str) -> Vec<u8> {
        let call = self.bump(sql);
        let mut out = Vec::new();
        out.extend_from_slice(self.header.as_bytes());
        out.push(b'\n');

        for i in 0..self.rows {
            let field: Vec<u8> = match self.mode {
                Hostility::EmbeddedTab => b"a\tb".to_vec(),
                Hostility::EmbeddedNewline => b"a\nb".to_vec(),
                Hostility::EmbeddedCarriageReturn => b"a\rb".to_vec(),
                Hostility::LoneBackslash => b"trailing\\".to_vec(),
                // Lone continuation bytes: valid TSV framing, invalid UTF-8.
                Hostility::InvalidUtf8 => vec![0x80, 0xFF, 0xFE],
                Hostility::OversizedField => vec![b'x'; 4 * 1024 * 1024],
                Hostility::DifferentOnSecondCall if call > 1 => b"second-pass".to_vec(),
                _ => b"ordinary".to_vec(),
            };
            out.extend_from_slice(i.to_string().as_bytes());
            out.push(b'\t');
            out.extend_from_slice(&field);
            out.push(b'\n');
        }
        out
    }
}

impl QueryRunner for HostileRunner {
    fn stream(&self, query: &Query) -> Result<Box<dyn std::io::Read + Send>> {
        if self.mode == Hostility::NeverEnding {
            return Ok(Box::new(NeverEnding));
        }
        Ok(Box::new(std::io::Cursor::new(self.body(&query.sql))))
    }

    fn scalar(&self, query: &Query) -> Result<String> {
        // The count this server *claims*, which under `RowCountDisagrees` is not the number of
        // rows it actually streams. Reconciliation is what catches that.
        let claimed = match self.mode {
            Hostility::RowCountDisagrees => self.rows.saturating_mul(10),
            _ => self.rows,
        };
        let _ = self.bump(&query.sql);
        Ok(claimed.to_string())
    }
}

/// A reader with no end. Reads succeed forever and never return `Ok(0)`.
///
/// The point is that it is not an *error* -- every individual read is fine, so nothing short of a
/// total budget stops it. A per-read timeout resets on each success and never fires.
#[derive(Debug)]
struct NeverEnding;

impl std::io::Read for NeverEnding {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        buf.fill(b'x');
        Ok(buf.len())
    }
}

#[cfg(test)]
mod runner_tests {
    use super::*;
    use crate::clickhouse::settings::EXPORT_SETTINGS;
    use crate::limits::{BoundedReader, TransferBudget};

    fn query(sql: &str) -> Query {
        Query {
            sql: sql.to_owned(),
            settings: &EXPORT_SETTINGS,
            kind: QueryKind::Page,
        }
    }

    fn read_all(mut r: Box<dyn std::io::Read + Send>) -> Vec<u8> {
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut out).unwrap();
        out
    }

    #[test]
    fn the_fake_records_the_settings_that_were_actually_sent() {
        let fake = FakeRunner::new().on("SELECT", b"id\tbody\n1\tx\n".to_vec());
        let _ = fake.stream(&query("SELECT a FROM t")).unwrap();
        let recorded = fake.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].kind, QueryKind::Page);
        assert!(fake.every_query_carried("read_overflow_mode = 'throw'"));
        assert!(!fake.every_query_carried("this_was_never_pinned"));
    }

    #[test]
    fn an_unscripted_query_is_an_error_rather_than_an_empty_result() {
        // An empty result and "no such response" are the same bytes downstream, and only one of
        // them means the table was empty.
        let fake = FakeRunner::new().on("count()", b"7".to_vec());
        assert!(fake.stream(&query("SELECT something_else")).is_err());
    }

    #[test]
    fn the_fake_is_deterministic_so_the_two_pass_diff_agrees() {
        let fake = FakeRunner::new().on("SELECT", b"id\tbody\n1\tx\n".to_vec());
        let one = read_all(fake.stream(&query("SELECT a FROM t")).unwrap());
        let two = read_all(fake.stream(&query("SELECT a FROM t")).unwrap());
        assert_eq!(one, two, "identical passes must be byte-identical");
    }

    #[test]
    fn the_hostile_runner_returns_different_bytes_on_the_second_identical_call() {
        // The oracle for addition A2. A `diff` phase that hashes one pass twice, or that caches
        // the response, passes every other test in the suite and fails only this one.
        let hostile = HostileRunner::new(Hostility::DifferentOnSecondCall);
        let one = read_all(hostile.stream(&query("SELECT a FROM t")).unwrap());
        let two = read_all(hostile.stream(&query("SELECT a FROM t")).unwrap());
        assert_ne!(one, two);
        assert!(String::from_utf8_lossy(&two).contains("second-pass"));

        // And a *different* query is still on its first call, so the counter is per statement.
        let other = read_all(hostile.stream(&query("SELECT b FROM t")).unwrap());
        assert!(!String::from_utf8_lossy(&other).contains("second-pass"));
    }

    #[test]
    fn a_never_ending_reader_is_stopped_by_the_byte_cap_and_nothing_else() {
        let hostile = HostileRunner::new(Hostility::NeverEnding);
        let raw = hostile.stream(&query("SELECT a FROM t")).unwrap();
        let budget = TransferBudget {
            wall_clock: std::time::Duration::from_secs(60),
            max_bytes: 64 * 1024,
        };
        let mut bounded = BoundedReader::new(
            raw,
            budget,
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        );
        let mut sink = Vec::new();
        let err = std::io::Read::read_to_end(&mut bounded, &mut sink).unwrap_err();
        assert!(crate::clickhouse::client::is_budget_overrun(&err), "{err}");
        // Every individual read succeeded. Only a total budget stops this, which is the point.
        assert!(bounded.bytes_read() > 0);
    }

    #[test]
    fn a_server_that_claims_more_rows_than_it_streams_is_visible_to_reconciliation() {
        let hostile = HostileRunner::new(Hostility::RowCountDisagrees);
        let claimed: usize = hostile
            .scalar(&query("SELECT count() FROM t"))
            .unwrap()
            .parse()
            .unwrap();
        let body = read_all(hostile.stream(&query("SELECT a FROM t")).unwrap());
        let streamed = body
            .iter()
            .filter(|b| **b == b'\n')
            .count()
            .saturating_sub(1);
        assert_ne!(
            claimed, streamed,
            "the three-number agreement is what catches this"
        );
    }

    #[test]
    fn each_escape_hostility_produces_the_byte_it_promises() {
        for (mode, needle) in [
            (Hostility::EmbeddedTab, &b"a\tb"[..]),
            (Hostility::EmbeddedNewline, &b"a\nb"[..]),
            (Hostility::EmbeddedCarriageReturn, &b"a\rb"[..]),
            (Hostility::LoneBackslash, &b"trailing\\"[..]),
        ] {
            let body = read_all(
                HostileRunner::new(mode)
                    .stream(&query("SELECT a FROM t"))
                    .unwrap(),
            );
            assert!(
                body.windows(needle.len()).any(|w| w == needle),
                "{mode:?} did not emit its payload"
            );
        }
    }

    #[test]
    fn invalid_utf8_reaches_the_parser_as_bytes() {
        // Section 8.2 operates on `&[u8]`: the input is attacker-authored and must not be assumed
        // UTF-8 before it has been checked.
        let body = read_all(
            HostileRunner::new(Hostility::InvalidUtf8)
                .stream(&query("SELECT a FROM t"))
                .unwrap(),
        );
        assert!(String::from_utf8(body.clone()).is_err());
        assert!(body.contains(&0xFF));
    }

    #[test]
    fn an_oversized_field_exceeds_the_default_field_cap() {
        let body = read_all(
            HostileRunner::new(Hostility::OversizedField)
                .stream(&query("SELECT a FROM t"))
                .unwrap(),
        );
        assert!(body.len() > 1_048_576, "got {} bytes", body.len());
    }
}

// -- the adversarial tar forge -------------------------------------------------------------------

use std::io::Write as _;

/// A byte-level tar writer that will emit anything, including archives no correct writer produces.
///
/// This exists because `.gitignore` excludes `*.tar` and `*.tar.gz`, so the hostile corpus cannot
/// be committed as fixtures and has to be synthesised. That turned out to be the better option
/// anyway: a committed fixture is opaque, whereas `TarForge::new().symlink("a", "/etc/passwd")`
/// says what it is testing.
///
/// The `tar` crate cannot be used to build these -- it refuses to write most of them, which is
/// precisely the property that makes it unsuitable as an adversary.
#[derive(Debug, Default)]
pub struct TarForge {
    out: Vec<u8>,
}

/// Tar type flags. `0` regular, `1` hard link, `2` symlink, `3` char device, `4` block device,
/// `5` directory, `6` FIFO, `L` GNU long name, `x` PAX header, `g` global PAX header.
pub mod typeflag {
    pub const REGULAR: u8 = b'0';
    pub const HARDLINK: u8 = b'1';
    pub const SYMLINK: u8 = b'2';
    pub const CHAR_DEVICE: u8 = b'3';
    pub const BLOCK_DEVICE: u8 = b'4';
    pub const DIRECTORY: u8 = b'5';
    pub const FIFO: u8 = b'6';
    pub const GNU_LONG_NAME: u8 = b'L';
    pub const PAX_HEADER: u8 = b'x';
    pub const PAX_GLOBAL: u8 = b'g';
}

impl TarForge {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An ordinary regular file.
    #[must_use]
    pub fn file(self, name: &str, body: &[u8]) -> Self {
        self.raw(name, body, typeflag::REGULAR, "", body.len() as u64)
    }

    /// A member whose header claims a size its body does not have.
    ///
    /// The reader stops at the claimed length, so a longer real body becomes the next header --
    /// a member smuggled inside another member's payload.
    #[must_use]
    pub fn lying_size(self, name: &str, body: &[u8], claimed: u64) -> Self {
        self.raw(name, body, typeflag::REGULAR, "", claimed)
    }

    /// A symlink pointing wherever you like, including out of the tree.
    #[must_use]
    pub fn symlink(self, name: &str, target: &str) -> Self {
        self.raw(name, &[], typeflag::SYMLINK, target, 0)
    }

    #[must_use]
    pub fn hardlink(self, name: &str, target: &str) -> Self {
        self.raw(name, &[], typeflag::HARDLINK, target, 0)
    }

    /// Any type flag at all, for the ones with no convenience method.
    #[must_use]
    pub fn typed(self, name: &str, body: &[u8], flag: u8) -> Self {
        let len = body.len() as u64;
        self.raw(name, body, flag, "", len)
    }

    /// A GNU long-name record followed by the member it renames.
    ///
    /// The header name is short and innocuous; the `L` record supplies the real one. A reader that
    /// merges them sees a different name from one that does not.
    #[must_use]
    pub fn gnu_long_name(self, header_name: &str, real_name: &str, body: &[u8]) -> Self {
        let mut with_nul = real_name.as_bytes().to_vec();
        with_nul.push(0);
        let len = with_nul.len() as u64;
        self.raw("././@LongLink", &with_nul, typeflag::GNU_LONG_NAME, "", len)
            .file(header_name, body)
    }

    /// A PAX extended header overriding `path=`, the same trick by another route.
    #[must_use]
    pub fn pax_path_override(self, header_name: &str, real_name: &str, body: &[u8]) -> Self {
        let record = pax_record("path", real_name);
        let len = record.len() as u64;
        self.raw("PaxHeader", &record, typeflag::PAX_HEADER, "", len)
            .file(header_name, body)
    }

    fn raw(mut self, name: &str, body: &[u8], flag: u8, linkname: &str, size: u64) -> Self {
        let mut header = [0u8; 512];
        write_field(&mut header[0..100], name.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], 0);
        // Checksum is computed with this field held as eight spaces, then written back.
        header[148..156].fill(b' ');
        header[156] = flag;
        write_field(&mut header[157..257], linkname.as_bytes());
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
        let digits = format!("{sum:06o}");
        header[148..154].copy_from_slice(digits.as_bytes());
        header[154] = 0;
        header[155] = b' ';

        self.out.extend_from_slice(&header);
        self.out.extend_from_slice(body);
        // Pad the body to a 512-byte boundary.
        let remainder = body.len() % 512;
        if remainder != 0 {
            self.out.extend(std::iter::repeat_n(0u8, 512 - remainder));
        }
        self
    }

    /// Finish with the two zero blocks a well-formed tar ends with.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        self.out.extend(std::iter::repeat_n(0u8, 1024));
        self.out
    }

    /// Finish **without** the end-of-archive marker.
    ///
    /// This is what a stream that died mid-write looks like, and it is the tar-level equivalent of
    /// the section 4 trap where an export dies mid-stream and still produces a valid gzip.
    #[must_use]
    pub fn finish_truncated(self) -> Vec<u8> {
        self.out
    }

    /// Cut the archive off in the middle of a member's body.
    #[must_use]
    pub fn finish_cut_short(self, keep: usize) -> Vec<u8> {
        let mut out = self.finish();
        out.truncate(keep.min(out.len()));
        out
    }
}

fn write_field(dest: &mut [u8], value: &[u8]) {
    let n = value.len().min(dest.len());
    dest[..n].copy_from_slice(&value[..n]);
}

fn write_octal(dest: &mut [u8], value: u64) {
    // Octal, NUL-terminated, right-aligned with leading zeros: `000000000144\0`.
    let text = format!("{:0width$o}", value, width = dest.len().saturating_sub(1));
    let bytes = text.as_bytes();
    let n = bytes.len().min(dest.len().saturating_sub(1));
    dest[..n].copy_from_slice(&bytes[..n]);
    if let Some(last) = dest.last_mut() {
        *last = 0;
    }
}

/// One PAX record: `"<len> <key>=<value>\n"`, where `<len>` counts itself.
fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut len = body.len() + 1;
    // The length prefix is part of the length, so it converges rather than being computed once.
    loop {
        let candidate = format!("{len}{body}");
        if candidate.len() == len {
            return candidate.into_bytes();
        }
        len = candidate.len();
    }
}

/// gzip some bytes into exactly one member.
#[must_use]
pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let _ = enc.write_all(bytes);
    enc.finish().unwrap_or_default()
}

/// Two gzip members back to back -- valid to `gunzip`, and section 8.1's smuggling path.
///
/// A scanner that reads the first member sees benign content; a decompressor emits both.
#[must_use]
pub fn gzip_concatenated(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut out = gzip(first);
    out.extend_from_slice(&gzip(second));
    out
}

/// One gzip member with arbitrary bytes appended after it.
#[must_use]
pub fn gzip_with_trailing(bytes: &[u8], trailing: &[u8]) -> Vec<u8> {
    let mut out = gzip(bytes);
    out.extend_from_slice(trailing);
    out
}

/// A gzip member whose decompressed size dwarfs its compressed size.
#[must_use]
pub fn gzip_bomb(uncompressed_bytes: usize) -> Vec<u8> {
    gzip(&vec![0u8; uncompressed_bytes])
}

// -- the insert-test double ----------------------------------------------------------------------

use crate::audit::insert::{InsertPlan, InsertTester};

/// Records every insert test the pipeline attempts, and succeeds.
///
/// Deliberately a *recorder* rather than a skip: the audit tests assert that the insert test was
/// **attempted**, with the right staging table and the right column list, on every page. A double
/// that merely returned `Ok` would let a pipeline that forgot the phase entirely pass its tests --
/// which, with no Q3 in this topology, is the last real-parser check going missing unnoticed.
#[derive(Debug, Default)]
pub struct RecordingInsertTester {
    plans: Mutex<Vec<InsertPlan>>,
    /// When set, the nth call fails, standing in for a real parser rejecting the data.
    fail_on_call: Option<usize>,
}

impl RecordingInsertTester {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the `n`th call (1-based), as a real ClickHouse would on a value that satisfied every
    /// regex and still could not be parsed.
    #[must_use]
    pub fn failing_on(mut self, n: usize) -> Self {
        self.fail_on_call = Some(n);
        self
    }

    pub fn attempted(&self) -> Vec<InsertPlan> {
        self.plans.lock().map(|p| p.clone()).unwrap_or_default()
    }
}

impl InsertTester for RecordingInsertTester {
    fn test(&self, plan: &InsertPlan) -> Result<()> {
        let n = {
            let Ok(mut plans) = self.plans.lock() else {
                return infra("RecordingInsertTester mutex poisoned");
            };
            plans.push(plan.clone());
            plans.len()
        };
        if self.fail_on_call == Some(n) {
            return crate::abort::abort("the insert test rejected the data").map_err(
                |e: crate::abort::SalvageError| e.with("staging_table", plan.staging_table.clone()),
            );
        }
        Ok(())
    }
}

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

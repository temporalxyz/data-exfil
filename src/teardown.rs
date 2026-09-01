//! Destroy the estate, and force the source disposition to be **recorded rather than defaulted**
//! (addition A6).
//!
//! The source plan says the compromised cluster is kept until acceptance, and then stops. It never
//! says what happens to it afterwards. Combined with section 0's *"no disk images or state
//! snapshots are taken"*, that makes the disposition irreversible **and unowned** -- which is a gap
//! rather than a decision, since nothing in the document suggests it was considered.
//!
//! This command does not decide it either. It refuses to run without one, which is the difference
//! between a decision and a default.
//!
//! # What this can and cannot do
//!
//! It releases temporary holds, because those go through the object store this tool already has.
//! Everything else -- deleting instances and disks, destroying CMEK keys, deleting service
//! accounts and buckets -- needs cloud credentials this tool deliberately never holds. Those are
//! emitted as a checklist for the operator rather than half-attempted.
//!
//! Two traps in that checklist are easy to miss and are called out in the output: **GCS soft
//! delete is on by default for new buckets**, so a deleted object is retained and billed for the
//! soft-delete window; and an Unlocked retention must be **removed or waited out** before the
//! objects under it can go.

use std::fmt::Write as _;

use crate::abort::{PartialOutput, Result, SalvageError, abort};
use crate::gcs::ObjectStore;

/// What happens to the compromised source after acceptance.
///
/// There is no default. Section 0 rules out evidence preservation by decision, which makes every
/// one of these irreversible -- so the choice is recorded with a named owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Wipe now. Nothing is recoverable afterwards, including anything the investigation has not
    /// thought to ask for yet.
    Wipe,
    /// Snapshot to a separate forensics project, then wipe.
    ///
    /// Worth naming as the recommendation it is: a disk snapshot is cheap, and section 0's "no
    /// evidence preservation" is unrecoverable the moment the disk is gone. This tool flags that
    /// rather than overriding it -- section 0 puts it out of scope by decision, and that decision
    /// belongs to whoever signs this.
    SnapshotThenWipe,
    /// Retain the source as it is, under whatever isolation it is already under.
    Retain,
}

impl Disposition {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Wipe => "wipe",
            Self::SnapshotThenWipe => "snapshot-then-wipe",
            Self::Retain => "retain",
        }
    }

    #[must_use]
    pub const fn consequence(self) -> &'static str {
        match self {
            Self::Wipe => {
                "Irreversible. Nothing about the incident can be re-examined afterwards, including \
                 questions nobody has asked yet."
            }
            Self::SnapshotThenWipe => {
                "The snapshot must live in a separate project the salvage service accounts cannot \
                 reach, with its own retention and its own owner."
            }
            Self::Retain => {
                "The source stays compromised and stays isolated. Someone owns keeping it that \
                 way, and that ownership does not lapse."
            }
        }
    }
}

/// Everything teardown needs, all of it explicit.
#[derive(Debug, Clone)]
pub struct TeardownPlan {
    pub table: String,
    pub batch: String,
    pub raw_prefix: String,
    pub disposition: Disposition,
    /// A named person. Not a team, not a rota -- section A6's point is that the decision has an
    /// owner.
    pub owner: String,
    /// The consumer has accepted the batch.
    pub accepted: bool,
    /// Every row of `SECRETS-ROTATION.md` is done.
    pub rotation_complete: bool,
    pub dry_run: bool,
    /// When the disposition was recorded, as `YYYY-MM-DD`. Section A6 asks for "a named owner
    /// **and date**"; the owner was written and the date was not.
    pub recorded_at: String,
}

/// Run teardown.
pub fn run_teardown(plan: &TeardownPlan, store: &dyn ObjectStore) -> Result<String> {
    if plan.owner.trim().is_empty() {
        return abort("teardown needs a named owner").map_err(|e: SalvageError| {
            e.with(
                "reason",
                "an unowned irreversible decision is a default, not a decision",
            )
        });
    }
    // Both gates, and neither is set by this tool. Tearing down before acceptance destroys the
    // retry the source was being kept for; tearing down before rotation leaves live credentials in
    // a system nobody is watching any more.
    if !plan.accepted {
        return abort("the batch has not been accepted").map_err(|e: SalvageError| {
            e.with(
                "reason",
                "the source is kept until acceptance precisely so there is a second attempt if \
                 the chain fails",
            )
        });
    }
    if !plan.rotation_complete {
        return abort("rotation is not complete").map_err(|e: SalvageError| {
            e.with(
                "reason",
                "rotation scope is every secret the compromised cluster could hold, and it \
                 proceeds regardless of whether the batch shipped",
            )
        });
    }

    // Enumerate on a dry run too. `store.list` is a **read**; only `set_hold` is the effectful
    // leaf. Guarding both meant a dry run never learned what holds existed, so `render` fell into
    // the empty branch and the report asserted "No temporary holds were outstanding" about a live
    // estate it had not looked at -- a false statement in the one artifact that is the record of
    // the teardown decision. The stated acceptance criterion for `--dry-run` is that every
    // validator still runs and only the effectful leaf is stubbed; this was the one phase that
    // broke it.
    let mut released = Vec::new();
    for stat in store.list(&plan.raw_prefix)? {
        if stat.hold {
            if !plan.dry_run {
                // Holds are the only part of the estate this tool holds credentials for. Released
                // here so the objects *can* be deleted; the deletion itself is the operator's.
                store.set_hold(&stat.name, stat.generation, false)?;
            }
            released.push(stat.name.as_str().to_owned());
        }
    }

    Ok(render(plan, &released))
}

/// Render `TEARDOWN.md`.
fn render(plan: &TeardownPlan, released: &[String]) -> String {
    let mut md = String::new();
    let w = &mut md;
    if plan.dry_run {
        // A dry run used to write a report ending "Acceptance: confirmed. Rotation: complete."
        // with nothing distinguishing it from a real one -- so it could later be read as the
        // record of a teardown that never happened, whose hold list was wrong.
        let _ = writeln!(
            w,
            "> **DRY RUN — nothing was released and nothing was destroyed.**\n>\n\
             > This document records what *would* happen. It is not a record that it did.\n"
        );
    }
    let _ = writeln!(
        w,
        "# Teardown -- `{}`, batch `{}`\n",
        plan.table, plan.batch
    );

    let _ = writeln!(w, "## Source disposition\n");
    let _ = writeln!(w, "- **Decision:** `{}`", plan.disposition.label());
    let _ = writeln!(w, "- **Owner:** {}", plan.owner);
    let _ = writeln!(w, "- **Consequence:** {}\n", plan.disposition.consequence());
    if plan.disposition == Disposition::Wipe {
        let _ = writeln!(
            w,
            "> A GCE disk snapshot to a separate forensics project is cheap, and section 0's \"no \
             evidence preservation\" is unrecoverable once the disk is gone. Flagged, not \
             overridden -- section 0 puts it out of scope by decision, and this decision is signed \
             above.\n"
        );
    }

    let _ = writeln!(w, "## Done by this command\n");
    if released.is_empty() {
        let _ = writeln!(w, "- No temporary holds were outstanding.\n");
    } else {
        let _ = writeln!(w, "Released {} temporary hold(s):\n", released.len());
        for name in released {
            let _ = writeln!(w, "- `{name}`");
        }
        let _ = writeln!(w);
    }

    let _ = writeln!(w, "## For the operator\n");
    let _ = writeln!(
        w,
        "This tool holds no cloud-admin credentials and never should, so the rest is a checklist \
         rather than an action. Each line is unchecked until someone does it.\n"
    );
    for item in [
        "Delete the batch objects from the raw bucket.",
        "Wait out or explicitly remove the Unlocked object retention -- objects under it cannot be \
         deleted until then, and the bucket cannot be deleted until they are.",
        "**Account for GCS soft delete**, which is on by default for new buckets: deleted objects \
         are retained and billed for the soft-delete window, and are still recoverable during it. \
         If the point of teardown is that the data is gone, the soft-delete policy has to be dealt \
         with explicitly.",
        "Delete the Q1 and Q2 instances and their disks.",
        "Destroy the dummy ClickHouse container and its volumes.",
        "Disable, then schedule destruction of, the CMEK keys.",
        "Delete the salvage service accounts and any keys issued to them.",
        "Delete the raw and clean buckets once retention permits.",
        "Drop the read-only user on the source cluster -- it was created for this operation and is \
         assumed compromised from the moment it existed.",
        "Execute the source disposition recorded above.",
    ] {
        let _ = writeln!(w, "- [ ] {item}");
    }

    let _ = writeln!(
        w,
        "\n## Sign-off\n\nRecorded by **{}** on {}. Acceptance: confirmed. Rotation: complete.{}",
        plan.owner,
        // The requirement is "a named owner **and date**"; the date was never written.
        plan.recorded_at,
        if plan.dry_run {
            "\n\n**This was a dry run. Nothing above was carried out.**"
        } else {
            ""
        }
    );
    md
}

/// Write `TEARDOWN.md` into the work dir.
pub fn write_report(body: &str, work: &std::path::Path) -> Result<std::path::PathBuf> {
    let path = work.join("TEARDOWN.md");
    let mut guard = PartialOutput::new(work.join("TEARDOWN.md.partial"));
    std::fs::write(guard.path(), body).map_err(|e| {
        crate::abort::infra::<()>(format!("could not write the teardown record: {e}")).unwrap_err()
    })?;
    guard.commit_as(&path)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcs::{Created, ObjectMeta, ObjectName};
    use crate::testkit::LocalStore;

    fn plan() -> TeardownPlan {
        TeardownPlan {
            table: "events.hits".to_owned(),
            batch: "b1".to_owned(),
            raw_prefix: "events.hits/b1".to_owned(),
            disposition: Disposition::SnapshotThenWipe,
            owner: "R. Okonkwo".to_owned(),
            recorded_at: "2026-09-01".to_owned(),
            accepted: true,
            rotation_complete: true,
            dry_run: false,
        }
    }

    fn store_with_a_held_object(dir: &std::path::Path) -> LocalStore {
        std::fs::create_dir_all(dir.join("store")).unwrap();
        let store = LocalStore::new(dir.join("store"));
        let body = dir.join("page.tar.gz");
        std::fs::write(&body, b"x").unwrap();
        let meta = ObjectMeta {
            sha256_hex: "aa".repeat(32),
            retain_until: None,
            hold: true,
            content_type: "application/gzip",
        };
        let name = ObjectName::new("events.hits/b1/page-0000.tar.gz").unwrap();
        assert!(matches!(
            store.create(&name, &body, &meta).unwrap(),
            Created::Fresh(_)
        ));
        store
    }

    #[test]
    fn a_dry_run_enumerates_holds_and_marks_the_report_as_a_dry_run() {
        // `store.list` is a read, not the effectful leaf. Guarding it too meant a dry run never
        // learned what holds existed, so the report claimed "No temporary holds were outstanding"
        // about a live estate it had not looked at -- and it said so in a document that was
        // otherwise indistinguishable from a real teardown record.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("store")).unwrap();
        let store = crate::testkit::LocalStore::new(dir.path().join("store"));

        let body_path = dir.path().join("obj");
        std::fs::write(&body_path, b"x").unwrap();
        let name = crate::gcs::ObjectName::new("events.hits/b1/page-0000.tar.gz").unwrap();
        store
            .create(
                &name,
                &body_path,
                &crate::gcs::ObjectMeta {
                    sha256_hex: "0".repeat(64),
                    retain_until: None,
                    hold: true,
                    content_type: "application/gzip",
                },
            )
            .unwrap();

        let mut p = plan();
        p.dry_run = true;
        let md = run_teardown(&p, &store).unwrap();

        assert!(md.contains("DRY RUN"), "the report must say so: {md}");
        assert!(
            md.contains("page-0000.tar.gz"),
            "a dry run must still enumerate the holds it would release: {md}"
        );
        assert!(
            !md.contains("No temporary holds were outstanding"),
            "the report must not claim an empty estate it never looked at"
        );
        // And the hold is genuinely still set: only the effectful leaf was stubbed.
        assert!(store.stat(&name).unwrap().unwrap().hold);

        // The date is recorded alongside the owner, which section A6 asks for and which was
        // never written.
        assert!(md.contains(&p.recorded_at), "no date in the sign-off: {md}");
    }

    #[test]
    fn teardown_releases_holds_and_records_the_disposition() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_a_held_object(dir.path());
        let md = run_teardown(&plan(), &store).unwrap();

        assert!(md.contains("snapshot-then-wipe"), "{md}");
        assert!(md.contains("R. Okonkwo"), "{md}");
        assert!(md.contains("page-0000.tar.gz"), "{md}");
        // The hold is actually gone, not merely reported.
        let name = ObjectName::new("events.hits/b1/page-0000.tar.gz").unwrap();
        assert!(!store.stat(&name).unwrap().unwrap().hold);
    }

    #[test]
    fn teardown_refuses_without_acceptance_or_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_a_held_object(dir.path());

        let mut p = plan();
        p.accepted = false;
        let err = run_teardown(&p, &store).unwrap_err();
        assert!(err.to_string().contains("second attempt"), "{err}");

        let mut p = plan();
        p.rotation_complete = false;
        assert!(run_teardown(&p, &store).is_err());

        // And the hold survives both refusals: nothing was torn down.
        let name = ObjectName::new("events.hits/b1/page-0000.tar.gz").unwrap();
        assert!(store.stat(&name).unwrap().unwrap().hold);
    }

    #[test]
    fn an_unowned_disposition_is_refused_because_it_would_be_a_default() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_a_held_object(dir.path());
        let mut p = plan();
        p.owner = "   ".to_owned();
        assert!(run_teardown(&p, &store).is_err());
    }

    #[test]
    fn a_wipe_carries_the_recommendation_it_is_overriding() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_a_held_object(dir.path());
        let mut p = plan();
        p.disposition = Disposition::Wipe;
        let md = run_teardown(&p, &store).unwrap();
        assert!(md.contains("forensics project"), "{md}");
        assert!(md.contains("Irreversible"), "{md}");
    }

    #[test]
    fn the_checklist_names_the_two_traps_that_leave_data_behind() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_a_held_object(dir.path());
        let md = run_teardown(&plan(), &store).unwrap();
        // Both are defaults that silently keep data after a "deletion".
        assert!(md.contains("soft delete"), "{md}");
        assert!(md.contains("Unlocked object retention"), "{md}");
    }
}

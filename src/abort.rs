//! Fail-closed primitives.
//!
//! Source plan section 8.0: a payload-catalogue match halts the parser at that value, the file is
//! abandoned in place, and no partial output is written. The rejection threshold is zero -- one
//! rejected row aborts the batch. Nothing downstream of an abort runs.
//!
//! An abort is never resolved by lowering the bar, only by changing the input and re-running from
//! the start: drop the offending column, reclassify it Closed or Constrained, or remove the table
//! from scope. Nothing here offers a "continue anyway" path, by design.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Process exit codes.
///
/// `Abort` and `Infra` are deliberately distinct: the first means the batch is dead because the
/// data is suspect, the second means we never got to look. Only the second is resumable, which is
/// what stops `--resume` from silently delivering the subset section 8.0 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Ok = 0,
    Abort = 1,
    Usage = 2,
    Infra = 3,
}

impl ExitCode {
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// One key/value pair of context attached to an error.
type Context = (&'static str, String);

#[derive(Debug, Error)]
pub enum SalvageError {
    /// A finding. The batch is dead.
    #[error("ABORT: {reason}{}", render(context))]
    Abort {
        reason: String,
        context: Vec<Context>,
    },

    /// Caller error -- bad flags, missing pinned file, malformed override.
    #[error("usage: {reason}{}", render(context))]
    Usage {
        reason: String,
        context: Vec<Context>,
    },

    /// No cluster, no bucket, no container runtime. Not a finding; we never got to look.
    #[error("infrastructure: {reason}{}", render(context))]
    Infra {
        reason: String,
        context: Vec<Context>,
    },
}

fn render(context: &[Context]) -> String {
    if context.is_empty() {
        return String::new();
    }
    let mut out = String::from(" [");
    for (i, (k, v)) in context.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        // Infallible for String; the result is discarded rather than unwrapped.
        let _ = write!(out, "{k}={v}");
    }
    out.push(']');
    out
}

impl SalvageError {
    /// The bare reason, **without** the rendered context.
    ///
    /// `Display` renders `reason` plus every `key=value` pair, and the section 8.3 validators
    /// attach the offending value as context at more than twenty sites. Anything that puts an
    /// error into an artifact a human or a consumer will read must use this rather than
    /// `to_string()`, or section 8.0's "a rejected value is never re-emitted forward" is broken by
    /// the error type rather than by the code that formats it.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Abort { reason, .. }
            | Self::Usage { reason, .. }
            | Self::Infra { reason, .. } => reason,
        }
    }

    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Abort { .. } => ExitCode::Abort,
            Self::Usage { .. } => ExitCode::Usage,
            Self::Infra { .. } => ExitCode::Infra,
        }
    }

    /// Attach a key/value pair to an existing error. Findings are only actionable if they say
    /// which table, column and row tripped them.
    #[must_use]
    pub fn with(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
        let ctx = match &mut self {
            Self::Abort { context, .. }
            | Self::Usage { context, .. }
            | Self::Infra { context, .. } => context,
        };
        ctx.push((key, value.to_string()));
        self
    }
}

pub type Result<T> = std::result::Result<T, SalvageError>;

/// Raise a finding. Every rejection funnels through here so findings have one shape.
pub fn abort<T>(reason: impl Into<String>) -> Result<T> {
    Err(SalvageError::Abort {
        reason: reason.into(),
        context: Vec::new(),
    })
}

pub fn usage<T>(reason: impl Into<String>) -> Result<T> {
    Err(SalvageError::Usage {
        reason: reason.into(),
        context: Vec::new(),
    })
}

pub fn infra<T>(reason: impl Into<String>) -> Result<T> {
    Err(SalvageError::Infra {
        reason: reason.into(),
        context: Vec::new(),
    })
}

/// An in-progress file that unlinks itself unless committed.
///
/// This is what makes "no partial output" true on disk rather than merely intended. Because it
/// runs in `Drop`, it holds on the error path *and on a panic* -- which is why the release profile
/// keeps `panic = "unwind"`. With `panic = "abort"` the destructor would never run and a truncated
/// file would survive.
#[derive(Debug)]
pub struct PartialOutput {
    path: PathBuf,
    committed: bool,
}

impl PartialOutput {
    /// Register a path before any bytes are written to it.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            committed: false,
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Mark the file complete so it survives the drop.
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Rename into place and commit in one step -- the completion sentinel from section 4.
    ///
    /// An export that dies mid-stream leaves only the `.partial`, so the presence of the final
    /// name means the write finished. `std::fs::rename` is atomic within a filesystem.
    pub fn commit_as(&mut self, final_path: &Path) -> Result<()> {
        std::fs::rename(&self.path, final_path).map_err(|e| {
            SalvageError::Infra {
                reason: format!("could not rename into place: {e}"),
                context: Vec::new(),
            }
            .with("from", self.path.display())
            .with("to", final_path.display())
        })?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PartialOutput {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Best effort: if the file cannot be removed we must not panic inside Drop. The caller's
        // report records the abort; a leftover .partial is inert and never renamed into place.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A directory of in-progress work that becomes visible in one atomic step, or not at all.
///
/// [`PartialOutput`] makes a single file all-or-nothing. This makes a whole batch all-or-nothing,
/// which is what section 8.0 needs now that the batch is table-scoped: *"nothing partial is ever
/// delivered, and no subset is assembled from a run that found something."* Individual pages are
/// still `PartialOutput` files **inside** the staging directory, so a crash mid-page is clean at
/// the file level; one `rename(2)` of the directory makes the batch visible at the batch level.
/// Two-phase commit with the filesystem doing phase two.
///
/// # Why the staging directory is a sibling of the destination
///
/// [`StagingDir::inside`] derives the staging path from `dest` rather than using the system
/// temporary directory, because `rename(2)` cannot cross a filesystem boundary. On macOS
/// `std::env::temp_dir()` is on a different device from a repository checkout, so a design that
/// staged in `/tmp` would fail with `EXDEV` only on some machines -- and pass every test written
/// on the others.
#[derive(Debug)]
pub struct StagingDir {
    staged: PathBuf,
    dest: PathBuf,
    committed: bool,
}

impl StagingDir {
    /// Create a staging directory beside `dest`.
    ///
    /// Fails if `dest` already exists: that is `Usage`, not `Infra`, because `Infra` is the
    /// resumable class and "this batch was already promoted" is not something a retry fixes.
    pub fn inside(dest: PathBuf) -> Result<Self> {
        if dest.exists() {
            return Err(SalvageError::Usage {
                reason: "batch is already promoted; pick a new --batch or run teardown".to_owned(),
                context: vec![("path", dest.display().to_string())],
            });
        }
        let parent = dest
            .parent()
            .ok_or_else(|| SalvageError::Usage {
                reason: "destination has no parent directory".to_owned(),
                context: vec![("path", dest.display().to_string())],
            })?
            .to_path_buf();
        std::fs::create_dir_all(&parent).map_err(|e| SalvageError::Infra {
            reason: format!("could not create the destination's parent: {e}"),
            context: vec![("path", parent.display().to_string())],
        })?;

        let name =
            dest.file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| SalvageError::Usage {
                    reason: "destination has no usable name".to_owned(),
                    context: Vec::new(),
                })?;
        let staged = parent.join(format!(".{name}.staging"));
        // A leftover from a previous crashed run. Removing it is safe precisely because it was
        // never promoted -- nothing has ever read from a staging directory.
        if staged.exists() {
            let _ = std::fs::remove_dir_all(&staged);
        }
        std::fs::create_dir_all(&staged).map_err(|e| SalvageError::Infra {
            reason: format!("could not create the staging directory: {e}"),
            context: vec![("path", staged.display().to_string())],
        })?;

        Ok(Self {
            staged,
            dest,
            committed: false,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.staged
    }

    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.dest
    }

    /// Make the whole batch visible in one step.
    pub fn promote(&mut self) -> Result<()> {
        // A destination that came into existence between construction and here is the same
        // operator condition `inside()` refuses, and it must get the same class. Mapping every
        // rename failure to `Infra` meant two overlapping runs produced different exit codes
        // depending on timing -- and the first one was the resumable class, for a condition that
        // is not resumable. `ENOTEMPTY` is the one that matters; `EXDEV` cannot arise because
        // `inside()` derives a sibling path, and if it ever did it would be a build error rather
        // than something to retry.
        if self.dest.exists() {
            return usage("the batch destination already exists").map_err(|e: SalvageError| {
                e.with("dest", self.dest.display()).with(
                    "reason",
                    "pick a new --batch or run teardown; this is not resumable",
                )
            });
        }
        std::fs::rename(&self.staged, &self.dest).map_err(|e| {
            let already = e.kind() == std::io::ErrorKind::DirectoryNotEmpty
                || e.kind() == std::io::ErrorKind::AlreadyExists;
            let err = if already {
                SalvageError::Usage {
                    reason: "the batch destination already exists".to_owned(),
                    context: Vec::new(),
                }
            } else {
                SalvageError::Infra {
                    reason: format!("could not promote the staging directory: {e}"),
                    context: Vec::new(),
                }
            };
            err.with("from", self.staged.display())
                .with("to", self.dest.display())
        })?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Best effort, and never a panic inside Drop. An unpromoted staging directory is inert:
        // nothing reads from one, and the caller's report records why the run died.
        let _ = std::fs::remove_dir_all(&self.staged);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn uncommitted_partial_is_unlinked_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("page-0000.tsv.partial");
        {
            let guard = PartialOutput::new(&path);
            std::fs::write(guard.path(), b"half a page").unwrap();
            assert!(path.exists());
        }
        assert!(
            !path.exists(),
            "section 8.0: an abort must leave no partial output"
        );
    }

    #[test]
    fn committed_partial_survives() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("page-0000.tsv");
        {
            let mut guard = PartialOutput::new(&path);
            std::fs::write(guard.path(), b"a whole page").unwrap();
            guard.commit();
        }
        assert!(path.exists());
    }

    #[test]
    fn partial_is_unlinked_even_on_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("page-0000.tsv.partial");
        let p = path.clone();
        let unwound = std::panic::catch_unwind(move || {
            let guard = PartialOutput::new(&p);
            std::fs::write(guard.path(), b"interrupted").unwrap();
            panic!("parser hit an unclassified input");
        });
        assert!(unwound.is_err());
        assert!(
            !path.exists(),
            "Drop must run during unwind; this is why panic = unwind is pinned"
        );
    }

    #[test]
    fn commit_as_renames_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let partial = dir.path().join("page-0000.tsv.gz.partial");
        let finalp = dir.path().join("page-0000.tsv.gz");
        let mut guard = PartialOutput::new(&partial);
        std::fs::write(guard.path(), b"complete").unwrap();
        guard.commit_as(&finalp).unwrap();
        drop(guard);
        assert!(finalp.exists());
        assert!(!partial.exists());
    }

    #[test]
    fn exit_codes_distinguish_finding_from_infrastructure() {
        let finding: SalvageError = abort::<()>("payload class matched").unwrap_err();
        let missing: SalvageError = infra::<()>("no container runtime").unwrap_err();
        assert_eq!(finding.exit_code(), ExitCode::Abort);
        assert_eq!(missing.exit_code(), ExitCode::Infra);
        assert_ne!(finding.exit_code(), missing.exit_code());
    }

    #[test]
    fn context_renders_into_the_message() {
        let e = abort::<()>("value failed its bound")
            .unwrap_err()
            .with("table", "events.hits")
            .with("column", "user_agent");
        let msg = e.to_string();
        assert!(msg.contains("events.hits"), "{msg}");
        assert!(msg.contains("user_agent"), "{msg}");
    }

    #[test]
    fn an_unpromoted_staging_dir_takes_its_contents_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("b1");
        let staged_path;
        {
            let staging = StagingDir::inside(dest.clone()).unwrap();
            staged_path = staging.path().to_path_buf();
            std::fs::write(staging.path().join("page-0000.tar.gz"), b"half a batch").unwrap();
            assert!(staged_path.exists());
        }
        assert!(
            !staged_path.exists(),
            "section 8.0: no subset survives a failed run"
        );
        assert!(!dest.exists(), "and nothing was promoted");
    }

    #[test]
    fn promotion_makes_every_page_visible_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("b1");
        let mut staging = StagingDir::inside(dest.clone()).unwrap();
        for i in 0..3 {
            std::fs::write(staging.path().join(format!("page-{i:04}.tar.gz")), b"x").unwrap();
        }
        assert!(!dest.exists(), "nothing is visible before promotion");
        staging.promote().unwrap();
        drop(staging);
        assert!(dest.join("page-0000.tar.gz").exists());
        assert!(dest.join("page-0002.tar.gz").exists());
    }

    #[test]
    fn the_staging_dir_is_a_sibling_so_the_rename_cannot_cross_a_filesystem() {
        // EXDEV: `rename(2)` cannot cross devices, and on macOS the system temp dir is on a
        // different one from a checkout. Staging in /tmp would fail on some machines and pass
        // every test written on the others. Promoting *into* a tempdir is the direction that
        // actually exercises this.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("nested").join("b1");
        let mut staging = StagingDir::inside(dest.clone()).unwrap();
        assert_eq!(staging.path().parent(), dest.parent());
        std::fs::write(staging.path().join("f"), b"x").unwrap();
        staging.promote().unwrap();
        assert!(dest.join("f").exists());
    }

    #[test]
    fn promoting_over_an_existing_batch_is_a_usage_error_not_a_resumable_one() {
        // Infra is the resumable class, and "this batch already exists" is not something a retry
        // fixes -- it needs a new --batch or a teardown.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("b1");
        std::fs::create_dir_all(&dest).unwrap();
        let err = StagingDir::inside(dest).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::Usage);
    }

    #[test]
    fn a_leftover_staging_dir_from_a_crashed_run_is_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("b1");
        let orphan = dir.path().join(".b1.staging");
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::write(orphan.join("stale"), b"from a crash").unwrap();

        let staging = StagingDir::inside(dest).unwrap();
        assert!(
            !staging.path().join("stale").exists(),
            "a stale page must not be carried forward"
        );
    }
}

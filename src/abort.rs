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
}

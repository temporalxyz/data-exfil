//! The two-pass diff (addition A2).
//!
//! Section 0 concedes that *"nothing verifies that what came back is all of what existed."* Reading
//! every page twice and comparing SHA-256 does not fix that, but it is the first completeness
//! signal in the chain: a difference means the source changed under us, or something is
//! truncating non-deterministically, and either way the batch is dead.
//!
//! # Why this costs one page of disk and not two
//!
//! Doubling the read is unavoidable; doubling the disk is not. **Pass 1 is streamed straight into
//! the hasher and discarded. Pass 2 is streamed into both the hasher and the file we keep.** Peak
//! disk is one page, which is what makes this affordable on a ~100 GB table. Shipping pass 2 rather
//! than pass 1 is not a choice between them: they are byte-identical or the batch is dead.

use sha2::{Digest as _, Sha256};

use crate::abort::{Result, SalvageError, abort};

/// Streaming SHA-256, so a page is never held in memory to be hashed.
#[derive(Debug, Default)]
pub struct Hasher {
    inner: Sha256,
    bytes: u64,
}

impl Hasher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.inner.update(chunk);
        self.bytes = self.bytes.saturating_add(chunk.len() as u64);
    }

    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    #[must_use]
    pub fn finish(self) -> String {
        format!("{:x}", self.inner.finalize())
    }
}

/// Hash a slice. Used for archives, which are already on disk and bounded.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Both passes of one page must agree exactly.
pub fn assert_passes_agree(page: u32, pass1: &str, pass2: &str) -> Result<()> {
    if pass1 == pass2 {
        return Ok(());
    }
    abort("the two export passes disagree").map_err(|e: SalvageError| {
        e.with("page", page)
            .with("pass1_sha256", pass1.to_owned())
            .with("pass2_sha256", pass2.to_owned())
            .with(
                "reason",
                "the source changed between the passes, or something is truncating \
                 non-deterministically",
            )
    })
}

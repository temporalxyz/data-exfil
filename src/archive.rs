//! Hostile tar reading and safe tar writing (deviation D6).
//!
//! The source plan predates tarballs, so this module carries section 8.1-equivalent framing rules
//! for archives. The rule is **reject, never sanitise**: regular files only, no absolute paths, no
//! `..` in any component, no duplicate members, caps on member count and size, ratio enforced
//! streaming.
//!
//! The `tar` crate does no path rewriting on iteration (only `unpack` sanitises), so rejection is
//! the only behaviour available here -- which is what we want.
//!
//! Not yet implemented; see the plan's step 8.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]

use std::path::Path;

use crate::abort::{Result, infra};

/// Read a page archive under the section 8.4 caps, rejecting every hostile framing construct.
pub fn read_page_archive(_archive: &Path, _dest: &Path) -> Result<()> {
    infra("archive::read_page_archive: not implemented")
}

/// Write a page archive from regenerated files. Members are generated, sorted, and unique.
pub fn write_page_archive(_src: &Path, _archive: &Path) -> Result<()> {
    infra("archive::write_page_archive: not implemented")
}

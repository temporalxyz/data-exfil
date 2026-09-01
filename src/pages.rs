//! Pagination: cursor selection, page sizing, and key-group extension.
//!
//! Some tables run to ~100 GB, which breaks three things at once: the `ORDER BY` cannot sort
//! whole, Q1's disk cannot hold the file, and "abort the batch" becomes a 100 GB re-run over a
//! hostile link. So a table is read in pages, by keyset cursor rather than `OFFSET` (seeking past
//! 100 GB is quadratic, and the `offset` *setting* is one of the truncation vectors we pin to
//! zero).
//!
//! Three rules make strict `>` safe, and all three are load-bearing:
//!
//! 1. The cursor is **re-rendered from our own parsed, validated value**, never interpolated from
//!    server-supplied text.
//! 2. **Nullable columns never enter the cursor.** `(a, b) > (x, NULL)` evaluates to NULL, the row
//!    is excluded, and rows vanish with no check firing.
//! 3. A page that ends **mid-key-group is extended** to consume the rest of that group before the
//!    cursor advances, so a non-unique key cannot let `>` skip a group's tail.
//!
//! Not yet implemented; see the plan's step 6.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]

use crate::abort::{Result, infra};
use crate::limits::div_floor;

/// How many rows to request per page, from the measured size of a row.
///
/// The server's `system.columns` estimate is only the seed. After each page this is recomputed
/// from **our own measured output**, so within one page the sizing stops depending on the
/// compromised server's arithmetic at all.
///
/// Uncompressed bytes, not `bytes_on_disk`: the TSV is what has to fit, not the compressed part.
pub fn rows_per_page(page_byte_budget: u64, bytes_per_row: u64) -> Result<u64> {
    div_floor(page_byte_budget, bytes_per_row, "rows_per_page")
}

/// Choose the pagination cursor from the table's ORDER BY key.
pub fn select_cursor() -> Result<()> {
    infra("pages::select_cursor: not implemented")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::abort::ExitCode;

    #[test]
    fn page_size_comes_from_row_size() {
        assert_eq!(rows_per_page(1_000_000, 100).unwrap(), 10_000);
    }

    #[test]
    fn a_fatter_row_yields_a_shorter_page() {
        let thin = rows_per_page(1_000_000, 100).unwrap();
        let fat = rows_per_page(1_000_000, 1_000).unwrap();
        assert!(fat < thin);
    }

    #[test]
    fn a_zero_byte_row_estimate_aborts_rather_than_panicking() {
        let e = rows_per_page(1_000_000, 0).unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
    }
}

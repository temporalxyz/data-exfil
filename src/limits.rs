//! Section 8.4 limits, and the checked-arithmetic vocabulary the parsing modules share.
//!
//! Two jobs. First, the caps themselves as plain data, so a review can read every bound in one
//! place instead of hunting for magic numbers at their call sites. Second, [`OrOverflow`] -- the
//! one idiom every module that denies `clippy::arithmetic_side_effects` uses to turn a `checked_*`
//! or `try_into` into a `SalvageError` that names the operand.
//!
//! Wrapping arithmetic in a bounds validator is a silent wrong answer, which is the exact failure
//! this plan exists to prevent. The release profile sets `overflow-checks = true`, but that only
//! turns a wrap into a panic; a panic in the audit path means an input we failed to classify. The
//! lint plus this trait make it a *finding* instead.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]

use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::abort::{Result, SalvageError, abort};

/// Turn a checked-arithmetic `None`, or a `TryFrom` failure, into a finding that names the operand.
///
/// ```ignore
/// total = total.checked_add(n).or_overflow("page_bytes")?;
/// let n = usize::try_from(cap).or_overflow("cap->usize")?;
/// ```
///
/// A macro was considered and rejected: it would hide the `?`, and the `?` is the point.
pub trait OrOverflow<T> {
    /// `what` names the quantity, so the finding says which bound blew rather than only that one did.
    fn or_overflow(self, what: &'static str) -> Result<T>;
}

impl<T> OrOverflow<T> for Option<T> {
    fn or_overflow(self, what: &'static str) -> Result<T> {
        match self {
            Some(v) => Ok(v),
            None => abort("arithmetic overflow").map_err(|e: SalvageError| e.with("operand", what)),
        }
    }
}

impl<T, E: Display> OrOverflow<T> for std::result::Result<T, E> {
    fn or_overflow(self, what: &'static str) -> Result<T> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => abort("value does not fit its target type")
                .map_err(|err: SalvageError| err.with("operand", what).with("error", e)),
        }
    }
}

/// Floor division that refuses a zero divisor.
///
/// The only place in the crate permitted to perform integer division. `pages.rs` needs it for
/// `rows_per_page = budget / bytes_per_row`, where a zero divisor is reachable: a table whose
/// measured row size is zero would otherwise panic or silently produce a nonsense page size.
pub fn div_floor(numerator: u64, denominator: u64, what: &'static str) -> Result<u64> {
    if denominator == 0 {
        return abort("division by zero").map_err(|e: SalvageError| e.with("operand", what));
    }
    // The only integer division in the crate. Guarded above; denied everywhere else.
    //
    // `arithmetic_side_effects` is allowed alongside it because the one panic this lint is warning
    // about -- division by zero -- is the branch immediately above. Unsigned division has no other
    // failure mode: the overflow case the lint also covers is `i64::MIN / -1`, which cannot arise
    // in `u64`. Both allows are scoped to this single expression.
    #[allow(clippy::integer_division, clippy::arithmetic_side_effects)]
    Ok(numerator / denominator)
}

/// Section 8.4 caps, applied at the stage each one belongs to.
///
/// Every field is a hard stop, not a warning. There is no "over the cap but probably fine" branch
/// anywhere that consumes this struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    // -- before parsing --------------------------------------------------------------------
    /// Cap on a single fetched object's compressed size, checked while streaming the download.
    pub max_compressed_bytes: u64,

    // -- during decompression --------------------------------------------------------------
    /// Cap on total uncompressed output, enforced streaming rather than after the fact.
    pub max_uncompressed_bytes: u64,
    /// Decompression ratio cap. A zip bomb is caught by this before the byte cap, because the
    /// byte cap alone would let a tiny archive consume the whole budget legitimately.
    pub max_expansion_ratio: u32,

    // -- during parsing --------------------------------------------------------------------
    /// Rows per page. A page that is not exactly this long, and is not the last, is a finding.
    pub max_rows_per_page: u64,
    /// Fields per row. Must equal the pinned column count exactly; this is the upper guard.
    pub max_fields_per_row: u32,
    /// Decoded size of one field, after unescaping. Checked post-decode: a short escaped field
    /// can decode large.
    pub max_field_bytes: u64,
    /// Elements in one `Array(T)`.
    pub max_array_elements: u32,
    /// Nesting depth for `Array`/`Tuple`/`Map`.
    pub max_nesting_depth: u32,

    // -- archives (deviation D6; not in the source plan) -------------------------------------
    /// Members permitted in one tar.
    pub max_tar_members: u32,
    /// Size of one tar member.
    pub max_tar_member_bytes: u64,
    /// Length of a tar member name.
    pub max_tar_name_bytes: u32,

    // -- payload decoding (section 8.6) ------------------------------------------------------
    /// Bounded decoding rounds (percent, HTML entity, `\uXXXX`, base64). Capped so the decoder
    /// does not become a decompression bomb by another name.
    pub max_decode_rounds: u32,
    /// Expansion permitted across all decoding rounds for one value.
    pub max_decode_expansion_ratio: u32,

    // -- host ---------------------------------------------------------------------------------
    /// Wall-clock budget for one query or one object transfer, in seconds.
    ///
    /// Enforced by us in the copy loop. Nothing in the HTTP stack provides a total budget: a
    /// per-read timeout resets on every read, so a slow-drip hostile server streams forever.
    pub wall_clock_secs: u64,
}

impl Limits {
    /// Check a running total against a cap, naming the cap in the finding.
    pub fn check_total(value: u64, cap: u64, what: &'static str) -> Result<()> {
        if value > cap {
            return abort("exceeded a section 8.4 limit").map_err(|e: SalvageError| {
                e.with("limit", what)
                    .with("cap", cap)
                    .with("observed", value)
            });
        }
        Ok(())
    }

    /// Check an expansion ratio without floating point.
    ///
    /// `output > input * ratio` is the test, computed as a checked multiply so a large `input`
    /// cannot wrap into a permissive comparison. A zero `input` with any output is a finding:
    /// output from nothing is not a ratio we can reason about.
    pub fn check_ratio(input: u64, output: u64, ratio: u32, what: &'static str) -> Result<()> {
        let ratio64 = u64::from(ratio);
        let permitted = input.checked_mul(ratio64).or_overflow(what)?;
        if output > permitted {
            return abort("exceeded the decompression ratio cap").map_err(|e: SalvageError| {
                e.with("limit", what)
                    .with("input_bytes", input)
                    .with("output_bytes", output)
                    .with("ratio_cap", ratio)
            });
        }
        Ok(())
    }
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
    fn or_overflow_turns_a_checked_none_into_a_finding() {
        let e = u64::MAX
            .checked_add(1)
            .or_overflow("page_bytes")
            .unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
        assert!(e.to_string().contains("page_bytes"), "{e}");
    }

    #[test]
    fn or_overflow_names_a_failed_narrowing() {
        let e = u8::try_from(300_u32)
            .or_overflow("field_count")
            .unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
        assert!(e.to_string().contains("field_count"), "{e}");
    }

    #[test]
    fn or_overflow_passes_success_through() {
        assert_eq!(2_u64.checked_add(2).or_overflow("x").unwrap(), 4);
    }

    #[test]
    fn div_floor_refuses_a_zero_divisor() {
        // Reachable in practice: a table whose measured bytes-per-row is zero.
        let e = div_floor(1024, 0, "rows_per_page").unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
        assert!(e.to_string().contains("rows_per_page"), "{e}");
    }

    #[test]
    fn div_floor_truncates_rather_than_rounding() {
        assert_eq!(div_floor(1000, 3, "x").unwrap(), 333);
    }

    #[test]
    fn a_total_at_the_cap_passes_and_one_over_it_aborts() {
        Limits::check_total(100, 100, "max_field_bytes").unwrap();
        let e = Limits::check_total(101, 100, "max_field_bytes").unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
        assert!(e.to_string().contains("max_field_bytes"), "{e}");
    }

    #[test]
    fn ratio_cap_catches_a_bomb() {
        Limits::check_ratio(10, 1000, 100, "expansion").unwrap();
        let e = Limits::check_ratio(10, 1001, 100, "expansion").unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
    }

    #[test]
    fn ratio_cap_does_not_wrap_on_a_huge_input() {
        // input * ratio overflows u64; that must be a finding, not a permissive comparison.
        let e = Limits::check_ratio(u64::MAX, 1, 100, "expansion").unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
    }

    #[test]
    fn limits_reject_an_unknown_field() {
        // A typo in a pinned override is a hard error, with no configuration required.
        let err = serde_json::from_str::<Limits>(r#"{"max_compressed_bytes": 1, "typo": 2}"#);
        assert!(err.is_err());
    }
}

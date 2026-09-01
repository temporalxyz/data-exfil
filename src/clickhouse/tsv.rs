//! Section 8.2: canonical TabSeparated escapes. Strict decode, canonical encode.
//!
//! ClickHouse's canonical TSV output escapes are the only ones accepted:
//!
//! ```text
//! \b \f \r \n \t \0 \' \\      and \N for NULL
//! ```
//!
//! **Every other backslash sequence rejects the row.** ClickHouse's *input* parser is permissive --
//! it accepts `\<any char>` as that character -- which means one value has several encodings.
//! Accepting that permissiveness would defeat canonicalisation entirely: two different byte
//! strings would validate, hash differently, and mean the same thing, so a payload could be
//! smuggled past a check that compares canonical forms. Raw control bytes inside a field also
//! reject.
//!
//! # `\N` is not `\\N`
//!
//! A true NULL is the two bytes `\` `N`. A *value* consisting of the two characters backslash and
//! N is written `\` `\` `N`. The distinction survives a round trip here, and a parser that
//! conflates them is wrong -- section 12 item 1 tests exactly this. `null` is also not `empty`:
//! an empty field is a zero-length value, never NULL.
//!
//! # Bytes, not `str`
//!
//! Everything here operates on `&[u8]`. The input is attacker-authored and must not be assumed to
//! be UTF-8 before that has been checked -- assuming it, and having the assumption be wrong, is
//! how a validator ends up rejecting on an encoding error at a point where it can no longer say
//! which column tripped.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]

use crate::abort::{Result, SalvageError, abort};

/// The two bytes that mean NULL on the wire.
const NULL_MARKER: &[u8] = b"\\N";

/// A decoded field: either SQL NULL, or a byte string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Null,
    Value(Vec<u8>),
}

impl Field {
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// The bytes, or `None` for NULL. Deliberately not `unwrap_or_default` anywhere: collapsing
    /// NULL to empty is the conflation this module exists to prevent.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Null => None,
            Self::Value(v) => Some(v),
        }
    }
}

/// Split a row into raw, still-escaped fields.
///
/// Splitting before decoding is what makes a raw tab unrepresentable inside a field: a real tab in
/// a value arrives as `\t` and is decoded afterwards, so it can never be mistaken for a delimiter.
#[must_use]
pub fn split_row(row: &[u8]) -> Vec<&[u8]> {
    row.split(|&b| b == b'\t').collect()
}

/// Decode one field, rejecting every non-canonical escape and every raw control byte.
pub fn decode_field(field: &[u8]) -> Result<Field> {
    if field == NULL_MARKER {
        return Ok(Field::Null);
    }

    let mut out = Vec::with_capacity(field.len());
    let mut bytes = field.iter().copied();

    while let Some(b) = bytes.next() {
        if b == b'\\' {
            let Some(escape) = bytes.next() else {
                // A bare trailing backslash. Section 12 item 2.
                return abort("bare trailing backslash in field");
            };
            let decoded = match escape {
                b'b' => 0x08,
                b'f' => 0x0C,
                b'r' => 0x0D,
                b'n' => 0x0A,
                b't' => 0x09,
                b'0' => 0x00,
                b'\'' => b'\'',
                b'\\' => b'\\',
                // Everything else, including `\a`, `\v`, `\x41`, and a `\N` that is not the whole
                // field. Reject, never normalise -- normalising is what would let two encodings
                // of one value both pass.
                other => {
                    return abort("non-canonical escape sequence").map_err(|e: SalvageError| {
                        e.with("escape", format!("\\{}", escape_for_display(other)))
                    });
                }
            };
            out.push(decoded);
        } else if b < 0x20 {
            // A raw control byte. Legitimate control characters arrive escaped; a raw one means
            // the framing is not what we believe it is.
            return abort("raw control byte in field")
                .map_err(|e: SalvageError| e.with("byte", format!("0x{b:02x}")));
        } else {
            out.push(b);
        }
    }

    Ok(Field::Value(out))
}

/// Encode one field into canonical form, for the regenerated files.
///
/// Original bytes are never copied forward (section 7): everything downstream is rebuilt from the
/// values we parsed, so this is the only writer.
#[must_use]
pub fn encode_field(field: &Field) -> Vec<u8> {
    let value = match field {
        Field::Null => return NULL_MARKER.to_vec(),
        Field::Value(v) => v,
    };

    let mut out = Vec::with_capacity(value.len());
    for &b in value {
        match b {
            0x08 => out.extend_from_slice(b"\\b"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x0D => out.extend_from_slice(b"\\r"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x00 => out.extend_from_slice(b"\\0"),
            b'\\' => out.extend_from_slice(b"\\\\"),
            other => out.push(other),
        }
    }
    out
}

/// Render a byte for a human-readable finding without ever emitting a raw control character into
/// the log.
fn escape_for_display(b: u8) -> String {
    if b.is_ascii_graphic() {
        // Infallible for a graphic ASCII byte.
        String::from_utf8(vec![b]).unwrap_or_else(|_| format!("0x{b:02x}"))
    } else {
        format!("0x{b:02x}")
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

    fn decoded(input: &[u8]) -> Field {
        decode_field(input).unwrap()
    }

    fn value(input: &[u8]) -> Vec<u8> {
        match decoded(input) {
            Field::Value(v) => v,
            Field::Null => panic!("expected a value, got NULL"),
        }
    }

    #[test]
    fn every_canonical_escape_decodes() {
        assert_eq!(value(br"\b"), vec![0x08]);
        assert_eq!(value(br"\f"), vec![0x0C]);
        assert_eq!(value(br"\r"), vec![0x0D]);
        assert_eq!(value(br"\n"), vec![0x0A]);
        assert_eq!(value(br"\t"), vec![0x09]);
        assert_eq!(value(br"\0"), vec![0x00]);
        assert_eq!(value(br"\'"), b"'".to_vec());
        assert_eq!(value(br"\\"), b"\\".to_vec());
    }

    #[test]
    fn a_bare_null_marker_is_null_and_an_empty_field_is_not() {
        assert!(decoded(b"\\N").is_null());
        // null != empty. Collapsing these is the conflation section 8.2 calls out.
        assert!(!decoded(b"").is_null());
        assert_eq!(value(b""), Vec::<u8>::new());
    }

    #[test]
    fn a_literal_backslash_n_survives_as_a_value() {
        // Section 12 item 1: Nullable(String) containing the two characters \N.
        let field = decoded(br"\\N");
        assert!(!field.is_null(), "\\\\N is a value, not NULL");
        assert_eq!(field.bytes(), Some(&b"\\N"[..]));
    }

    #[test]
    fn a_null_marker_mid_field_is_rejected_rather_than_normalised() {
        let e = decode_field(br"abc\Ndef").unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
    }

    #[test]
    fn alternative_escapes_reject() {
        // Section 12 item 2: reject, never normalise.
        for bad in [&br"\a"[..], &br"\v"[..], &br"\x41"[..], &br"\q"[..]] {
            let e = decode_field(bad).unwrap_err();
            assert_eq!(e.exit_code(), ExitCode::Abort, "{bad:?} must reject");
        }
    }

    #[test]
    fn a_bare_trailing_backslash_rejects() {
        let e = decode_field(br"abc\").unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::Abort);
    }

    #[test]
    fn raw_control_bytes_reject() {
        for raw in [0x00_u8, 0x09, 0x0A, 0x0D, 0x1F] {
            let e = decode_field(&[b'a', raw, b'b']).unwrap_err();
            assert_eq!(
                e.exit_code(),
                ExitCode::Abort,
                "raw 0x{raw:02x} must reject"
            );
        }
    }

    #[test]
    fn a_finding_never_puts_a_raw_control_byte_in_the_message() {
        let e = decode_field(&[b'a', 0x07, b'b']).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("0x07"), "{msg}");
        assert!(!msg.as_bytes().contains(&0x07), "log must stay printable");
    }

    #[test]
    fn a_row_splits_on_tabs_and_an_escaped_tab_is_not_a_delimiter() {
        let fields = split_row(b"a\tb\tc");
        assert_eq!(fields.len(), 3);

        // A real tab inside a value arrives escaped, so it survives splitting intact.
        let fields = split_row(br"one\ttwo\tthree");
        assert_eq!(fields.len(), 1);
        assert_eq!(value(fields[0]), b"one\ttwo\tthree".to_vec());
    }

    #[test]
    fn encode_round_trips_every_decoded_value() {
        for original in [
            &b""[..],
            &b"plain"[..],
            &b"\\N"[..],
            &[0x00, 0x08, 0x09, 0x0A, 0x0C, 0x0D][..],
            &b"tab\there"[..],
            &b"back\\slash"[..],
        ] {
            let field = Field::Value(original.to_vec());
            let encoded = encode_field(&field);
            assert_eq!(decode_field(&encoded).unwrap(), field, "{original:?}");
        }
    }

    #[test]
    fn null_round_trips_and_does_not_collide_with_a_literal() {
        assert_eq!(encode_field(&Field::Null), b"\\N".to_vec());
        assert_eq!(
            decode_field(&encode_field(&Field::Null)).unwrap(),
            Field::Null
        );

        let literal = Field::Value(b"\\N".to_vec());
        assert_eq!(encode_field(&literal), b"\\\\N".to_vec());
        assert_ne!(encode_field(&literal), encode_field(&Field::Null));
    }

    #[test]
    fn encoded_output_contains_no_raw_control_bytes() {
        let field = Field::Value(vec![0x00, 0x09, 0x0A, 0x0D]);
        let encoded = encode_field(&field);
        assert!(
            encoded.iter().all(|&b| b >= 0x20),
            "canonical output must escape every control byte"
        );
    }
}

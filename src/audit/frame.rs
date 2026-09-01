//! Section 8.1 framing, over an archive rather than a bare `.tsv.gz` (deviation D6).
//!
//! Four rules, verbatim:
//!
//! > - Exactly one gzip member, with no trailing bytes after it.
//! > - Header row must match the expected column list exactly, in order.
//! > - Field count per row must equal the expected count exactly.
//! > - Any parse error is fatal to the row. No error is skipped, defaulted or repaired.
//!
//! The gzip and tar halves live in [`crate::archive`], which is where the `bufread::GzDecoder`
//! subtlety is documented. What is here is the TSV half: the header, the field counts, and section
//! 8.2's escape decoding -- which runs over `&[u8]`, because the input is attacker-authored bytes
//! and must not be assumed UTF-8 before it has been checked.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]
use crate::abort::{Result, SalvageError, abort};
use crate::archive::read_targz;
use crate::clickhouse::tsv::{self, Field};
use crate::limits::Limits;

/// One page, unpacked and framed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedPage {
    /// The column names as the file declared them, already checked against the expectation.
    pub header: Vec<String>,
    /// Rows of decoded fields. Section 8.2 has already run: `\N` is [`Field::Null`], every other
    /// escape is canonical or the row aborted.
    pub rows: Vec<Vec<Field>>,
    /// The page's own metadata member, **parsed**.
    ///
    /// Parsed rather than carried as bytes, because whatever the audit emits is regenerated from
    /// this value. Carrying the member's bytes made it the one input byte range that reached the
    /// clean bucket unexamined.
    pub metadata: crate::models::PageMeta,
}

/// Unpack and frame one `page-NNNN.tar.gz`.
pub fn frame(archive: &[u8], expected: &[String], limits: &Limits) -> Result<FramedPage> {
    let members = read_targz(archive, limits)?;

    let tsv_member = members
        .iter()
        .find(|m| m.name.ends_with(".tsv"))
        .ok_or_else(|| {
            abort::<()>("the archive has no .tsv member")
                .unwrap_err()
                .with("members", members.len())
        })?;
    let meta_member = members
        .iter()
        .find(|m| m.name.ends_with(".json"))
        .ok_or_else(|| abort::<()>("the archive has no .json member").unwrap_err())?;
    // Parsed through `deny_unknown_fields`, so an extra key is a finding rather than a passenger.
    let metadata: crate::models::PageMeta =
        serde_json::from_slice(&meta_member.bytes).map_err(|e| {
            abort::<()>("the page metadata does not parse")
                .unwrap_err()
                .with("error", e)
        })?;

    // Exactly two members, and both accounted for. A third would be something we did not write.
    if members.len() != 2 {
        return abort("the archive has unexpected members").map_err(|e: SalvageError| {
            e.with("count", members.len()).with(
                "names",
                members
                    .iter()
                    .map(|m| m.name.clone())
                    .collect::<Vec<_>>()
                    .join(","),
            )
        });
    }

    frame_tsv(&tsv_member.bytes, expected, limits).map(|(header, rows)| FramedPage {
        header,
        rows,
        metadata,
    })
}

/// The TSV half, split out so it can be tested without building an archive.
pub fn frame_tsv(
    bytes: &[u8],
    expected: &[String],
    limits: &Limits,
) -> Result<(Vec<String>, Vec<Vec<Field>>)> {
    // Strip exactly one trailing newline before splitting. `split` yields a trailing empty
    // element for a file that ends in `\n`, which every well-formed page does -- but skipping
    // *every* empty line to absorb it was too broad. For a single-column projection an empty
    // string is a legal value and renders as an empty line, so the skip silently dropped that row
    // and undercounted the page; for a wider projection an empty line is a one-field row, which
    // the exact-width check below is supposed to reject and instead never saw. Removing one known
    // terminator here leaves every remaining empty line to be judged on its field count.
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let mut lines = body.split(|b| *b == b'\n');

    let header_line = lines
        .next()
        .ok_or_else(|| abort::<()>("the page is empty").unwrap_err())?;
    // A `\r` here would mean the file went through something that rewrote line endings, which is
    // a different file from the one we hashed.
    if header_line.last() == Some(&b'\r') {
        return abort("the page header carries a carriage return").map_err(|e: SalvageError| {
            e.with("reason", "the file was rewritten between export and audit")
        });
    }

    let header: Vec<String> = tsv::split_row(header_line)
        .into_iter()
        .map(|f| String::from_utf8_lossy(f).into_owned())
        .collect();
    if header != expected {
        return abort("the page header does not match the expected column list").map_err(
            |e: SalvageError| {
                e.with("expected", expected.join("\t"))
                    .with("got", header.join("\t"))
            },
        );
    }

    let width = expected.len();
    // The exact-width check below is stricter, but the pinned cap is an independent upper guard:
    // if the expectation itself were ever built wrong, this is what stops a 10,000-column row
    // being parsed at all.
    if u64::try_from(width).unwrap_or(u64::MAX) > u64::from(limits.max_fields_per_row) {
        return abort("the expected column count exceeds the pinned field cap").map_err(
            |e: SalvageError| {
                e.with("columns", width)
                    .with("cap", limits.max_fields_per_row)
            },
        );
    }
    let mut rows = Vec::new();
    for (i, line) in lines.enumerate() {
        let row_no = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
        if u64::try_from(rows.len()).unwrap_or(u64::MAX) >= limits.max_rows_per_page {
            return abort("the page exceeds the pinned row cap")
                .map_err(|e: SalvageError| e.with("cap", limits.max_rows_per_page));
        }

        let raw = tsv::split_row(line);
        if raw.len() != width {
            return abort("row has the wrong field count").map_err(|e: SalvageError| {
                e.with("row", row_no)
                    .with("expected", width)
                    .with("got", raw.len())
            });
        }

        let mut fields = Vec::with_capacity(width);
        for (col, field) in raw.into_iter().enumerate() {
            // Section 8.2 decoding. Any parse error is fatal to the row, and a fatal row is a dead
            // batch -- nothing is skipped, defaulted or repaired.
            let decoded = tsv::decode_field(field).map_err(|e| {
                e.with("row", row_no)
                    .with("column", expected.get(col).cloned().unwrap_or_default())
            })?;
            if let Some(bytes) = decoded.bytes() {
                let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                if len > limits.max_field_bytes {
                    // Post-decode, deliberately: a short escaped field can decode large.
                    return abort("decoded field exceeds the pinned size cap").map_err(
                        |e: SalvageError| {
                            e.with("row", row_no)
                                .with("column", expected.get(col).cloned().unwrap_or_default())
                                .with("bytes", len)
                                .with("cap", limits.max_field_bytes)
                        },
                    );
                }
            }
            fields.push(decoded);
        }
        rows.push(fields);
    }

    Ok((header, rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clickhouse::tsv::Field;

    fn limits() -> Limits {
        let toml = std::fs::read_to_string("overrides/typematrix.typematrix.toml").unwrap();
        let o: crate::models::Overrides = toml::from_str(&toml).unwrap();
        o.limits
    }

    fn cols(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("c{i}")).collect()
    }

    #[test]
    fn a_well_formed_page_parses_with_the_trailing_newline_consumed() {
        let (header, rows) = frame_tsv(b"c0\tc1\n1\ta\n2\tb\n", &cols(2), &limits()).unwrap();
        assert_eq!(header, cols(2));
        assert_eq!(rows.len(), 2, "the trailing newline is not a row");
    }

    #[test]
    fn a_page_without_a_trailing_newline_parses_identically() {
        let (_, rows) = frame_tsv(b"c0\tc1\n1\ta\n2\tb", &cols(2), &limits()).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn an_empty_value_in_a_single_column_page_is_a_row_and_not_a_dropped_one() {
        // This is the bug the blank-line skip caused. With one exported column an empty string is
        // a legal value and renders as an empty line. Skipping it dropped the row from the count
        // -- and on the export side an undercounted full page looks short, which ends the run with
        // the rest of the table unread.
        let (_, rows) = frame_tsv(b"c0\n1\n\n3\n", &cols(1), &limits()).unwrap();
        assert_eq!(rows.len(), 3, "the empty-string row must survive");
        assert_eq!(rows[1][0], Field::Value(Vec::new()));
        // And section 8.2's null-is-not-empty distinction still holds through the frame.
        let (_, nulls) = frame_tsv(b"c0\n\\N\n\n", &cols(1), &limits()).unwrap();
        assert_eq!(nulls[0][0], Field::Null);
        assert_eq!(nulls[1][0], Field::Value(Vec::new()));
    }

    #[test]
    fn an_interior_blank_line_in_a_wide_page_is_a_field_count_finding() {
        // Previously skipped in silence. ClickHouse never emits a blank line, so one is either
        // tampering or a rewritten file -- and section 8.1 says any parse error is fatal to the
        // row, with nothing skipped, defaulted or repaired.
        let err = frame_tsv(b"c0\tc1\n1\ta\n\n2\tb\n", &cols(2), &limits())
            .err()
            .unwrap_or_else(|| panic!("a blank line in a two-column page must be refused"));
        assert!(err.to_string().contains("wrong field count"), "{err}");
    }

    #[test]
    fn a_header_that_does_not_match_the_expected_columns_is_refused() {
        let err = frame_tsv(b"c1\tc0\n1\ta\n", &cols(2), &limits())
            .err()
            .unwrap_or_else(|| panic!("a reordered header must be refused"));
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn a_header_carrying_a_carriage_return_is_refused() {
        let err = frame_tsv(b"c0\tc1\r\n1\ta\n", &cols(2), &limits())
            .err()
            .unwrap_or_else(|| panic!("a rewritten line ending must be refused"));
        assert!(err.to_string().contains("carriage return"), "{err}");
    }

    #[test]
    fn a_row_with_too_many_or_too_few_fields_is_refused_in_both_directions() {
        for page in [&b"c0\tc1\n1\ta\textra\n"[..], &b"c0\tc1\n1\n"[..]] {
            let err = frame_tsv(page, &cols(2), &limits())
                .err()
                .unwrap_or_else(|| panic!("wrong width must be refused"));
            assert!(err.to_string().contains("wrong field count"), "{err}");
        }
    }

    #[test]
    fn a_non_canonical_escape_is_fatal_to_the_row_rather_than_repaired() {
        let err = frame_tsv(b"c0\n\\a\n", &cols(1), &limits())
            .err()
            .unwrap_or_else(|| panic!("section 8.2 forbids `\\a`"));
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Abort, "{err}");
    }

    #[test]
    fn the_row_cap_is_enforced() {
        let mut lim = limits();
        lim.max_rows_per_page = 2;
        let err = frame_tsv(b"c0\n1\n2\n3\n", &cols(1), &lim)
            .err()
            .unwrap_or_else(|| panic!("the row cap must fire"));
        assert!(err.to_string().contains("row cap"), "{err}");
    }

    #[test]
    fn an_expectation_wider_than_the_pinned_field_cap_is_refused() {
        let mut lim = limits();
        lim.max_fields_per_row = 2;
        let err = frame_tsv(b"c0\tc1\tc2\n", &cols(3), &lim)
            .err()
            .unwrap_or_else(|| panic!("the field cap must fire"));
        assert!(err.to_string().contains("field cap"), "{err}");
    }

    #[test]
    fn a_decoded_field_over_the_pinned_size_cap_is_refused() {
        let mut lim = limits();
        lim.max_field_bytes = 4;
        let err = frame_tsv(b"c0\nabcdefgh\n", &cols(1), &lim)
            .err()
            .unwrap_or_else(|| panic!("the field size cap must fire"));
        assert!(err.to_string().contains("field"), "{err}");
    }
}

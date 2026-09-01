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
    /// The page's own metadata member, unparsed.
    pub metadata: Vec<u8>,
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
    let metadata = members
        .iter()
        .find(|m| m.name.ends_with(".json"))
        .map(|m| m.bytes.clone())
        .ok_or_else(|| abort::<()>("the archive has no .json member").unwrap_err())?;

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
    let mut lines = bytes.split(|b| *b == b'\n');

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
        if line.is_empty() {
            continue;
        }
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

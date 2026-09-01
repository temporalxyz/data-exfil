//! Hostile tar reading, safe tar writing, and the section 8.1 gzip framing check (deviation D6).
//!
//! The source plan predates tarballs -- it moves bare `.tsv.gz` files -- so packing a page's TSV
//! together with its `PAGE.json` adds a framing surface the document never analysed. D6 is that
//! admission, and this module is the mitigation.
//!
//! # Reject, never sanitise
//!
//! Section 8.1's rule for gzip applies unchanged to tar: *"Any parse error is fatal to the row. No
//! error is skipped, defaulted or repaired."* The `tar` crate hands over raw header fields and does
//! no path rewriting on iteration (only `unpack` sanitises, and nothing here calls it), so
//! rejection is the only behaviour available -- which is what we want. A Python design would have
//! had to work around `tarfile`'s data filter quietly fixing member paths.
//!
//! # The gzip check that fails open if written the obvious way
//!
//! Section 8.1 requires **exactly one gzip member and no trailing bytes**, because *"Concatenated
//! members and trailing data are a smuggling path -- a scanner may read the first member while a
//! decompressor emits all."*
//!
//! `flate2::read::GzDecoder` cannot express that check. It wraps the reader in a private 32 KiB
//! `BufReader` and `into_inner()` **discards the read-ahead**, so "is the underlying reader at
//! EOF?" answers yes even when megabytes of smuggled data follow. flate2's own rustdoc says the
//! decoder "may have read past the end of the gzip data". [`read_single_gzip_member`] uses
//! `bufread::GzDecoder` over our own `BufReader` and checks `fill_buf()?.is_empty()`, which
//! consumes exactly the member and nothing more.
//!
//! Two further details in that function are load-bearing: the reader is driven to `Ok(0)` so the
//! CRC32 **and** ISIZE trailer checks actually run, and `MultiGzDecoder` is never used because it
//! would happily consume concatenated members -- it is the smuggling path with a type name.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division
)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::Path;

use crate::abort::{PartialOutput, Result, SalvageError, abort};
use crate::limits::{Limits, OrOverflow as _};

/// One file inside an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMember {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Member names we generate and accept: `^[A-Za-z0-9_./-]{1,128}$`, with no traversal.
///
/// Names are generated from a local counter, never from data, so this is a backstop rather than
/// the primary control -- but it is the backstop that makes a slip loud instead of exploitable.
fn validate_member_name(name: &[u8], limits: &Limits) -> Result<String> {
    let max = usize::try_from(limits.max_tar_name_bytes).or_overflow("name_cap->usize")?;
    let bad = |why: &'static str| -> SalvageError {
        abort::<()>("archive member name rejected")
            .unwrap_err()
            .with("name", String::from_utf8_lossy(name).escape_debug())
            .with("reason", why)
    };

    if name.is_empty() {
        return Err(bad("empty"));
    }
    if name.len() > max {
        return Err(bad("longer than the pinned name cap"));
    }
    if name.first() == Some(&b'/') {
        return Err(bad("absolute path"));
    }
    if name.last() == Some(&b'/') {
        return Err(bad("directory entry; only regular files are carried"));
    }
    for byte in name {
        let ok = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/');
        if !ok {
            return Err(bad("character outside [A-Za-z0-9_./-]"));
        }
    }
    let text = std::str::from_utf8(name).map_err(|_| bad("not UTF-8"))?;
    for component in text.split('/') {
        if component.is_empty() {
            return Err(bad("empty path component"));
        }
        if component == ".." || component == "." {
            return Err(bad("relative path component"));
        }
    }
    // A backslash is not a separator on our hosts, which is exactly why it is refused: a consumer
    // on another platform would read `..\` as traversal that we had declared safe.
    if text.contains('\\') {
        return Err(bad("backslash"));
    }
    Ok(text.to_owned())
}

/// Write members into a `.tar.gz` with exactly one gzip member.
///
/// The archive is deterministic: mtime, uid, gid and mode are fixed, and members are written in
/// sorted order. Two runs producing byte-identical input must produce byte-identical output, or
/// the two-pass diff in `export/diff.rs` compares timestamps instead of data.
pub fn write_targz(dest: &Path, members: &[ArchiveMember], limits: &Limits) -> Result<()> {
    let count = u32::try_from(members.len()).or_overflow("member_count->u32")?;
    if count > limits.max_tar_members {
        return abort("archive would exceed the pinned member cap").map_err(|e: SalvageError| {
            e.with("members", count).with("cap", limits.max_tar_members)
        });
    }

    let mut sorted: Vec<&ArchiveMember> = members.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    for pair in sorted.windows(2) {
        if let [a, b] = pair
            && a.name == b.name
        {
            return abort("duplicate member name")
                .map_err(|e: SalvageError| e.with("name", a.name.escape_debug()));
        }
    }

    let mut guard = PartialOutput::new(dest.with_extension("partial"));
    let file = std::fs::File::create(guard.path()).map_err(|e| {
        crate::abort::infra::<()>(format!("could not create the archive: {e}")).unwrap_err()
    })?;
    // Compression level 9 and no gzip filename/mtime field, so the output is a pure function of
    // the input bytes.
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::best());
    let mut tar = tar::Builder::new(gz);

    for member in sorted {
        let name = validate_member_name(member.name.as_bytes(), limits)?;
        let len = u64::try_from(member.bytes.len()).or_overflow("member_len->u64")?;
        if len > limits.max_tar_member_bytes {
            return abort("member would exceed the pinned per-member cap")
                .map_err(|e: SalvageError| e.with("name", name).with("bytes", len));
        }

        let mut header = tar::Header::new_ustar();
        header.set_size(len);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header
            .set_path(&name)
            .map_err(|e| abort::<()>(format!("could not set member path: {e}")).unwrap_err())?;
        header.set_cksum();
        tar.append(&header, member.bytes.as_slice())
            .map_err(|e| abort::<()>(format!("could not append member: {e}")).unwrap_err())?;
    }

    let gz = tar
        .into_inner()
        .map_err(|e| abort::<()>(format!("could not finish the tar: {e}")).unwrap_err())?;
    let mut file = gz
        .finish()
        .map_err(|e| abort::<()>(format!("could not finish the gzip: {e}")).unwrap_err())?;
    file.flush()
        .map_err(|e| abort::<()>(format!("could not flush the archive: {e}")).unwrap_err())?;
    drop(file);

    guard.commit_as(dest)
}

/// Decompress **exactly one** gzip member and assert nothing follows it.
///
/// See the module header for why this cannot be written with `flate2::read::GzDecoder`.
pub fn read_single_gzip_member(bytes: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    let compressed = u64::try_from(bytes.len()).or_overflow("compressed->u64")?;
    if compressed > limits.max_compressed_bytes {
        return abort("compressed input exceeds the pinned cap").map_err(|e: SalvageError| {
            e.with("bytes", compressed)
                .with("cap", limits.max_compressed_bytes)
        });
    }

    let mut source = BufReader::new(bytes);
    let mut decoder = flate2::bufread::GzDecoder::new(&mut source);

    // Streaming, so the ratio and byte caps bite before the memory is spent rather than after.
    // Section 8.4 puts both at "during decompression" for exactly this reason.
    let mut out = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = decoder
            .read(&mut chunk)
            .map_err(|e| abort::<()>(format!("gzip stream is not readable: {e}")).unwrap_err())?;
        // Driving to Ok(0) is what makes the CRC32 and ISIZE trailer checks run at all. Stopping
        // when we have "enough" bytes would skip them.
        if n == 0 {
            break;
        }
        let total = u64::try_from(out.len().checked_add(n).or_overflow("out_len")?)
            .or_overflow("out->u64")?;
        if total > limits.max_uncompressed_bytes {
            return abort("decompressed output exceeds the pinned cap").map_err(
                |e: SalvageError| {
                    e.with("bytes", total)
                        .with("cap", limits.max_uncompressed_bytes)
                },
            );
        }
        if compressed > 0 {
            let ratio = crate::limits::div_floor(total, compressed, "expansion_ratio")?;
            if ratio > u64::from(limits.max_expansion_ratio) {
                return abort("decompression ratio exceeds the pinned cap").map_err(
                    |e: SalvageError| {
                        e.with("ratio", ratio)
                            .with("cap", limits.max_expansion_ratio)
                    },
                );
            }
        }
        out.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    }

    // The whole point of `bufread::GzDecoder`: it consumed exactly the member, so anything left in
    // the buffer is smuggled. `read::GzDecoder` would have discarded its read-ahead and answered
    // "empty" here regardless.
    let rest = decoder.into_inner();
    let trailing = rest.fill_buf().map_err(|e| {
        abort::<()>(format!("could not check for trailing bytes: {e}")).unwrap_err()
    })?;
    if !trailing.is_empty() {
        return abort("bytes follow the gzip member").map_err(|e: SalvageError| {
            e.with("trailing_bytes", trailing.len()).with(
                "reason",
                "section 8.1: a scanner may read the first member while a decompressor emits all",
            )
        });
    }

    Ok(out)
}

/// Read a `.tar.gz` under every pinned cap, rejecting anything that is not a plain regular file.
pub fn read_targz(bytes: &[u8], limits: &Limits) -> Result<Vec<ArchiveMember>> {
    let tar_bytes = read_single_gzip_member(bytes, limits)?;
    read_tar(&tar_bytes, limits)
}

/// Read an uncompressed tar under every pinned cap.
pub fn read_tar(bytes: &[u8], limits: &Limits) -> Result<Vec<ArchiveMember>> {
    let mut archive = tar::Archive::new(bytes);
    // `raw(true)` stops the crate absorbing GNU long-name (`L`), long-link (`K`) and PAX (`x`)
    // records into the entry that follows them. Absorbed, they are an invisible second name for a
    // member; yielded raw, they arrive as entries whose type is not `Regular` and are refused
    // below by name. That is the stricter reading and the one this tool wants: we generate these
    // archives, so an extension record in one is not something to interpret.
    //
    // Note `entries()` does not absorb `g` (global PAX) at all, and absorbs `L` only for
    // ustar/GNU magic -- an `L` record in a v7 header is yielded verbatim either way. Refusing on
    // entry type rather than on absorption is what makes that difference not matter.
    let entries = archive
        .entries()
        .map_err(|e| abort::<()>(format!("tar is not readable: {e}")).unwrap_err())?
        .raw(true);

    let mut out: Vec<ArchiveMember> = Vec::new();
    let mut total: u64 = 0;

    for entry in entries {
        let mut entry = entry
            .map_err(|e| abort::<()>(format!("tar entry is not readable: {e}")).unwrap_err())?;

        let count = u32::try_from(out.len().checked_add(1).or_overflow("member_count")?)
            .or_overflow("member_count->u32")?;
        if count > limits.max_tar_members {
            return abort("tar exceeds the pinned member cap")
                .map_err(|e: SalvageError| e.with("cap", limits.max_tar_members));
        }

        let kind = entry.header().entry_type();
        if !kind.is_file() {
            // Symlinks, hardlinks, devices, FIFOs, directories, and the GNU/PAX extension records.
            // An `L` (GNU long name) record inside a v7 header is yielded verbatim rather than
            // absorbed, which is a real evasion surface and is why this is a whitelist.
            return abort("tar member is not a regular file").map_err(|e: SalvageError| {
                e.with("type_byte", kind.as_byte()).with(
                    "reason",
                    "only regular files are carried; nothing is followed",
                )
            });
        }

        // Under `raw(true)` the crate does no merging, so these must agree. Asserted rather than
        // assumed: if a future change turns raw off, a PAX record overriding the header name would
        // otherwise become an invisible second name for the member -- and a scanner reading one
        // while an extractor uses the other is the whole game.
        let raw = entry.header().path_bytes().to_vec();
        let merged = entry.path_bytes().to_vec();
        if raw != merged {
            return abort("tar member has two disagreeing names").map_err(|e: SalvageError| {
                e.with("header", String::from_utf8_lossy(&raw).escape_debug())
                    .with("merged", String::from_utf8_lossy(&merged).escape_debug())
            });
        }
        let name = validate_member_name(&raw, limits)?;

        // The size the header claims, checked before a byte is read.
        let claimed = entry
            .header()
            .size()
            .map_err(|e| abort::<()>(format!("tar member size is unreadable: {e}")).unwrap_err())?;
        if claimed > limits.max_tar_member_bytes {
            return abort("tar member exceeds the pinned per-member cap").map_err(
                |e: SalvageError| {
                    e.with("name", name)
                        .with("claimed", claimed)
                        .with("cap", limits.max_tar_member_bytes)
                },
            );
        }
        total = total.checked_add(claimed).or_overflow("tar_total")?;
        if total > limits.max_uncompressed_bytes {
            return abort("tar total exceeds the pinned uncompressed cap")
                .map_err(|e: SalvageError| e.with("cap", limits.max_uncompressed_bytes));
        }

        if out.iter().any(|m| m.name == name) {
            // Two members with one name: an extractor keeps the last, a scanner may read the
            // first, and the two disagree about what was delivered.
            return abort("duplicate tar member name")
                .map_err(|e: SalvageError| e.with("name", name));
        }

        let mut body = Vec::new();
        entry
            .read_to_end(&mut body)
            .map_err(|e| abort::<()>(format!("tar member is not readable: {e}")).unwrap_err())?;
        let actual = u64::try_from(body.len()).or_overflow("body_len->u64")?;
        if actual != claimed {
            // A header that lies about its size. The crate stops at the claimed length, so a
            // larger real body would silently become the next header.
            return abort("tar member size disagrees with its header").map_err(
                |e: SalvageError| {
                    e.with("name", name)
                        .with("claimed", claimed)
                        .with("actual", actual)
                },
            );
        }

        out.push(ArchiveMember { name, bytes: body });
    }

    if out.is_empty() {
        return abort("tar contains no members").map_err(|e: SalvageError| {
            e.with(
                "reason",
                "an empty archive and a missing one are different facts",
            )
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{
        TarForge, gzip, gzip_bomb, gzip_concatenated, gzip_with_trailing, typeflag,
    };

    fn limits() -> Limits {
        Limits {
            max_compressed_bytes: 1024 * 1024,
            max_uncompressed_bytes: 8 * 1024 * 1024,
            max_expansion_ratio: 100,
            max_rows_per_page: 1000,
            max_fields_per_row: 64,
            max_field_bytes: 1024,
            max_array_elements: 16,
            max_nesting_depth: 8,
            max_tar_members: 4,
            max_tar_member_bytes: 1024 * 1024,
            max_tar_name_bytes: 128,
            max_decode_rounds: 1,
            max_decode_expansion_ratio: 8,
            wall_clock_secs: 60,
        }
    }

    fn members() -> Vec<ArchiveMember> {
        vec![
            ArchiveMember {
                name: "page-0000.tsv".to_owned(),
                bytes: b"id\tbody\n1\tx\n".to_vec(),
            },
            ArchiveMember {
                name: "PAGE.json".to_owned(),
                bytes: b"{\"rows\":1}".to_vec(),
            },
        ]
    }

    // -- the round trip ---------------------------------------------------------------------

    #[test]
    fn a_written_archive_reads_back_identically_and_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.tar.gz");
        let b = dir.path().join("b.tar.gz");
        write_targz(&a, &members(), &limits()).unwrap();
        write_targz(&b, &members(), &limits()).unwrap();

        let bytes_a = std::fs::read(&a).unwrap();
        // Byte-identical output for identical input, or the two-pass diff compares timestamps
        // instead of data and aborts on every page.
        assert_eq!(bytes_a, std::fs::read(&b).unwrap());

        let read = read_targz(&bytes_a, &limits()).unwrap();
        // Sorted on write, so the order is a property of the names and not of the caller.
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].name, "PAGE.json");
        assert_eq!(read[1].name, "page-0000.tsv");
        assert_eq!(read[1].bytes, b"id\tbody\n1\tx\n");
    }

    #[test]
    fn a_failed_write_leaves_no_partial_archive() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("page.tar.gz");
        let oversized = vec![ArchiveMember {
            name: "big".to_owned(),
            bytes: vec![0u8; 4096],
        }];
        let mut small = limits();
        small.max_tar_member_bytes = 16;
        assert!(write_targz(&dest, &oversized, &small).is_err());
        assert!(!dest.exists());
        assert!(!dest.with_extension("partial").exists());
    }

    // -- section 8.1 gzip framing ------------------------------------------------------------

    #[test]
    fn concatenated_gzip_members_are_refused() {
        // The smuggling path section 8.1 names: a scanner may read the first member while a
        // decompressor emits all. `MultiGzDecoder` would consume both without complaint.
        let bytes = gzip_concatenated(b"benign", b"smuggled");
        let err = read_single_gzip_member(&bytes, &limits()).unwrap_err();
        assert!(err.to_string().contains("follow the gzip member"), "{err}");
    }

    #[test]
    fn trailing_bytes_after_a_gzip_member_are_refused() {
        // The check that fails open if written with `flate2::read::GzDecoder`, whose `into_inner()`
        // discards a private 32 KiB read-ahead. Under 32 KiB of trailing data is exactly the range
        // that variant would have missed.
        for trailing in [&b"x"[..], &[0u8; 4096][..], &[0u8; 40_000][..]] {
            let bytes = gzip_with_trailing(b"page bytes", trailing);
            assert!(
                read_single_gzip_member(&bytes, &limits()).is_err(),
                "{} trailing bytes slipped through",
                trailing.len()
            );
        }
    }

    #[test]
    fn a_clean_single_member_round_trips() {
        let bytes = gzip(b"exactly these bytes");
        assert_eq!(
            read_single_gzip_member(&bytes, &limits()).unwrap(),
            b"exactly these bytes"
        );
    }

    #[test]
    fn a_corrupt_trailer_is_refused_because_the_reader_is_driven_to_eof() {
        // CRC32 and ISIZE are only verified on the read *after* the deflate stream ends. Stopping
        // when we have the bytes we wanted would skip both checks entirely.
        let mut bytes = gzip(b"page bytes");
        let n = bytes.len();
        bytes[n - 5] ^= 0xFF;
        assert!(read_single_gzip_member(&bytes, &limits()).is_err());
    }

    #[test]
    fn a_decompression_bomb_is_caught_streaming_by_the_ratio_cap() {
        // The byte cap alone would let a tiny archive spend the whole budget legitimately; the
        // ratio is what identifies it as a bomb. Both are enforced during decompression, not after.
        let bomb = gzip_bomb(4 * 1024 * 1024);
        let err = read_single_gzip_member(&bomb, &limits()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ratio") || msg.contains("uncompressed"),
            "{msg}"
        );
    }

    #[test]
    fn an_oversized_compressed_input_is_refused_before_it_is_parsed() {
        // Section 8.4 puts the compressed cap at "before parsing" for a reason.
        let mut tiny = limits();
        tiny.max_compressed_bytes = 8;
        assert!(read_single_gzip_member(&gzip(b"more than eight bytes"), &tiny).is_err());
    }

    // -- deviation D6: hostile tar -------------------------------------------------------------

    #[test]
    fn every_non_regular_member_type_is_refused() {
        for (label, bytes) in [
            (
                "symlink",
                TarForge::new().symlink("a", "/etc/passwd").finish(),
            ),
            (
                "hardlink",
                TarForge::new().hardlink("a", "/etc/shadow").finish(),
            ),
            (
                "char device",
                TarForge::new()
                    .typed("a", &[], typeflag::CHAR_DEVICE)
                    .finish(),
            ),
            (
                "block device",
                TarForge::new()
                    .typed("a", &[], typeflag::BLOCK_DEVICE)
                    .finish(),
            ),
            (
                "fifo",
                TarForge::new().typed("a", &[], typeflag::FIFO).finish(),
            ),
            (
                "directory",
                TarForge::new()
                    .typed("d/", &[], typeflag::DIRECTORY)
                    .finish(),
            ),
            (
                "global pax",
                TarForge::new()
                    .typed("g", b"20 comment=hi\n", typeflag::PAX_GLOBAL)
                    .finish(),
            ),
        ] {
            let err = read_tar(&bytes, &limits())
                .err()
                .unwrap_or_else(|| panic!("{label} was accepted"));
            assert!(
                err.to_string().contains("not a regular file"),
                "{label}: {err}"
            );
        }
    }

    #[test]
    fn traversal_and_absolute_paths_are_refused() {
        for name in [
            "/etc/passwd",
            "../../etc/passwd",
            "a/../../b",
            "./a",
            "a//b",
            "a\\b",
            "a/",
        ] {
            let bytes = TarForge::new().file(name, b"x").finish();
            assert!(
                read_tar(&bytes, &limits()).is_err(),
                "{name} must not be accepted"
            );
        }
    }

    #[test]
    fn a_name_outside_the_charset_is_refused() {
        for name in ["a b", "a;b", "a'b", "a\nb", "café"] {
            let bytes = TarForge::new().file(name, b"x").finish();
            assert!(read_tar(&bytes, &limits()).is_err(), "{name:?}");
        }
    }

    #[test]
    fn a_gnu_long_name_record_cannot_rename_a_member_behind_our_back() {
        // The header says `short`; the `L` record says `../../etc/passwd`. A reader that merges
        // them extracts somewhere else than a scanner that does not. Under `raw(true)` the record
        // arrives as its own non-regular entry and is refused on sight.
        let bytes = TarForge::new()
            .gnu_long_name("short", "../../etc/passwd", b"payload")
            .finish();
        let err = read_tar(&bytes, &limits()).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }

    #[test]
    fn a_pax_path_override_is_refused_the_same_way() {
        let bytes = TarForge::new()
            .pax_path_override("short", "../../etc/passwd", b"payload")
            .finish();
        assert!(read_tar(&bytes, &limits()).is_err());
    }

    #[test]
    fn a_header_that_lies_about_its_size_is_refused() {
        // The reader stops at the claimed length, so the rest of the real body would be parsed as
        // the next header -- a member smuggled inside another member's payload.
        let bytes = TarForge::new()
            .lying_size("a.tsv", &vec![b'x'; 1024], 16)
            .finish();
        assert!(read_tar(&bytes, &limits()).is_err());
    }

    #[test]
    fn duplicate_member_names_are_refused() {
        // An extractor keeps the last, a scanner may read the first, and the two disagree about
        // what was delivered.
        let bytes = TarForge::new()
            .file("page.tsv", b"benign")
            .file("page.tsv", b"replacement")
            .finish();
        let err = read_tar(&bytes, &limits()).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn too_many_members_is_refused() {
        let mut forge = TarForge::new();
        for i in 0..10 {
            forge = forge.file(&format!("f{i}.tsv"), b"x");
        }
        assert!(read_tar(&forge.finish(), &limits()).is_err());
    }

    #[test]
    fn an_over_long_member_name_is_refused() {
        let mut short = limits();
        short.max_tar_name_bytes = 16;
        let bytes = TarForge::new()
            .file("a-rather-long-name.tsv", b"x")
            .finish();
        assert!(read_tar(&bytes, &short).is_err());
    }

    #[test]
    fn an_archive_cut_short_mid_member_is_refused() {
        let bytes = TarForge::new()
            .file("page.tsv", &vec![b'x'; 2048])
            .finish_cut_short(600);
        assert!(read_tar(&bytes, &limits()).is_err());
    }

    #[test]
    fn an_archive_with_no_end_marker_is_still_read_but_an_empty_one_is_refused() {
        // A missing end marker is what a stream that died mid-write looks like. The `tar` crate
        // tolerates it, so the emptiness check is what stops "nothing came back" reading as
        // "the archive was empty".
        let truncated = TarForge::new().file("page.tsv", b"x").finish_truncated();
        assert!(read_tar(&truncated, &limits()).is_ok());

        let empty = TarForge::new().finish();
        let err = read_tar(&empty, &limits()).unwrap_err();
        assert!(err.to_string().contains("no members"), "{err}");
    }

    #[test]
    fn a_member_over_the_per_member_cap_is_refused_on_its_header_alone() {
        let mut small = limits();
        small.max_tar_member_bytes = 64;
        let bytes = TarForge::new().file("big.tsv", &vec![b'x'; 4096]).finish();
        let err = read_tar(&bytes, &small).unwrap_err();
        assert!(err.to_string().contains("per-member cap"), "{err}");
    }

    #[test]
    fn the_writer_refuses_what_the_reader_would_refuse() {
        // The two halves must agree, or we generate archives our own audit rejects -- which would
        // be discovered on Q2 after a 100 GB export rather than here.
        let dir = tempfile::tempdir().unwrap();
        for name in ["../escape", "/absolute", "a b", ""] {
            let bad = vec![ArchiveMember {
                name: name.to_owned(),
                bytes: b"x".to_vec(),
            }];
            assert!(
                write_targz(&dir.path().join("out.tar.gz"), &bad, &limits()).is_err(),
                "{name:?} was written"
            );
        }
    }

    #[test]
    fn the_writer_refuses_duplicate_names() {
        let dir = tempfile::tempdir().unwrap();
        let dupes = vec![
            ArchiveMember {
                name: "a".to_owned(),
                bytes: b"1".to_vec(),
            },
            ArchiveMember {
                name: "a".to_owned(),
                bytes: b"2".to_vec(),
            },
        ];
        assert!(write_targz(&dir.path().join("o.tar.gz"), &dupes, &limits()).is_err());
    }
}

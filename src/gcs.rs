//! Google Cloud Storage: create-only push, generation-pinned pull, retention and holds.
//!
//! Hand-written over `reqwest` on purpose, and this stays hand-written even though the ClickHouse
//! side is also hand-rolled now. Every GCS feature relied on here is a security control --
//! `ifGenerationMatch=0`, generation-pinned reads, SHA-256 in custom metadata, Unlocked object
//! retention, temporary holds -- and object retention in particular is new enough that crate
//! coverage is patchy. A dependency that might not expose a control is worse than a reviewed
//! implementation that does.
//!
//! # Four traps, recorded here because each reads as pedantic and none is
//!
//! - A client-side existence check is **not** `ifGenerationMatch=0`. Checking first needs read or
//!   list, which `roles/storage.objectCreator` deliberately lacks, and races anyway. Only the
//!   precondition is a real server-side create-only write.
//! - `ifGenerationMatch=0` means "no *live* object". With versioning on it still succeeds when only
//!   noncurrent generations exist, so reconcile against the ledger, never against the precondition
//!   alone.
//! - The `crc32c` value in `x-goog-hash` is **base64 of the big-endian u32**, not the decimal
//!   number and not little-endian. [`crc32c_header`] exists so there is one place to get it wrong,
//!   and it is tested against a known vector.
//! - GCS has **no SHA-256 upload checksum** (deviation D5). The producer computes it into custom
//!   metadata and the ledger is the authority. A GCS-reported hash is never trusted.
//!
//! # Rollback
//!
//! **Write-side rollback is impossible by design.** The raw bucket carries retention plus temporary
//! holds, which is the point of it: an attacker with our credentials must not be able to erase what
//! we already pushed. So no `Drop` in this module deletes anything, and none ever should -- a
//! future reader who "fixes" that has removed the control. An interrupted batch leaves orphan
//! objects that are inert, immutable, and `teardown`'s problem. What makes a partial batch
//! harmless is the read side: `PAGES.json` is written last and lists every page, so a prefix
//! without it is an incomplete run and a consumer treats it as absent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::abort::{PartialOutput, Result, SalvageError, infra, usage};
use crate::limits::{Limits, OrOverflow as _};

/// A GCS object generation. Named `Generation`, never `gen` -- `gen` is a reserved keyword in
/// edition 2024.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generation(pub u64);

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// GCS caps object names at 1024 bytes of UTF-8.
pub const MAX_OBJECT_NAME_BYTES: usize = 1024;

/// A validated object name.
///
/// Object names are generated locally -- `<db>.<tbl>/<batch>/page-NNNN.tar.gz`, with the page
/// number from a counter -- so a name that fails validation is our bug rather than a hostile
/// input, which is why construction is [`SalvageError::Usage`] and not `Abort`. Section 4's rule
/// that no database value is ever interpolated into a path is upheld by the *callers*; this type
/// is the backstop that makes a slip loud.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectName(String);

impl ObjectName {
    /// Validate and wrap. Rejects anything that could traverse, hide, or confuse a path.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let bad = |why: &str| -> SalvageError {
            usage::<()>("invalid object name")
                .unwrap_err()
                .with("name", name.escape_debug())
                .with("reason", why.to_owned())
        };

        if name.is_empty() {
            return Err(bad("empty"));
        }
        if name.len() > MAX_OBJECT_NAME_BYTES {
            return Err(bad("longer than 1024 bytes"));
        }
        if name.starts_with('/') || name.ends_with('/') {
            return Err(bad("leading or trailing slash"));
        }
        // Rejected rather than normalised. `//` would collapse on some paths and not others, and
        // "collapse" is a repair -- the one thing this project never does.
        if name.contains("//") {
            return Err(bad("empty path component"));
        }
        for component in name.split('/') {
            if component == ".." || component == "." {
                return Err(bad("relative path component"));
            }
        }
        for byte in name.bytes() {
            let ok = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/');
            if !ok {
                return Err(bad("character outside [A-Za-z0-9._/-]"));
            }
        }
        Ok(Self(name))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ObjectName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What the producer attaches to an object at create time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    /// Deviation D5: GCS has no SHA-256 upload checksum, so the producer computes one and puts it
    /// here. Every consumer recomputes from the bytes; a GCS-reported hash is never the authority.
    pub sha256_hex: String,
    /// Unlocked (governance) object retention, per addition A5. Never Locked: locked retention
    /// would hold the attacker's data immutably and indefinitely and block deleting the bucket,
    /// which is a liability rather than a control.
    pub retain_until: Option<OffsetDateTime>,
    /// A temporary hold, released at teardown. Needs `storage.objects.update`, not `setRetention`.
    pub hold: bool,
    pub content_type: &'static str,
}

/// What the store reports back about one object generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectStat {
    pub name: ObjectName,
    pub generation: Generation,
    pub size: u64,
    /// From custom metadata, so absent on anything we did not write. `None` is not "matches".
    pub sha256_hex: Option<String>,
    pub hold: bool,
}

/// The outcome of a create-only write.
///
/// The two cases are separated in the type because they mean opposite things to `--resume`. A 412
/// from `ifGenerationMatch=0` is not a failure: on a resumed run it is the **verify-and-skip**
/// signal, and the caller compares the existing SHA-256 and generation against the ledger. A
/// mismatch there is an `Abort` -- something else wrote to our prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Created {
    /// No live object existed; this generation is ours.
    Fresh(Generation),
    /// A live object already existed and was left untouched.
    Existed(Box<ObjectStat>),
}

/// The seam every caller uses, so push and pull can be tested against a local oracle with no GCP.
pub trait ObjectStore {
    /// Create-only write. Never overwrites: the precondition is server-side.
    fn create(&self, name: &ObjectName, body: &Path, meta: &ObjectMeta) -> Result<Created>;

    /// Read one exact generation into `dest`. Never "latest under prefix".
    fn get_pinned(&self, name: &ObjectName, generation: Generation, dest: &Path) -> Result<()>;

    /// The live generation of one object, if any. Used by `--resume` to verify and skip.
    fn stat(&self, name: &ObjectName) -> Result<Option<ObjectStat>>;

    /// Live objects under a prefix. Used by `teardown` to find orphans from a failed run.
    fn list(&self, prefix: &str) -> Result<Vec<ObjectStat>>;

    /// Set or release a temporary hold on one generation.
    fn set_hold(&self, name: &ObjectName, generation: Generation, hold: bool) -> Result<()>;
}

// -- pure wire-format shaping ------------------------------------------------------------------
//
// Unit-tested directly. There is no HTTP mock in dev-dependencies and none is wanted: the URL and
// header shapes are where the security-relevant details live, and they are pure functions of their
// inputs, so they can be asserted exactly.

/// Everything not in the RFC 3986 unreserved set gets percent-encoded, `/` included.
///
/// The object name is a single path *segment* in the JSON API (`/o/<name>`), so an unencoded `/`
/// would be read as a path separator and address a different object.
const OBJECT_NAME_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[must_use]
pub fn encode_object_name(name: &ObjectName) -> String {
    utf8_percent_encode(name.as_str(), OBJECT_NAME_ENCODE).to_string()
}

/// The resumable-upload initiation URL, with the create-only precondition.
///
/// Resumable rather than single-shot because pages off a ~100 GB table are multi-GB and a
/// single `POST` will not survive one over a hostile link. `ifGenerationMatch=0` is applied to the
/// initiating request and governs the whole session, so create-only holds across the resume.
#[must_use]
pub fn resumable_init_url(bucket: &str, name: &ObjectName) -> String {
    format!(
        "https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o\
         ?uploadType=resumable&name={}&ifGenerationMatch=0",
        encode_object_name(name)
    )
}

/// The generation-pinned download URL. `alt=media` returns bytes rather than JSON metadata.
#[must_use]
pub fn download_url(bucket: &str, name: &ObjectName, generation: Generation) -> String {
    format!(
        "https://storage.googleapis.com/storage/v1/b/{bucket}/o/{}?alt=media&generation={generation}",
        encode_object_name(name)
    )
}

/// The metadata URL for one exact generation.
#[must_use]
pub fn metadata_url(bucket: &str, name: &ObjectName, generation: Generation) -> String {
    format!(
        "https://storage.googleapis.com/storage/v1/b/{bucket}/o/{}?generation={generation}",
        encode_object_name(name)
    )
}

/// The `x-goog-hash` header value for a body.
///
/// **base64 of the big-endian u32**, which is the detail worth having exactly one copy of. The
/// decimal form and the little-endian form are both plausible-looking and both wrong, and a wrong
/// checksum header is accepted by GCS as a mismatch rather than ignored -- so this fails loudly if
/// it is wrong, but only against a real bucket. Hence the known-vector test.
#[must_use]
pub fn crc32c_header(body: &[u8]) -> String {
    let sum = crc32c::crc32c(body);
    base64::engine::general_purpose::STANDARD.encode(sum.to_be_bytes())
}

/// Render a retain-until instant the way the JSON API wants it.
pub fn retain_until_rfc3339(at: OffsetDateTime) -> Result<String> {
    at.format(&Rfc3339)
        .map_err(|e| infra::<()>(format!("could not format retain-until: {e}")).unwrap_err())
}

// -- the real client ---------------------------------------------------------------------------

/// Where the bearer token comes from.
#[derive(Debug, Clone)]
pub enum TokenSource {
    /// The GCE metadata server. Both hosts are GCE instances with attached service accounts, so
    /// there is no auth crate, no key file on disk, and nothing to steal from Q1 that is not
    /// already scoped to one bucket prefix.
    ///
    /// **`?scopes=` alone does not downscope the token.** `enforce_scopes=true` is also required,
    /// and without it the returned token carries the service account's full scope set. That is the
    /// difference between a put-only credential and a general one.
    Metadata { scopes: &'static str },
    /// An explicit token. Read from the environment *by `main`* and passed in -- never read here,
    /// and never written anywhere: `std::env::set_var` is `unsafe` in edition 2024 and this crate
    /// forbids unsafe, so no test can set one either.
    Static(String),
}

/// Read-only scope, for the audit host pulling from the raw bucket.
pub const SCOPE_READ_ONLY: &str = "https://www.googleapis.com/auth/devstorage.read_only";
/// Write-only scope, for the export host pushing to the raw bucket.
pub const SCOPE_WRITE_ONLY: &str = "https://www.googleapis.com/auth/devstorage.write_only";
/// Read-write, needed only for holds and retention (`storage.objects.update`).
pub const SCOPE_READ_WRITE: &str = "https://www.googleapis.com/auth/devstorage.read_write";

/// The wall-clock and byte budget for one transfer.
///
/// This exists because **nothing in the HTTP stack provides a total budget.** Verified against the
/// vendored source: `reqwest::blocking::ClientBuilder` has no `read_timeout` at all, and the
/// client-level `.timeout()` recomputes `Instant::now() + d` on every `read()`, so a server that
/// drips one byte per second streams forever without ever tripping it. Section 8.4's wall-clock cap
/// is therefore ours to enforce, in the copy loop, or it does not exist.
#[derive(Debug, Clone, Copy)]
pub struct TransferBudget {
    pub wall_clock: Duration,
    pub max_bytes: u64,
}

impl TransferBudget {
    /// Derive from the pinned per-table limits.
    #[must_use]
    pub fn from_limits(limits: &Limits) -> Self {
        Self {
            wall_clock: Duration::from_secs(limits.wall_clock_secs),
            max_bytes: limits.max_compressed_bytes,
        }
    }
}

/// 8 MiB. GCS requires every non-final resumable chunk to be a multiple of 256 KiB.
const UPLOAD_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

/// Cap on a JSON control-plane response. Metadata documents are small; anything larger is either a
/// bug or someone feeding us a body instead of an answer.
const MAX_JSON_RESPONSE_BYTES: u64 = 1024 * 1024;

/// The real client.
///
/// Constructed **exactly once** in `main` and passed down as `&dyn ObjectStore`.
/// `reqwest::blocking` spins its own runtime thread, and constructing one inside a `Drop` would
/// deadlock -- a live risk given how much of this design lives in destructors.
#[derive(Debug)]
pub struct HttpStore {
    client: reqwest::blocking::Client,
    bucket: String,
    tokens: TokenSource,
    budget: TransferBudget,
    /// Where resumable-upload session URIs are persisted, so an interrupted multi-GB push resumes
    /// instead of restarting. Pages off a ~100 GB table are large enough that this is not an
    /// optimisation.
    session_dir: PathBuf,
}

impl HttpStore {
    /// `session_dir` must exist. `bucket` is pinned configuration, never derived from data.
    pub fn new(
        bucket: impl Into<String>,
        tokens: TokenSource,
        budget: TransferBudget,
        session_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        // Every codec explicitly off. With all four features disabled reqwest never writes an
        // `Accept-Encoding` header and the decompression layer is not in the service type -- but
        // Cargo feature unification lets *any* other dependency turn `reqwest/gzip` on behind our
        // back, and a transparently decompressed body would make section 8.1's "exactly one gzip
        // member, no trailing bytes" check test nothing at all. These calls exist unconditionally
        // for exactly this reason.
        let client = reqwest::blocking::Client::builder()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| infra::<()>(format!("could not build HTTP client: {e}")).unwrap_err())?;

        Ok(Self {
            client,
            bucket: bucket.into(),
            tokens,
            budget,
            session_dir: session_dir.into(),
        })
    }

    fn token(&self) -> Result<String> {
        match &self.tokens {
            TokenSource::Static(t) => Ok(t.clone()),
            TokenSource::Metadata { scopes } => {
                let url = format!(
                    "http://metadata.google.internal/computeMetadata/v1/instance/\
                     service-accounts/default/token?scopes={scopes}&enforce_scopes=true"
                );
                let resp = self
                    .client
                    .get(&url)
                    .header("Metadata-Flavor", "Google")
                    .timeout(Duration::from_secs(10))
                    .send()
                    .map_err(|e| {
                        infra::<()>(format!("metadata server unreachable: {e}")).unwrap_err()
                    })?;
                let resp = expect_status(resp, &[200], "metadata token")?;
                let body = read_bounded_body(resp, MAX_JSON_RESPONSE_BYTES)?;
                let parsed: MetadataToken = serde_json::from_slice(&body).map_err(|e| {
                    infra::<()>(format!("malformed metadata token response: {e}")).unwrap_err()
                })?;
                Ok(parsed.access_token)
            }
        }
    }

    fn deadline(&self) -> Instant {
        Instant::now()
            .checked_add(self.budget.wall_clock)
            .unwrap_or_else(Instant::now)
    }

    /// A stable, traversal-proof filename for one object's resumable session.
    ///
    /// The object name contains `/`, so it cannot be a filename. Hashing it also means a session
    /// file cannot be steered anywhere by a name, which matters because this path is derived from
    /// a value that -- despite section 4 -- is one refactor away from being data-influenced.
    fn session_path(&self, name: &ObjectName) -> PathBuf {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(name.as_str().as_bytes());
        self.session_dir.join(format!("{digest:x}.session"))
    }

    /// The metadata document sent when initiating an upload.
    fn init_metadata(&self, name: &ObjectName, meta: &ObjectMeta) -> Result<String> {
        let mut doc = serde_json::json!({
            "name": name.as_str(),
            "contentType": meta.content_type,
            // Deviation D5. GCS has no SHA-256 upload checksum, so ours travels as custom
            // metadata. It is a record of what the producer computed, never an integrity control
            // the service enforces -- the ledger is the authority and every consumer recomputes.
            "metadata": { "sha256": meta.sha256_hex },
        });
        if meta.hold {
            doc["temporaryHold"] = serde_json::Value::Bool(true);
        }
        if let Some(until) = meta.retain_until {
            // Addition A5: Unlocked, never Locked. Locked retention would make the raw bucket hold
            // the attacker's data immutably and indefinitely and block deleting the bucket at all
            // until every retain-until has passed. That is a liability, not a control.
            doc["retention"] = serde_json::json!({
                "mode": "Unlocked",
                "retainUntilTime": retain_until_rfc3339(until)?,
            });
        }
        Ok(doc.to_string())
    }

    /// Fetch one object's live metadata, or `None` if there is no live object.
    fn get_metadata(
        &self,
        name: &ObjectName,
        generation: Option<Generation>,
    ) -> Result<Option<ObjectStat>> {
        let mut url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}",
            self.bucket,
            encode_object_name(name)
        );
        if let Some(g) = generation {
            url.push_str(&format!("?generation={g}"));
        }
        let resp = self
            .client
            .get(&url)
            .bearer_auth(self.token()?)
            .timeout(Duration::from_secs(30))
            .send()
            .map_err(|e| infra::<()>(format!("metadata request failed: {e}")).unwrap_err())?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = expect_status(resp, &[200], "object metadata")?;
        let body = read_bounded_body(resp, MAX_JSON_RESPONSE_BYTES)?;
        let raw: GcsObject = serde_json::from_slice(&body)
            .map_err(|e| infra::<()>(format!("malformed object metadata: {e}")).unwrap_err())?;
        Ok(Some(raw.into_stat()?))
    }
}

impl ObjectStore for HttpStore {
    fn create(&self, name: &ObjectName, body: &Path, meta: &ObjectMeta) -> Result<Created> {
        let total = std::fs::metadata(body)
            .map_err(|e| {
                infra::<()>(format!("could not stat upload body: {e}"))
                    .unwrap_err()
                    .with("path", body.display())
            })?
            .len();

        let session_path = self.session_path(name);
        let session_uri = match std::fs::read_to_string(&session_path) {
            // An interrupted push. Ask the session how much it committed and continue from there;
            // restarting a multi-GB page over a hostile link is not a recovery strategy.
            Ok(uri) if !uri.trim().is_empty() => uri.trim().to_owned(),
            _ => {
                let init = self
                    .client
                    .post(resumable_init_url(&self.bucket, name))
                    .bearer_auth(self.token()?)
                    .header("Content-Type", "application/json; charset=UTF-8")
                    .header("X-Upload-Content-Type", meta.content_type)
                    .header("X-Upload-Content-Length", total.to_string())
                    .body(self.init_metadata(name, meta)?)
                    .timeout(Duration::from_secs(60))
                    .send()
                    .map_err(|e| infra::<()>(format!("upload init failed: {e}")).unwrap_err())?;

                // 412 is the create-only precondition doing its job. On a resumed run this is the
                // verify-and-skip signal, not a failure -- the caller compares the returned
                // SHA-256 and generation against the ledger, and a mismatch there is an Abort.
                if init.status() == reqwest::StatusCode::PRECONDITION_FAILED {
                    let existing = self.get_metadata(name, None)?.ok_or_else(|| {
                        // Live-object precondition failed but nothing is live: someone deleted it
                        // between the two calls, or the bucket is not what we think it is.
                        infra::<()>("create-only precondition failed but no live object exists")
                            .unwrap_err()
                            .with("object", name)
                    })?;
                    return Ok(Created::Existed(Box::new(existing)));
                }

                let init = expect_status(init, &[200, 201], "upload init")?;
                let uri = init
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| infra::<()>("upload init returned no session URI").unwrap_err())?
                    .to_owned();
                std::fs::write(&session_path, &uri).map_err(|e| {
                    infra::<()>(format!("could not persist upload session: {e}")).unwrap_err()
                })?;
                uri
            }
        };

        let generation = self.put_chunks(&session_uri, body, total)?;

        // Only now is the session spent. Leaving it would make the next run resume a finished
        // upload; removing it earlier would lose the resume point on a crash mid-PUT.
        let _ = std::fs::remove_file(&session_path);
        Ok(Created::Fresh(generation))
    }

    fn get_pinned(&self, name: &ObjectName, generation: Generation, dest: &Path) -> Result<()> {
        let resp = self
            .client
            .get(download_url(&self.bucket, name, generation))
            .bearer_auth(self.token()?)
            // Belt and braces with the disabled codecs above. If the transport decompressed for
            // us, the bytes we hash would not be the bytes stored and `archive.rs`'s framing check
            // would be inspecting something the producer never wrote.
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .send()
            .map_err(|e| {
                infra::<()>(format!("pinned download failed: {e}"))
                    .unwrap_err()
                    .with("object", name)
                    .with("generation", generation)
            })?;
        let resp = expect_status(resp, &[200, 206], "pinned download")?;

        if let Some(enc) = resp.headers().get(reqwest::header::CONTENT_ENCODING) {
            return infra("response carried a Content-Encoding").map_err(|e: SalvageError| {
                e.with("object", name)
                    .with("encoding", String::from_utf8_lossy(enc.as_bytes()))
            });
        }

        // The guard makes "a failed download leaves no file that looks complete" structural rather
        // than a matter of remembering to clean up on every error path below.
        let mut guard = PartialOutput::new(dest.with_extension("partial"));
        let mut out = std::fs::File::create(guard.path()).map_err(|e| {
            infra::<()>(format!("could not open download destination: {e}")).unwrap_err()
        })?;

        let budget = TransferBudget {
            wall_clock: self.budget.wall_clock,
            max_bytes: self.budget.max_bytes,
        };
        copy_bounded(resp, &mut out, budget, self.deadline())?;
        drop(out);
        guard.commit_as(dest)
    }

    fn stat(&self, name: &ObjectName) -> Result<Option<ObjectStat>> {
        self.get_metadata(name, None)
    }

    fn list(&self, prefix: &str) -> Result<Vec<ObjectStat>> {
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!(
                "https://storage.googleapis.com/storage/v1/b/{}/o?prefix={}",
                self.bucket,
                utf8_percent_encode(prefix, OBJECT_NAME_ENCODE)
            );
            if let Some(t) = &page_token {
                url.push_str(&format!(
                    "&pageToken={}",
                    utf8_percent_encode(t, OBJECT_NAME_ENCODE)
                ));
            }
            let resp = self
                .client
                .get(&url)
                .bearer_auth(self.token()?)
                .timeout(Duration::from_secs(60))
                .send()
                .map_err(|e| infra::<()>(format!("list failed: {e}")).unwrap_err())?;
            let resp = expect_status(resp, &[200], "list")?;
            let body = read_bounded_body(resp, MAX_JSON_RESPONSE_BYTES)?;
            let page: GcsListing = serde_json::from_slice(&body)
                .map_err(|e| infra::<()>(format!("malformed listing: {e}")).unwrap_err())?;

            for item in page.items {
                out.push(item.into_stat()?);
            }
            match page.next_page_token {
                Some(t) => page_token = Some(t),
                None => break,
            }
        }
        Ok(out)
    }

    fn set_hold(&self, name: &ObjectName, generation: Generation, hold: bool) -> Result<()> {
        // PATCH on the object, not `setRetention`: a temporary hold needs
        // `storage.objects.update`, which is a different permission from the retention one and is
        // the reason teardown's service account is scoped read-write rather than write-only.
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}?generation={generation}",
            self.bucket,
            encode_object_name(name)
        );
        let resp = self
            .client
            .patch(&url)
            .bearer_auth(self.token()?)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({ "temporaryHold": hold }).to_string())
            .timeout(Duration::from_secs(60))
            .send()
            .map_err(|e| infra::<()>(format!("hold update failed: {e}")).unwrap_err())?;
        expect_status(resp, &[200], "hold update")?;
        Ok(())
    }
}

impl HttpStore {
    /// Upload the body in chunks against an existing resumable session, returning the generation.
    fn put_chunks(&self, session_uri: &str, body: &Path, total: u64) -> Result<Generation> {
        use std::io::{Read as _, Seek as _, SeekFrom};

        let deadline = self.deadline();
        let mut file = std::fs::File::open(body)
            .map_err(|e| infra::<()>(format!("could not open upload body: {e}")).unwrap_err())?;

        let mut offset = self.committed_offset(session_uri, total)?;
        if offset > 0 {
            file.seek(SeekFrom::Start(offset)).map_err(|e| {
                infra::<()>(format!("could not seek to resume point: {e}")).unwrap_err()
            })?;
        }

        loop {
            if Instant::now() > deadline {
                return infra("upload exceeded its wall-clock budget")
                    .map_err(|e: SalvageError| e.with("uploaded_bytes", offset))
                    .map(|()| Generation(0));
            }

            let remaining = total.saturating_sub(offset);
            if remaining == 0 {
                break;
            }
            let this_chunk = remaining.min(UPLOAD_CHUNK_BYTES);
            let mut buf = vec![0u8; usize::try_from(this_chunk).or_overflow("chunk->usize")?];
            file.read_exact(&mut buf).map_err(|e| {
                infra::<()>(format!("short read from upload body: {e}")).unwrap_err()
            })?;

            let last = buf.len() as u64;
            let range = format!("bytes {}-{}/{}", offset, offset + last - 1, total);
            let resp = self
                .client
                .put(session_uri)
                .header(reqwest::header::CONTENT_RANGE, &range)
                .header("x-goog-hash", format!("crc32c={}", crc32c_header(&buf)))
                .body(buf)
                .send()
                .map_err(|e| {
                    infra::<()>(format!("chunk upload failed: {e}"))
                        .unwrap_err()
                        .with("range", range.clone())
                })?;

            let status = resp.status().as_u16();
            match status {
                // 308 Resume Incomplete: more to send. Trust the server's committed offset over
                // our own arithmetic -- it is the one that decides what was durably written.
                308 => {
                    offset = committed_from_range(resp.headers()).unwrap_or(offset + last);
                }
                200 | 201 => {
                    let body = read_bounded_body(resp, MAX_JSON_RESPONSE_BYTES)?;
                    let obj: GcsObject = serde_json::from_slice(&body).map_err(|e| {
                        infra::<()>(format!("malformed upload completion: {e}")).unwrap_err()
                    })?;
                    return obj.generation_parsed();
                }
                other => {
                    let detail = read_bounded_body(resp, 8192)
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default();
                    return infra("chunk upload rejected")
                        .map_err(|e: SalvageError| e.with("status", other).with("detail", detail))
                        .map(|()| Generation(0));
                }
            }
        }

        infra("upload finished without a completion response")
    }

    /// Ask an existing session how many bytes it has durably committed.
    fn committed_offset(&self, session_uri: &str, total: u64) -> Result<u64> {
        let resp = self
            .client
            .put(session_uri)
            .header(reqwest::header::CONTENT_RANGE, format!("bytes */{total}"))
            .header(reqwest::header::CONTENT_LENGTH, "0")
            .timeout(Duration::from_secs(60))
            .send()
            .map_err(|e| {
                infra::<()>(format!("could not query upload session: {e}")).unwrap_err()
            })?;
        match resp.status().as_u16() {
            308 => Ok(committed_from_range(resp.headers()).unwrap_or(0)),
            // A finished session answers 200/201; there is nothing left to send.
            200 | 201 => Ok(total),
            // A dead or expired session. Starting over is correct here and only here: the object
            // is not yet live, so create-only has not been spent.
            _ => Ok(0),
        }
    }
}

/// Parse the committed byte count out of a 308's `Range: bytes=0-N` header.
///
/// Absent means nothing is committed yet, which is why the caller treats `None` as zero on a fresh
/// session and as "no progress" mid-stream rather than assuming success.
fn committed_from_range(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let raw = headers.get(reqwest::header::RANGE)?.to_str().ok()?;
    let end = raw.rsplit('-').next()?;
    end.parse::<u64>().ok().map(|n| n.saturating_add(1))
}

/// Copy a response body under both a byte cap and a wall-clock deadline.
///
/// Both checks are inside the loop, and that placement is the whole point: a cap checked after the
/// copy has already consumed the disk, and a timeout that resets per read never fires against a
/// slow drip. This is section 8.4's host-stage wall-clock limit, and nothing else in the process
/// implements it.
fn copy_bounded(
    mut src: impl std::io::Read,
    dest: &mut impl std::io::Write,
    budget: TransferBudget,
    deadline: Instant,
) -> Result<u64> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        if Instant::now() > deadline {
            return infra("transfer exceeded its wall-clock budget")
                .map_err(|e: SalvageError| {
                    e.with("bytes_so_far", total)
                        .with("budget_secs", budget.wall_clock.as_secs())
                })
                .map(|()| 0);
        }
        let n = src
            .read(&mut buf)
            .map_err(|e| infra::<()>(format!("read failed mid-transfer: {e}")).unwrap_err())?;
        if n == 0 {
            return Ok(total);
        }
        total = total.checked_add(n as u64).or_overflow("transfer_bytes")?;
        if total > budget.max_bytes {
            return infra("transfer exceeded its byte cap")
                .map_err(|e: SalvageError| {
                    e.with("cap", budget.max_bytes).with("bytes_so_far", total)
                })
                .map(|()| 0);
        }
        dest.write_all(&buf[..n])
            .map_err(|e| infra::<()>(format!("write failed mid-transfer: {e}")).unwrap_err())?;
    }
}

/// Read a control-plane response body under a hard cap.
fn read_bounded_body(resp: reqwest::blocking::Response, max: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let budget = TransferBudget {
        wall_clock: Duration::from_secs(60),
        max_bytes: max,
    };
    let deadline = Instant::now()
        .checked_add(budget.wall_clock)
        .unwrap_or_else(Instant::now);
    copy_bounded(resp, &mut out, budget, deadline)?;
    Ok(out)
}

/// Require one of an expected set of status codes, carrying the body into the error when not.
fn expect_status(
    resp: reqwest::blocking::Response,
    expected: &[u16],
    what: &'static str,
) -> Result<reqwest::blocking::Response> {
    let status = resp.status().as_u16();
    if expected.contains(&status) {
        return Ok(resp);
    }
    let detail = read_bounded_body(resp, 8192)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    infra(format!("{what}: unexpected status"))
        .map_err(|e: SalvageError| e.with("status", status).with("detail", detail))
}

// -- wire documents ----------------------------------------------------------------------------
//
// Deliberately *not* `deny_unknown_fields`. Every other serde type in this crate denies unknown
// keys because it reads our own pinned source control, where an unrecognised key means a typo in a
// control. These read Google's API, which adds fields on its own schedule; denying here would turn
// a routine GCS release into an outage on an incident-response tool.

#[derive(Debug, serde::Deserialize)]
struct MetadataToken {
    access_token: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcsObject {
    name: String,
    /// A JSON string, not a number: generations exceed 2^53 and would lose precision as a double.
    generation: String,
    size: String,
    #[serde(default)]
    temporary_hold: bool,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

impl GcsObject {
    fn generation_parsed(&self) -> Result<Generation> {
        self.generation.parse::<u64>().map(Generation).map_err(|_| {
            infra::<()>("object generation was not an integer")
                .unwrap_err()
                .with("generation", self.generation.escape_debug())
        })
    }

    fn into_stat(self) -> Result<ObjectStat> {
        let generation = self.generation_parsed()?;
        let size = self.size.parse::<u64>().map_err(|_| {
            infra::<()>("object size was not an integer")
                .unwrap_err()
                .with("size", self.size.escape_debug())
        })?;
        Ok(ObjectStat {
            // Re-validated rather than trusted. The name came back over the wire, and section 4's
            // rule is that the server's answer is a cross-check and never the authority.
            name: ObjectName::new(self.name)?,
            generation,
            size,
            sha256_hex: self.metadata.get("sha256").cloned(),
            hold: self.temporary_hold,
        })
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcsListing {
    #[serde(default)]
    items: Vec<GcsObject>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_page_name_is_accepted() {
        let n = ObjectName::new("events.hits/b-0001/page-0000.tar.gz").unwrap();
        assert_eq!(n.as_str(), "events.hits/b-0001/page-0000.tar.gz");
    }

    #[test]
    fn traversal_and_absolute_names_are_refused() {
        for bad in [
            "../etc/passwd",
            "a/../../b",
            "/leading",
            "trailing/",
            "a//b",
            "a/./b",
            "..",
        ] {
            assert!(
                ObjectName::new(bad).is_err(),
                "{bad} must not become an object name"
            );
        }
    }

    #[test]
    fn characters_outside_the_allowed_set_are_refused() {
        // A newline or a quote in an object name is either our bug or a value that reached a path
        // it must never reach. Either way it stops here.
        for bad in ["a\nb", "a b", "a'b", "a;b", "a\0b", "caf\u{e9}"] {
            assert!(ObjectName::new(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn an_over_long_name_is_refused() {
        assert!(ObjectName::new("a".repeat(MAX_OBJECT_NAME_BYTES)).is_ok());
        assert!(ObjectName::new("a".repeat(MAX_OBJECT_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn the_object_name_is_one_path_segment_so_slashes_encode() {
        let n = ObjectName::new("events.hits/b1/page-0000.tar.gz").unwrap();
        let encoded = encode_object_name(&n);
        assert!(
            !encoded.contains('/'),
            "an unencoded slash addresses a different object: {encoded}"
        );
        assert_eq!(encoded, "events.hits%2Fb1%2Fpage-0000.tar.gz");
    }

    #[test]
    fn the_upload_url_always_carries_the_create_only_precondition() {
        let n = ObjectName::new("t/b/page-0000.tar.gz").unwrap();
        let url = resumable_init_url("raw-bucket", &n);
        assert!(
            url.contains("ifGenerationMatch=0"),
            "a push without the precondition can silently replace an object: {url}"
        );
        assert!(url.contains("uploadType=resumable"), "{url}");
    }

    #[test]
    fn reads_are_always_generation_pinned() {
        let n = ObjectName::new("t/b/page-0000.tar.gz").unwrap();
        let url = download_url("raw-bucket", &n, Generation(1735689600000001));
        assert!(url.contains("generation=1735689600000001"), "{url}");
        assert!(url.contains("alt=media"), "{url}");
    }

    #[test]
    fn crc32c_is_base64_of_the_big_endian_u32() {
        // Known vector: CRC-32C of "123456789" is 0xE3069283 (the Castagnoli check value).
        assert_eq!(crc32c::crc32c(b"123456789"), 0xE306_9283);
        // Big-endian bytes E3 06 92 83 -> base64 "4waSgw==". Little-endian would be "g5IG4w==",
        // which is the bug this test exists to catch.
        assert_eq!(crc32c_header(b"123456789"), "4waSgw==");
        assert_ne!(crc32c_header(b"123456789"), "g5IG4w==");
    }

    #[test]
    fn the_empty_body_still_has_a_checksum() {
        // An empty page is a bug elsewhere, but the header must still be well formed rather than
        // absent -- GCS treats a missing hash as "no integrity claim", which is not what we mean.
        assert_eq!(crc32c_header(b""), "AAAAAA==");
    }

    #[test]
    fn retain_until_renders_as_rfc3339_in_utc() {
        let at = OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap();
        assert_eq!(retain_until_rfc3339(at).unwrap(), "2026-01-01T00:00:00Z");
    }

    fn offline_store() -> (tempfile::TempDir, HttpStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = HttpStore::new(
            "raw-bucket",
            TokenSource::Static("test-token".to_owned()),
            TransferBudget {
                wall_clock: Duration::from_secs(30),
                max_bytes: 1024,
            },
            dir.path(),
        )
        .unwrap();
        (dir, store)
    }

    #[test]
    fn the_upload_metadata_carries_the_producer_sha256_and_unlocked_retention() {
        let (_d, store) = offline_store();
        let n = ObjectName::new("t/b1/page-0000.tar.gz").unwrap();
        let meta = ObjectMeta {
            sha256_hex: "ab".repeat(32),
            retain_until: Some(OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap()),
            hold: true,
            content_type: "application/gzip",
        };
        let doc: serde_json::Value =
            serde_json::from_str(&store.init_metadata(&n, &meta).unwrap()).unwrap();

        // D5: GCS has no SHA-256 upload checksum, so ours rides in custom metadata.
        assert_eq!(doc["metadata"]["sha256"], "ab".repeat(32));
        assert_eq!(doc["temporaryHold"], true);
        // A5: Unlocked, never Locked. Locked retention would make the raw bucket hold the
        // attacker's data immutably and block deleting the bucket at all.
        assert_eq!(doc["retention"]["mode"], "Unlocked");
        assert_eq!(doc["retention"]["retainUntilTime"], "2026-01-01T00:00:00Z");
    }

    #[test]
    fn retention_is_never_locked_under_any_input() {
        let (_d, store) = offline_store();
        let n = ObjectName::new("t/b1/p.tar.gz").unwrap();
        for retain in [None, Some(OffsetDateTime::from_unix_timestamp(0).unwrap())] {
            let meta = ObjectMeta {
                sha256_hex: "00".repeat(32),
                retain_until: retain,
                hold: false,
                content_type: "application/gzip",
            };
            let rendered = store.init_metadata(&n, &meta).unwrap();
            assert!(
                !rendered.contains("Locked") || rendered.contains("Unlocked"),
                "addition A5 forbids Locked retention: {rendered}"
            );
        }
    }

    #[test]
    fn a_session_path_cannot_be_steered_by_an_object_name() {
        let (d, store) = offline_store();
        let a = ObjectName::new("t/b1/page-0000.tar.gz").unwrap();
        let b = ObjectName::new("t/b1/page-0001.tar.gz").unwrap();
        // Distinct names, distinct sessions, and both inside the session dir -- the name is
        // hashed rather than embedded, so no name can address a path outside it.
        assert_ne!(store.session_path(&a), store.session_path(&b));
        assert_eq!(store.session_path(&a), store.session_path(&a));
        assert!(store.session_path(&a).starts_with(d.path()));
        // The filename is a hex digest, so nothing from the object name -- which contains `/` --
        // survives into the path. A name is never a path component here.
        let file = store.session_path(&a);
        let stem = file.file_name().unwrap().to_string_lossy().into_owned();
        assert!(stem.ends_with(".session"), "{stem}");
        assert!(
            stem.trim_end_matches(".session")
                .bytes()
                .all(|b| b.is_ascii_hexdigit()),
            "session filename must be a bare digest, got {stem}"
        );
        assert_eq!(file.parent().unwrap(), d.path());
    }

    #[test]
    fn the_copy_loop_stops_at_the_byte_cap() {
        let src = vec![0u8; 4096];
        let mut out = Vec::new();
        let budget = TransferBudget {
            wall_clock: Duration::from_secs(60),
            max_bytes: 1024,
        };
        let err = copy_bounded(
            &src[..],
            &mut out,
            budget,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), crate::abort::ExitCode::Infra);
        assert!(err.to_string().contains("byte cap"), "{err}");
    }

    #[test]
    fn the_copy_loop_stops_at_the_deadline() {
        // Section 8.4's wall-clock cap. Nothing in the HTTP stack provides a total budget: a
        // per-read timeout resets on every read, so without this a slow drip streams forever.
        let src = vec![0u8; 4096];
        let mut out = Vec::new();
        let budget = TransferBudget {
            wall_clock: Duration::from_secs(1),
            max_bytes: u64::MAX,
        };
        let already_past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test clock");
        let err = copy_bounded(&src[..], &mut out, budget, already_past).unwrap_err();
        assert!(err.to_string().contains("wall-clock"), "{err}");
    }

    #[test]
    fn a_transfer_inside_both_bounds_copies_exactly() {
        let src = b"exactly these bytes".to_vec();
        let mut out = Vec::new();
        let budget = TransferBudget {
            wall_clock: Duration::from_secs(60),
            max_bytes: 1024,
        };
        let n = copy_bounded(
            &src[..],
            &mut out,
            budget,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(n, src.len() as u64);
        assert_eq!(out, src);
    }

    #[test]
    fn a_generation_larger_than_2_pow_53_survives_the_round_trip() {
        // Generations come back as JSON *strings* precisely because they exceed what a double can
        // hold. Parsing one as a number would silently round it, and a rounded generation pins the
        // wrong bytes -- or nothing at all.
        let json = br#"{
            "name": "events.hits/b1/page-0000.tar.gz",
            "generation": "9007199254740993",
            "size": "1048576",
            "temporaryHold": true,
            "metadata": { "sha256": "cc" }
        }"#;
        let obj: GcsObject = serde_json::from_slice(json).unwrap();
        let stat = obj.into_stat().unwrap();
        assert_eq!(stat.generation, Generation(9_007_199_254_740_993));
        assert_eq!(stat.size, 1_048_576);
        assert_eq!(stat.sha256_hex.as_deref(), Some("cc"));
        assert!(stat.hold);
    }

    #[test]
    fn an_object_whose_name_we_would_not_have_written_is_refused_on_the_way_back() {
        // Section 4: the server's answer is a cross-check, never the authority. A listing that
        // returns a traversing name does not get to construct one.
        let json = br#"{"name": "../../etc/passwd", "generation": "1", "size": "0"}"#;
        let obj: GcsObject = serde_json::from_slice(json).unwrap();
        assert!(obj.into_stat().is_err());
    }

    #[test]
    fn an_absent_sha256_is_none_rather_than_a_match() {
        let json = br#"{"name": "t/b/p.tar.gz", "generation": "12", "size": "3"}"#;
        let obj: GcsObject = serde_json::from_slice(json).unwrap();
        assert_eq!(obj.into_stat().unwrap().sha256_hex, None);
    }

    #[test]
    fn the_resume_offset_comes_from_the_range_header() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(reqwest::header::RANGE, "bytes=0-8388607".parse().unwrap());
        // `Range: bytes=0-N` is inclusive, so N+1 bytes are committed. Off by one here re-sends or
        // skips a chunk, and skipping corrupts the object with no error anywhere.
        assert_eq!(committed_from_range(&h), Some(8_388_608));

        // No header means nothing is committed -- never "assume it worked".
        assert_eq!(
            committed_from_range(&reqwest::header::HeaderMap::new()),
            None
        );
    }

    #[test]
    fn the_transfer_budget_comes_from_the_pinned_limits() {
        let limits = crate::limits::Limits {
            max_compressed_bytes: 268_435_456,
            max_uncompressed_bytes: 1_073_741_824,
            max_expansion_ratio: 100,
            max_rows_per_page: 5_000_000,
            max_fields_per_row: 64,
            max_field_bytes: 1_048_576,
            max_array_elements: 4096,
            max_nesting_depth: 8,
            max_tar_members: 16,
            max_tar_member_bytes: 1_073_741_824,
            max_tar_name_bytes: 128,
            max_decode_rounds: 1,
            max_decode_expansion_ratio: 8,
            wall_clock_secs: 3600,
        };
        let b = TransferBudget::from_limits(&limits);
        assert_eq!(b.max_bytes, 268_435_456);
        assert_eq!(b.wall_clock, Duration::from_secs(3600));
    }
}

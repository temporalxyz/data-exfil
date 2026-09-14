//! S3 transfers: pinned reads, resumable multipart writes, and create-only completion.
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart, ObjectLockMode,
};
use futures::{StreamExt, future::BoxFuture};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

use super::{atomic_json, file::hash_file, infrastructure};
use crate::abort::{Result, SalvageError, abort, infra, usage};

pub const PART_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Source {
    pub key: String,
    pub size: u64,
    pub version: Option<String>,
    pub etag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub version: Option<String>,
    pub etag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub bucket: String,
    pub prefix: String,
}
impl Location {
    pub fn parse(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("s3://")
            .ok_or_else(|| usage::<()>("expected s3://bucket/prefix").unwrap_err())?;
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        if bucket.len() < 3
            || bucket.len() > 63
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        {
            return usage("invalid S3 bucket name");
        }
        let prefix = prefix.trim_end_matches('/');
        if !prefix.is_empty() {
            crate::gcs::ObjectName::new(prefix.to_owned())?;
        }
        if prefix.chars().any(char::is_control)
            || prefix.contains('?')
            || prefix.contains('#')
            || prefix.split('/').any(|p| p == "." || p == "..")
        {
            return usage("invalid S3 prefix");
        }
        Ok(Self {
            bucket: bucket.into(),
            prefix: prefix.into(),
        })
    }
    pub fn key(&self, suffix: &str) -> String {
        if self.prefix.is_empty() {
            suffix.to_owned()
        } else {
            format!("{}/{suffix}", self.prefix)
        }
    }
}

/// Transfer seam used by the real pipeline and deterministic offline scheduling tests.
pub trait Store: Send + Sync {
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<Source>>>;
    fn download<'a>(&'a self, source: &'a Source, path: &'a Path) -> BoxFuture<'a, Result<String>>;
    fn upload<'a>(
        &'a self,
        key: &'a str,
        path: &'a Path,
        sha256: &'a str,
        session: &'a Path,
    ) -> BoxFuture<'a, Result<Receipt>>;
}

#[derive(Clone)]
pub struct S3Store {
    client: aws_sdk_s3::Client,
    bucket: String,
    timeout: Duration,
    retain_days: u32,
    parts: Arc<Semaphore>,
    part_concurrency: usize,
}

pub(super) struct PublishedHead {
    pub source: Source,
    pub sha256: String,
}

impl S3Store {
    pub(super) async fn published_head(&self, key: &str) -> Result<Option<PublishedHead>> {
        tokio::time::timeout(self.timeout, async {
            let head = match self
                .client
                .head_object()
                .bucket(&self.bucket)
                .key(key)
                .send()
                .await
            {
                Ok(head) => head,
                Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 404) => {
                    return Ok(None);
                }
                Err(e) => return Err(infrastructure(e)),
            };
            let size =
                u64::try_from(head.content_length().unwrap_or(-1)).map_err(infrastructure)?;
            let etag = head
                .e_tag()
                .ok_or_else(|| infra::<()>("published HEAD omitted ETag").unwrap_err())?
                .to_owned();
            let sha256 = head
                .metadata()
                .and_then(|m| m.get("sha256"))
                .cloned()
                .unwrap_or_default();
            if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return abort("published object lacks valid audit hash metadata");
            }
            Ok(Some(PublishedHead {
                source: Source {
                    key: key.into(),
                    size,
                    etag,
                    version: head
                        .version_id()
                        .filter(|v| *v != "null")
                        .map(str::to_owned),
                },
                sha256,
            }))
        })
        .await
        .map_err(infrastructure)?
    }

    pub(super) async fn published_manifest(&self, key: &str) -> Result<Option<super::Manifest>> {
        let Some(head) = self.published_head(key).await? else {
            return Ok(None);
        };
        if head.source.size == 0 || head.source.size > 32 * 1024 * 1024 {
            return abort("published manifest exceeds size bound");
        }
        tokio::time::timeout(self.timeout, async {
            let mut body = self
                .client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .set_version_id(head.source.version.clone())
                .if_match(&head.source.etag)
                .send()
                .await
                .map_err(infrastructure)?
                .body;
            let mut bytes = Vec::new();
            while let Some(chunk) = body.next().await {
                let chunk = chunk.map_err(infrastructure)?;
                if bytes.len() as u64 + chunk.len() as u64 > head.source.size {
                    return abort("published manifest grew while reading");
                }
                bytes.extend_from_slice(&chunk);
            }
            if bytes.len() as u64 != head.source.size
                || format!("{:x}", Sha256::digest(&bytes)) != head.sha256
            {
                return abort("published manifest hash or size mismatch");
            }
            serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| abort::<()>("invalid published manifest JSON").unwrap_err())
        })
        .await
        .map_err(infrastructure)?
    }

    pub(super) fn with_timeout(&self, seconds: u64) -> Self {
        Self {
            timeout: Duration::from_secs(seconds),
            ..self.clone()
        }
    }

    pub async fn new(
        bucket: String,
        profile: Option<&str>,
        timeout: u64,
        retain_days: u32,
        concurrency: usize,
    ) -> Result<Self> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(profile) = profile {
            loader = loader.profile_name(profile);
        }
        let config = loader.load().await;
        let client = aws_sdk_s3::Client::new(&config);
        Ok(Self {
            client,
            bucket,
            timeout: Duration::from_secs(timeout),
            retain_days,
            parts: Arc::new(Semaphore::new(concurrency)),
            part_concurrency: concurrency,
        })
    }

    async fn enumerate(&self, prefix: &str) -> Result<Vec<Source>> {
        let mut token = None;
        let mut result = Vec::new();
        loop {
            let page = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .set_continuation_token(token.clone())
                .send()
                .await
                .map_err(infrastructure)?;
            let mut heads = futures::stream::iter(page.contents().to_vec()).map(|object| async move {
                let key = object
                    .key()
                    .ok_or_else(|| infra::<()>("S3 listing omitted key").unwrap_err())?;
                if !key.ends_with(".parquet") {
                    return Ok(None);
                }
                if !key.starts_with(prefix) || crate::gcs::ObjectName::new(key.to_owned()).is_err()
                {
                    return abort(
                        "source key contains unsafe provenance characters or lies outside selected prefix",
                    );
                }
                // HEAD pins the actual object version. ListObjectsV2 does not supply version IDs.
                let head = self
                    .client
                    .head_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send()
                    .await
                    .map_err(infrastructure)?;
                let size =
                    u64::try_from(head.content_length().unwrap_or(-1)).map_err(infrastructure)?;
                let etag = head
                    .e_tag()
                    .ok_or_else(|| infra::<()>("S3 HEAD omitted ETag").unwrap_err())?
                    .to_owned();
                if Some(size as i64) != object.size() || object.e_tag() != Some(etag.as_str()) {
                    return abort("source object changed during inventory");
                }
                Ok(Some(Source {
                    key: key.into(),
                    size,
                    version: head
                        .version_id()
                        .filter(|v| *v != "null")
                        .map(str::to_owned),
                    etag,
                }))
            }).buffer_unordered(self.part_concurrency);
            while let Some(source) = heads.next().await {
                if let Some(source) = source? {
                    if result.len() >= 100_000 {
                        return usage(
                            "day exceeds 100000 source objects; narrow the source prefix",
                        );
                    }
                    result.push(source);
                }
            }
            if !page.is_truncated().unwrap_or(false) {
                break;
            }
            let next = page
                .next_continuation_token()
                .ok_or_else(|| {
                    infra::<()>("truncated S3 listing omitted continuation token").unwrap_err()
                })?
                .to_owned();
            if token.as_ref() == Some(&next) {
                return infra("S3 listing made no progress");
            }
            token = Some(next);
        }
        result.sort_by(|a, b| a.key.cmp(&b.key));
        if result.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return abort("duplicate source object in inventory");
        }
        Ok(result)
    }

    async fn pull(&self, source: &Source, path: &Path) -> Result<String> {
        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&source.key)
            .set_version_id(source.version.clone())
            .if_match(&source.etag)
            .send()
            .await
            .map_err(|e| {
                if e.raw_response()
                    .is_some_and(|r| matches!(r.status().as_u16(), 404 | 412))
                {
                    abort::<()>("pinned source object changed or disappeared").unwrap_err()
                } else {
                    infrastructure(e)
                }
            })?;
        if response.content_length() != Some(source.size as i64)
            || response.e_tag() != Some(source.etag.as_str())
        {
            return abort("download identity differs from source inventory");
        }
        let partial = path.with_extension("partial");
        let mut guard = crate::abort::PartialOutput::new(partial);
        let mut file = tokio::fs::File::create(guard.path())
            .await
            .map_err(infrastructure)?;
        let mut body = response.body;
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let started = Instant::now();
        let mut last_progress = started;
        while let Some(bytes) = body.next().await {
            let bytes = bytes.map_err(infrastructure)?;
            count = count
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| abort::<()>("download size overflow").unwrap_err())?;
            if count > source.size {
                return abort("download exceeds pinned source size");
            }
            hash.update(&bytes);
            file.write_all(&bytes).await.map_err(infrastructure)?;
            if last_progress.elapsed() >= Duration::from_secs(15) {
                tracing::info!(
                    key = source.key,
                    downloaded_bytes = count,
                    total_bytes = source.size,
                    mib_per_sec = count as f64 / 1048576.0 / started.elapsed().as_secs_f64(),
                    "download progress"
                );
                last_progress = Instant::now();
            }
        }
        if count != source.size {
            return infra("truncated S3 download");
        }
        file.sync_all().await.map_err(infrastructure)?;
        drop(file);
        guard.commit_as(path)?;
        Ok(format!("{:x}", hash.finalize()))
    }

    async fn verify_existing(&self, key: &str, path: &Path, sha: &str) -> Result<Option<Receipt>> {
        let head = match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(head) => head,
            Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 404) => {
                return Ok(None);
            }
            Err(e) => return Err(infrastructure(e)),
        };
        let size = std::fs::metadata(path).map_err(infrastructure)?.len();
        if head.content_length() != Some(size as i64)
            || head
                .metadata()
                .and_then(|m| m.get("sha256"))
                .map(String::as_str)
                != Some(sha)
        {
            return abort("existing clean object conflicts with regenerated output");
        }
        let etag = head
            .e_tag()
            .ok_or_else(|| infra::<()>("clean HEAD omitted ETag").unwrap_err())?
            .to_owned();
        // Custom metadata is not proof of bytes. Rehash the pinned existing object on resume.
        let mut body = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .set_version_id(head.version_id().map(str::to_owned))
            .if_match(&etag)
            .send()
            .await
            .map_err(infrastructure)?
            .body;
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(infrastructure)?;
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| abort::<()>("existing output size overflow").unwrap_err())?;
            if bytes > size {
                return abort("existing output exceeds expected size");
            }
            hash.update(&chunk);
        }
        if bytes != size || format!("{:x}", hash.finalize()) != sha {
            return abort("existing clean object hash mismatch");
        }
        Ok(Some(Receipt {
            version: head.version_id().map(str::to_owned),
            etag,
        }))
    }

    fn retention_date(&self) -> Option<aws_sdk_s3::primitives::DateTime> {
        (self.retain_days > 0).then(|| {
            aws_sdk_s3::primitives::DateTime::from_secs(
                time::OffsetDateTime::now_utc().unix_timestamp()
                    + i64::from(self.retain_days) * 86400,
            )
        })
    }

    async fn push(
        &self,
        key: &str,
        path: &Path,
        sha: &str,
        session_path: &Path,
    ) -> Result<Receipt> {
        // A local artifact is always checked again before transfer, including after a crash.
        let owned = path.to_owned();
        let actual = tokio::task::spawn_blocking(move || hash_file(&owned))
            .await
            .map_err(infrastructure)??;
        if actual != sha {
            return abort("local regenerated output changed before upload");
        }
        if let Some(receipt) = self.verify_existing(key, path, sha).await? {
            return Ok(receipt);
        }
        let size = std::fs::metadata(path).map_err(infrastructure)?.len();
        let retain = self.retention_date();
        if size <= PART_BYTES {
            let _permit = self.parts.acquire().await.map_err(infrastructure)?;
            let result = self
                .client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .if_none_match("*")
                .metadata("sha256", sha)
                .content_type(if key.ends_with(".parquet") {
                    "application/vnd.apache.parquet"
                } else {
                    "application/json"
                })
                .set_object_lock_mode(retain.as_ref().map(|_| ObjectLockMode::Governance))
                .set_object_lock_retain_until_date(retain)
                .body(ByteStream::from_path(path).await.map_err(infrastructure)?)
                .send()
                .await;
            return match result {
                Ok(out) => Ok(Receipt {
                    version: out.version_id().map(str::to_owned),
                    etag: out.e_tag().unwrap_or_default().into(),
                }),
                Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 412) => {
                    self.verify_existing(key, path, sha).await?.ok_or_else(|| {
                        infra::<()>("conditional write conflict disappeared").unwrap_err()
                    })
                }
                Err(e) => Err(infrastructure(e)),
            };
        }
        let part_size = PART_BYTES.max(size.div_ceil(10_000));
        let previous = if session_path.exists() {
            let session: Session = super::read_json(session_path)?;
            if session.bucket != self.bucket
                || session.key != key
                || session.sha256 != sha
                || session.size != size
                || session.part_size != part_size
            {
                return abort("multipart checkpoint identity mismatch");
            }
            match self
                .client
                .list_parts()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(&session.upload_id)
                .max_parts(1)
                .send()
                .await
            {
                Ok(_) => Some(session),
                Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 404) => {
                    std::fs::remove_file(session_path).map_err(infrastructure)?;
                    None
                }
                Err(e) => return Err(infrastructure(e)),
            }
        } else {
            None
        };
        let mut session = if let Some(session) = previous {
            session
        } else {
            let out = self
                .client
                .create_multipart_upload()
                .bucket(&self.bucket)
                .key(key)
                .metadata("sha256", sha)
                .content_type("application/vnd.apache.parquet")
                .checksum_algorithm(ChecksumAlgorithm::Crc32C)
                .set_object_lock_mode(retain.as_ref().map(|_| ObjectLockMode::Governance))
                .set_object_lock_retain_until_date(retain)
                .send()
                .await
                .map_err(infrastructure)?;
            let session = Session {
                bucket: self.bucket.clone(),
                key: key.into(),
                sha256: sha.into(),
                size,
                part_size,
                upload_id: out
                    .upload_id()
                    .ok_or_else(|| infra::<()>("multipart init omitted upload id").unwrap_err())?
                    .into(),
                parts: Vec::new(),
            };
            atomic_json(session_path, &session)?;
            session
        };
        let count = size.div_ceil(part_size);
        if session.parts.iter().any(|p| {
            p.number < 1 || p.number as u64 > count || p.etag.is_empty() || p.crc32c.is_empty()
        }) || session.parts.windows(2).any(|p| p[0].number >= p[1].number)
        {
            return abort("invalid multipart checkpoint parts");
        }
        let missing: Vec<_> = (1..=count as i32)
            .filter(|n| !session.parts.iter().any(|p| p.number == *n))
            .collect();
        let upload_id = session.upload_id.clone();
        let mut uploads = futures::stream::iter(missing)
            .map(|number| {
                let upload_id = &upload_id;
                async move {
                    let _permit = self.parts.acquire().await.map_err(infrastructure)?;
                    let offset = (number as u64 - 1) * part_size;
                    let length = part_size.min(size - offset);
                    let body = ByteStream::read_from()
                        .path(path)
                        .offset(offset)
                        .length(aws_sdk_s3::primitives::Length::Exact(length))
                        .build()
                        .await
                        .map_err(infrastructure)?;
                    let result = self
                        .client
                        .upload_part()
                        .bucket(&self.bucket)
                        .key(key)
                        .upload_id(upload_id)
                        .part_number(number)
                        .checksum_algorithm(ChecksumAlgorithm::Crc32C)
                        .body(body)
                        .send()
                        .await
                        .map_err(infrastructure)?;
                    Ok::<_, SalvageError>(Part {
                        number,
                        crc32c: result
                            .checksum_crc32_c()
                            .ok_or_else(|| infra::<()>("upload part omitted CRC32C").unwrap_err())?
                            .into(),
                        etag: result
                            .e_tag()
                            .ok_or_else(|| infra::<()>("upload part omitted ETag").unwrap_err())?
                            .into(),
                    })
                }
            })
            .buffer_unordered(self.part_concurrency);
        while let Some(result) = uploads.next().await {
            session.parts.push(result?);
            session.parts.sort_by_key(|p| p.number);
            atomic_json(session_path, &session)?;
        }
        let parts = session
            .parts
            .iter()
            .map(|p| {
                CompletedPart::builder()
                    .part_number(p.number)
                    .e_tag(&p.etag)
                    .checksum_crc32_c(&p.crc32c)
                    .build()
            })
            .collect();
        let result = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&session.upload_id)
            .if_none_match("*")
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build(),
            )
            .send()
            .await;
        let receipt = match result {
            Ok(out) => Receipt {
                version: out.version_id().map(str::to_owned),
                etag: out.e_tag().unwrap_or_default().into(),
            },
            Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 412) => self
                .verify_existing(key, path, sha)
                .await?
                .ok_or_else(|| infra::<()>("multipart conflict disappeared").unwrap_err())?,
            Err(e)
                if e.raw_response()
                    .is_some_and(|r| matches!(r.status().as_u16(), 404 | 409)) =>
            {
                let _ = self
                    .client
                    .abort_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(&session.upload_id)
                    .send()
                    .await;
                std::fs::remove_file(session_path).map_err(infrastructure)?;
                return Err(infrastructure(e));
            }
            Err(e) => return Err(infrastructure(e)),
        };
        std::fs::remove_file(session_path).map_err(infrastructure)?;
        Ok(receipt)
    }
}

#[derive(Serialize, Deserialize)]
struct Session {
    bucket: String,
    key: String,
    sha256: String,
    size: u64,
    part_size: u64,
    upload_id: String,
    parts: Vec<Part>,
}
#[derive(Serialize, Deserialize)]
struct Part {
    number: i32,
    etag: String,
    crc32c: String,
}

impl Store for S3Store {
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<Source>>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, self.enumerate(prefix))
                .await
                .map_err(infrastructure)?
        })
    }
    fn download<'a>(&'a self, source: &'a Source, path: &'a Path) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, self.pull(source, path))
                .await
                .map_err(infrastructure)?
        })
    }
    fn upload<'a>(
        &'a self,
        key: &'a str,
        path: &'a Path,
        sha: &'a str,
        session: &'a Path,
    ) -> BoxFuture<'a, Result<Receipt>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, self.push(key, path, sha, session))
                .await
                .map_err(infrastructure)?
        })
    }
}

/// Verification/survey cannot accidentally publish, even if a caller reaches a write path.
pub struct NoUploadStore;
impl Store for NoUploadStore {
    fn list<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<Source>>> {
        Box::pin(async { abort("clean S3 is disabled for this run") })
    }
    fn download<'a>(&'a self, _: &'a Source, _: &'a Path) -> BoxFuture<'a, Result<String>> {
        Box::pin(async { abort("clean S3 is disabled for this run") })
    }
    fn upload<'a>(
        &'a self,
        _: &'a str,
        _: &'a Path,
        _: &'a str,
        _: &'a Path,
    ) -> BoxFuture<'a, Result<Receipt>> {
        Box::pin(async { abort("clean S3 writes are disabled for this run") })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    fn response(status: u16, headers: &[(&str, &str)], body: &str) -> ReplayEvent {
        let mut response = http::Response::builder().status(status);
        for (name, value) in headers {
            response = response.header(*name, *value);
        }
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://unused.invalid")
                .body(SdkBody::empty())
                .unwrap(),
            response.body(SdkBody::from(body)).unwrap(),
        )
    }

    fn store(events: Vec<ReplayEvent>) -> (S3Store, StaticReplayClient) {
        let replay = StaticReplayClient::new(events);
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test",
                "test",
                None,
                None,
                "offline-test",
            ))
            .http_client(replay.clone())
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(1))
            .build();
        (
            S3Store {
                client: aws_sdk_s3::Client::from_conf(config),
                bucket: "test-bucket".into(),
                timeout: Duration::from_secs(10),
                retain_days: 0,
                parts: Arc::new(Semaphore::new(1)),
                part_concurrency: 1,
            },
            replay,
        )
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn sdk_download_pins_version_etag_and_verifies_size() {
        let (store, replay) = store(vec![response(
            200,
            &[
                ("etag", "\"etag1\""),
                ("content-length", "4"),
                ("x-amz-version-id", "version1"),
            ],
            "data",
        )]);
        let dir = tempfile::tempdir().unwrap();
        let source = Source {
            key: "2026/09/01/events/part.parquet".into(),
            size: 4,
            version: Some("version1".into()),
            etag: "\"etag1\"".into(),
        };
        let sha = rt()
            .block_on(store.download(&source, &dir.path().join("raw.parquet")))
            .unwrap();
        assert_eq!(sha, crate::export::diff::sha256_hex(b"data"));
        let request = replay.actual_requests();
        for r in request {
            assert!(r.uri().contains("versionId=version1"));
            assert_eq!(r.headers().get("if-match"), Some("\"etag1\""));
        }
        assert!(!dir.path().join("raw.partial").exists());
    }

    #[test]
    fn sdk_inventory_paginates_filters_and_pins_each_object() {
        let (store, replay) = store(vec![
            response(
                200,
                &[],
                "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>2026/09/01/events/a.parquet</Key><Size>12</Size><ETag>a</ETag></Contents><Contents><Key>2026/09/01/events/readme.txt</Key><Size>12</Size><ETag>text</ETag></Contents></ListBucketResult>",
            ),
            response(
                200,
                &[
                    ("content-length", "12"),
                    ("etag", "a"),
                    ("x-amz-version-id", "v1"),
                ],
                "",
            ),
            response(
                200,
                &[],
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>2026/09/01/events/b.parquet</Key><Size>14</Size><ETag>b</ETag></Contents></ListBucketResult>",
            ),
            response(200, &[("content-length", "14"), ("etag", "b")], ""),
        ]);
        let sources = rt().block_on(store.list("2026/09/01/events/")).unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].version.as_deref(), Some("v1"));
        assert_eq!(sources[1].version, None);
        assert_eq!(sources[1].etag, "b");
        assert!(
            replay
                .actual_requests()
                .any(|r| r.uri().contains("continuation-token=next"))
        );
        assert_eq!(
            replay
                .actual_requests()
                .filter(|r| r.method() == "HEAD")
                .count(),
            2
        );
    }

    #[test]
    fn sdk_inventory_rejects_objects_that_change_between_list_and_head() {
        let (store, _) = store(vec![
            response(
                200,
                &[],
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>x/a.parquet</Key><Size>12</Size><ETag>old</ETag></Contents></ListBucketResult>",
            ),
            response(200, &[("content-length", "12"), ("etag", "new")], ""),
        ]);
        assert_eq!(
            rt().block_on(store.list("x/")).unwrap_err().exit_code(),
            crate::abort::ExitCode::Abort
        );
    }

    #[test]
    fn sdk_stale_pin_and_truncated_download_never_leave_complete_file() {
        for event in [
            response(412, &[], "<Error><Code>PreconditionFailed</Code></Error>"),
            response(200, &[("etag", "e"), ("content-length", "4")], "bad"),
        ] {
            let (store, _) = store(vec![event]);
            let dir = tempfile::tempdir().unwrap();
            let source = Source {
                key: "x.parquet".into(),
                size: 4,
                version: None,
                etag: "e".into(),
            };
            assert!(
                rt().block_on(store.download(&source, &dir.path().join("raw.parquet")))
                    .is_err()
            );
            assert!(!dir.path().join("raw.parquet").exists());
            assert!(!dir.path().join("raw.partial").exists());
        }
    }

    #[test]
    fn sdk_small_upload_is_create_only_and_carries_hash_and_governance() {
        let (mut store, replay) = store(vec![
            response(404, &[], ""),
            response(200, &[("etag", "out"), ("x-amz-version-id", "v1")], ""),
        ]);
        store.retain_days = 2;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("part.parquet");
        std::fs::write(&path, b"clean").unwrap();
        let sha = hash_file(&path).unwrap();
        let result = rt()
            .block_on(store.upload(
                "part.parquet",
                &path,
                &sha,
                &dir.path().join("session.json"),
            ))
            .unwrap();
        assert_eq!(result.version.as_deref(), Some("v1"));
        let requests: Vec<_> = replay
            .actual_requests()
            .map(|r| {
                (
                    r.method().to_string(),
                    r.headers().get("if-none-match").map(str::to_owned),
                    r.headers().get("x-amz-meta-sha256").map(str::to_owned),
                    r.headers().get("x-amz-object-lock-mode").map(str::to_owned),
                )
            })
            .collect();
        assert_eq!(requests[0].0, "HEAD");
        assert_eq!(
            requests[1],
            (
                "PUT".into(),
                Some("*".into()),
                Some(sha),
                Some("GOVERNANCE".into())
            )
        );
    }

    #[test]
    fn sdk_resume_rehashes_existing_bytes_instead_of_trusting_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("part.parquet");
        std::fs::write(&path, b"good").unwrap();
        let sha = hash_file(&path).unwrap();
        let (store, replay) = store(vec![
            response(
                200,
                &[
                    ("etag", "e"),
                    ("content-length", "4"),
                    ("x-amz-meta-sha256", &sha),
                ],
                "",
            ),
            response(200, &[("etag", "e"), ("content-length", "4")], "evil"),
        ]);
        let error = rt()
            .block_on(store.upload(
                "part.parquet",
                &path,
                &sha,
                &dir.path().join("session.json"),
            ))
            .unwrap_err();
        assert_eq!(error.exit_code(), crate::abort::ExitCode::Abort);
        assert!(replay.actual_requests().all(|r| r.method() != "PUT"));
    }

    #[test]
    fn sdk_multipart_resumes_missing_parts_and_completes_conditionally_with_checksums() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.parquet");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(PART_BYTES + 1)
            .unwrap();
        let sha = hash_file(&path).unwrap();
        let session = dir.path().join("session.json");
        let (first, _) = store(vec![
            response(404, &[], ""),
            response(
                200,
                &[],
                "<InitiateMultipartUploadResult><Bucket>test-bucket</Bucket><Key>large.parquet</Key><UploadId>upload1</UploadId></InitiateMultipartUploadResult>",
            ),
            response(
                200,
                &[("etag", "part1"), ("x-amz-checksum-crc32c", "AAAAAA==")],
                "",
            ),
            response(503, &[], "<Error><Code>ServiceUnavailable</Code></Error>"),
        ]);
        assert!(
            rt().block_on(first.upload("large.parquet", &path, &sha, &session))
                .is_err()
        );
        let saved: Session = super::super::read_json(&session).unwrap();
        assert_eq!(saved.parts.len(), 1);
        assert_eq!(saved.parts[0].number, 1);
        let (second, replay) = store(vec![
            response(404, &[], ""),
            response(
                200,
                &[],
                "<ListPartsResult><Bucket>test-bucket</Bucket><Key>large.parquet</Key><UploadId>upload1</UploadId><IsTruncated>false</IsTruncated></ListPartsResult>",
            ),
            response(
                200,
                &[("etag", "part2"), ("x-amz-checksum-crc32c", "AAAAAA==")],
                "",
            ),
            response(
                200,
                &[("x-amz-version-id", "final1")],
                "<CompleteMultipartUploadResult><Bucket>test-bucket</Bucket><Key>large.parquet</Key><ETag>final</ETag></CompleteMultipartUploadResult>",
            ),
        ]);
        let receipt = rt()
            .block_on(second.upload("large.parquet", &path, &sha, &session))
            .unwrap();
        assert_eq!(receipt.version.as_deref(), Some("final1"));
        assert!(!session.exists());
        let requests: Vec<_> = replay
            .actual_requests()
            .map(|r| {
                (
                    r.method().to_string(),
                    r.uri().to_owned(),
                    r.headers().get("if-none-match").map(str::to_owned),
                    r.body()
                        .bytes()
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(requests.iter().filter(|r| r.0 == "PUT").count(), 1);
        assert!(
            requests
                .iter()
                .any(|r| r.0 == "PUT" && r.1.contains("partNumber=2"))
        );
        let complete = requests.iter().find(|r| r.0 == "POST").unwrap();
        assert_eq!(complete.2.as_deref(), Some("*"));
        assert!(complete.3.contains("ChecksumCRC32C"));
    }

    #[test]
    fn sdk_expired_multipart_session_is_replaced_without_overwriting_the_object() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.parquet");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(PART_BYTES + 1)
            .unwrap();
        let sha = hash_file(&path).unwrap();
        let checkpoint = dir.path().join("session.json");
        atomic_json(
            &checkpoint,
            &Session {
                bucket: "test-bucket".into(),
                key: "large.parquet".into(),
                sha256: sha.clone(),
                size: PART_BYTES + 1,
                part_size: PART_BYTES,
                upload_id: "expired".into(),
                parts: vec![Part {
                    number: 1,
                    etag: "old-part".into(),
                    crc32c: "AAAAAA==".into(),
                }],
            },
        )
        .unwrap();
        let (store, replay) = store(vec![
            response(404, &[], ""),
            response(404, &[], "<Error><Code>NoSuchUpload</Code></Error>"),
            response(
                200,
                &[],
                "<InitiateMultipartUploadResult><Bucket>test-bucket</Bucket><Key>large.parquet</Key><UploadId>replacement</UploadId></InitiateMultipartUploadResult>",
            ),
            response(
                200,
                &[("etag", "part1"), ("x-amz-checksum-crc32c", "AAAAAA==")],
                "",
            ),
            response(
                200,
                &[("etag", "part2"), ("x-amz-checksum-crc32c", "AAAAAA==")],
                "",
            ),
            response(
                200,
                &[],
                "<CompleteMultipartUploadResult><Bucket>test-bucket</Bucket><Key>large.parquet</Key><ETag>final</ETag></CompleteMultipartUploadResult>",
            ),
        ]);
        rt().block_on(store.upload("large.parquet", &path, &sha, &checkpoint))
            .unwrap();
        assert!(!checkpoint.exists());
        let parts: Vec<_> = replay
            .actual_requests()
            .filter(|r| r.method() == "PUT")
            .map(|r| r.uri().to_owned())
            .collect();
        assert_eq!(parts.len(), 2);
        assert!(parts.iter().all(|uri| uri.contains("uploadId=replacement")));
        assert!(
            replay
                .actual_requests()
                .any(|r| r.method() == "POST" && r.headers().get("if-none-match") == Some("*"))
        );
    }
    #[test]
    fn published_head_distinguishes_absence_from_access_errors() {
        let (s, replay) = store(vec![response(404, &[], "")]);
        assert!(
            rt().block_on(s.published_manifest("MANIFEST.json"))
                .unwrap()
                .is_none()
        );
        assert_eq!(replay.actual_requests().count(), 1);
        let (s, _) = store(vec![response(403, &[], "")]);
        assert!(
            rt().block_on(s.published_manifest("MANIFEST.json"))
                .is_err()
        );
        let (s, _) = store(vec![response(
            200,
            &[("etag", "e"), ("content-length", "10")],
            "",
        )]);
        assert!(rt().block_on(s.published_head("part.parquet")).is_err());
    }

    #[test]
    fn published_manifest_reads_are_pinned_bounded_and_hash_checked() {
        let hash = crate::export::diff::sha256_hex(b"{}");
        for (body, reason) in [
            ("{}", "invalid published manifest JSON"),
            ("[]", "published manifest hash or size mismatch"),
        ] {
            let (s, replay) = store(vec![
                response(
                    200,
                    &[
                        ("etag", "e"),
                        ("content-length", "2"),
                        ("x-amz-version-id", "v1"),
                        ("x-amz-meta-sha256", &hash),
                    ],
                    "",
                ),
                response(200, &[], body),
            ]);
            let error = rt()
                .block_on(s.published_manifest("MANIFEST.json"))
                .err()
                .unwrap();
            assert_eq!(error.reason(), reason);
            let requests: Vec<_> = replay.actual_requests().collect();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[1].method(), "GET");
            assert!(requests[1].uri().contains("versionId=v1"));
            assert_eq!(requests[1].headers().get("if-match"), Some("e"));
        }
        let (s, replay) = store(vec![response(
            200,
            &[
                ("etag", "e"),
                ("content-length", "33554433"),
                ("x-amz-meta-sha256", &hash),
            ],
            "",
        )]);
        assert!(
            rt().block_on(s.published_manifest("MANIFEST.json"))
                .is_err()
        );
        assert_eq!(replay.actual_requests().count(), 1);
    }
}

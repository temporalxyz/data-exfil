//! Reuse committed database partitions without re-reading their data payloads.
use super::*;

pub(super) trait PublishedStore: Send + Sync {
    fn manifest<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Manifest>>>;
    fn head<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<store::PublishedHead>>>;
}
impl PublishedStore for store::S3Store {
    fn manifest<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Manifest>>> {
        Box::pin(self.published_manifest(key))
    }
    fn head<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<store::PublishedHead>>> {
        Box::pin(self.published_head(key))
    }
}

fn validate(pipeline: &Pipeline, day: &Day, manifest: &Manifest) -> Result<()> {
    if manifest.format != FORMAT
        || manifest.table != pipeline.identity.table
        || manifest.date != day.date
        || manifest.schema_source != "parquet"
        || !manifest.shape_review_signoff
        || !manifest.rotation_signoff
        || manifest.objects.is_empty()
    {
        return abort("published manifest identity or completion contract mismatch");
    }
    // This flag adopts the earlier audit revision, but must not silently discard custom rules.
    let policy = pipeline
        .native_policy
        .as_ref()
        .ok_or_else(|| usage::<()>("published reuse requires native policy").unwrap_err())?;
    if !policy.columns.is_empty()
        || !policy.types.is_empty()
        || !policy.iocs.is_empty()
        || manifest.incident_indicator_count != 0
        || !manifest.dropped_columns.is_empty()
        || !pipeline.overrides.columns.is_empty()
        || serde_json::to_value(&manifest.audit_limits).map_err(infrastructure)?
            != serde_json::to_value(&pipeline.overrides.limits).map_err(infrastructure)?
    {
        return abort(
            "published reuse requires matching default audit limits and no custom field policies",
        );
    }
    let prefix = pipeline.destination.key(&format!("{}/", day.prefix));
    let mut keys = std::collections::BTreeSet::new();
    let mut sources = BTreeMap::new();
    let mut rows = 0u64;
    for object in &manifest.objects {
        let Some(name) = object.key.strip_prefix(&prefix) else {
            return abort("published output lies outside its partition");
        };
        if name.is_empty()
            || name.contains('/')
            || !name.ends_with(".parquet")
            || !keys.insert(&object.key)
            || object.bytes == 0
            || object.receipt.etag.is_empty()
            || object.sha256.len() != 64
            || !object.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return abort("invalid or duplicate published object");
        }
        if let Some(previous) = sources.insert(&object.source.key, &object.source)
            && previous != &object.source
        {
            return abort("conflicting published source identities");
        }
        rows = rows
            .checked_add(object.rows)
            .ok_or_else(|| abort::<()>("published row count overflow").unwrap_err())?;
    }
    if rows != manifest.rows
        || sources.len() != day.sources.len()
        || day
            .sources
            .iter()
            .any(|s| sources.get(&s.key).is_none_or(|previous| **previous != *s))
    {
        return abort("published source inventory or row totals differ; cannot skip partition");
    }
    if manifest.source_schema_sha256.len() != 64
        || !manifest
            .source_schema_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return abort("invalid published source schema hash");
    }
    Ok(())
}

pub(super) async fn reuse(
    pipeline: &Pipeline,
    day: &Day,
    store: &dyn PublishedStore,
) -> Result<Option<u64>> {
    tracing::info!(
        table = pipeline.identity.table,
        day = day.date,
        "checking clean publication"
    );
    let key = pipeline.output_key(day, "MANIFEST.json");
    let Some(manifest) = store.manifest(&key).await? else {
        return Ok(None);
    };
    validate(pipeline, day, &manifest)?;
    let mut checks = futures::stream::iter(&manifest.objects)
        .map(|object| async move {
            let head = store.head(&object.key).await?.ok_or_else(|| {
                abort::<()>("committed output is missing from clean bucket").unwrap_err()
            })?;
            if head.source.size != object.bytes
                || head.source.etag != object.receipt.etag
                || head.source.version.as_deref()
                    != object.receipt.version.as_deref().filter(|v| *v != "null")
                || head.sha256 != object.sha256
            {
                return abort("committed output identity or hash metadata changed");
            }
            Ok(())
        })
        .buffer_unordered(4);
    while let Some(result) = checks.next().await {
        result?;
    }
    for report in [
        "SHAPE-REVIEW.json",
        "PAYLOAD-INVENTORY.json",
        "FIELD-AUDIT.json",
    ] {
        let head = store
            .head(&pipeline.output_key(day, report))
            .await?
            .ok_or_else(|| {
                abort::<()>("committed audit report is missing from clean bucket").unwrap_err()
            })?;
        if head.source.size == 0 {
            return abort("committed audit report is empty");
        }
    }
    std::fs::create_dir_all(&pipeline.work).map_err(infrastructure)?;
    {
        let _lock = pipeline.schema_lock.lock().map_err(infrastructure)?;
        let baseline = pipeline.work.join("REUSED-SOURCE-SCHEMA.json");
        if baseline.exists() && read_json::<String>(&baseline)? != manifest.source_schema_sha256 {
            return abort("reused partitions disagree on source schema");
        }
        let current = pipeline.work.join("SOURCE-SCHEMA.json");
        if current.exists() {
            let schema: arrow_schema::Schema = read_json(&current)?;
            let hash = crate::export::diff::sha256_hex(
                &serde_json::to_vec(&schema).map_err(infrastructure)?,
            );
            if hash != manifest.source_schema_sha256 {
                return abort("reused and newly audited source schemas differ");
            }
        }
        atomic_json(&baseline, &manifest.source_schema_sha256)?;
    }
    let work = pipeline.work.join(&day.date);
    std::fs::create_dir_all(&work).map_err(infrastructure)?;
    atomic_json(
        &work.join("REUSED.json"),
        &serde_json::json!({
            "manifest_key": key, "original_batch": manifest.batch, "original_git_commit": manifest.git_commit,
            "original_contract_sha256": manifest.contract_sha256, "rows": manifest.rows,
            "revalidated": false, "verification": "manifest hash and object HEAD identities; data bytes not reread"
        }),
    )?;
    tracing::info!(
        table = pipeline.identity.table,
        day = day.date,
        original_batch = manifest.batch,
        rows = manifest.rows,
        "skipping previously published partition"
    );
    Ok(Some(manifest.rows))
}

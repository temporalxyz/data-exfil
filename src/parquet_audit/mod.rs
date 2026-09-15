//! One table, independent day transactions, globally bounded download/check/upload pools.
mod database;
pub mod file;
pub mod policy;
pub mod profile;
mod published;
mod stop;
pub mod store;
pub mod target;
pub mod validation;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{FutureExt, StreamExt, future::BoxFuture};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::abort::{ExitCode, Result, SalvageError, abort, infra, usage};
use crate::cli::{Common, ParquetArgs};
use crate::models::Overrides;
use store::{Location, Receipt, Source, Store};

const MIB: u64 = 1024 * 1024;
const FORMAT: &str = "salvage-parquet-v2";

/// Log liveness without spawning detached tasks or changing cancellation semantics.
async fn stage_progress<T>(
    table: &str,
    day: &str,
    file: usize,
    stage: &str,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let started = Instant::now();
    tracing::info!(table, day, file, stage, "stage started");
    tokio::pin!(operation);
    loop {
        match tokio::time::timeout(Duration::from_secs(15), &mut operation).await {
            Ok(result) => {
                tracing::info!(
                    table,
                    day,
                    file,
                    stage,
                    seconds = started.elapsed().as_secs_f64(),
                    success = result.is_ok(),
                    "stage finished"
                );
                return result;
            }
            Err(_) => {
                tracing::info!(
                    table,
                    day,
                    file,
                    stage,
                    seconds = started.elapsed().as_secs_f64(),
                    "stage still running"
                );
            }
        }
    }
}

pub fn infrastructure(e: impl std::fmt::Display) -> SalvageError {
    infra::<()>(format!("Parquet pipeline infrastructure error: {e}")).unwrap_err()
}
pub fn finding_error(_e: impl std::fmt::Display) -> SalvageError {
    // Parser diagnostics may quote raw field bytes. Findings never echo those diagnostics.
    abort::<()>("invalid native Parquet structure or value").unwrap_err()
}

pub fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let mut partial_name = path.as_os_str().to_owned();
    partial_name.push(".partial");
    let partial = PathBuf::from(partial_name);
    let mut guard = crate::abort::PartialOutput::new(partial);
    let mut file = std::fs::File::create(guard.path()).map_err(infrastructure)?;
    serde_json::to_writer_pretty(&mut file, value).map_err(infrastructure)?;
    file.write_all(b"\n").map_err(infrastructure)?;
    file.sync_all().map_err(infrastructure)?;
    drop(file);
    guard.commit_as(path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .map_err(infrastructure)?
            .sync_all()
            .map_err(infrastructure)?;
    }
    Ok(())
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = std::fs::File::open(path).map_err(infrastructure)?;
    if file.metadata().map_err(infrastructure)?.len() > 64 * MIB {
        return abort("checkpoint exceeds metadata size cap");
    }
    serde_json::from_reader(std::io::BufReader::new(file))
        .map_err(|_| abort::<()>("invalid Parquet checkpoint").unwrap_err())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tuning {
    pub days: usize,
    pub downloads: usize,
    pub checks: usize,
    pub uploads: usize,
    pub memory_bytes: u64,
    pub worker_memory_bytes: u64,
    pub scratch_bytes: u64,
    pub day_scratch_bytes: u64,
    pub batch_rows: usize,
    pub row_group_bytes: u64,
    pub chunk_bytes: u64,
}

impl Tuning {
    fn resolve(args: &ParquetArgs) -> Result<Self> {
        let cores = std::thread::available_parallelism().map_or(1, usize::from);
        let desired_checks = args.check_concurrency.unwrap_or(cores);
        if [
            args.day_concurrency,
            args.download_concurrency,
            desired_checks,
            args.upload_concurrency,
            args.batch_rows,
        ]
        .contains(&0)
        {
            return usage("concurrency and batch rows must be positive");
        }
        if args.worker_memory_bytes < 256 * MIB
            || args.max_day_scratch_bytes == 0
            || args.row_group_bytes == 0
            || args.output_chunk_bytes == 0
        {
            return usage(
                "worker memory must be at least 256 MiB; scratch and writer budgets must be positive",
            );
        }
        if args.row_group_bytes > args.worker_memory_bytes / 4 {
            return usage("row group target must fit in one quarter of worker memory");
        }
        let days = args.day_concurrency.min(
            usize::try_from(args.scratch_bytes / args.max_day_scratch_bytes).unwrap_or(usize::MAX),
        );
        if days == 0 {
            return usage("scratch budget cannot admit one day");
        }
        // Controller, bounded metadata, and transport headroom are reserved separately from
        // isolated workers. Part streams use disk-backed ByteStreams, not complete file buffers.
        let headroom = 256 * MIB;
        let available = args
            .memory_bytes
            .saturating_sub(headroom)
            .saturating_sub(args.worker_memory_bytes);
        if available < 2 * MIB {
            return usage(
                "memory budget cannot admit one worker plus controller and transfer headroom",
            );
        }
        let downloads = args
            .download_concurrency
            .min((available / (2 * MIB)).min(usize::MAX as u64) as usize)
            .max(1);
        let remaining = available.saturating_sub(downloads as u64 * MIB);
        let uploads = args
            .upload_concurrency
            .min((remaining / MIB).min(usize::MAX as u64) as usize)
            .max(1);
        let reserve = headroom + (downloads + uploads) as u64 * MIB;
        let checks = desired_checks.min(
            ((args.memory_bytes - reserve) / args.worker_memory_bytes).min(usize::MAX as u64)
                as usize,
        );
        if checks == 0 {
            return usage("memory budget cannot admit one validation worker");
        }
        Ok(Self {
            days,
            downloads,
            checks,
            uploads,
            memory_bytes: args.memory_bytes,
            worker_memory_bytes: args.worker_memory_bytes,
            scratch_bytes: args.scratch_bytes,
            day_scratch_bytes: args.max_day_scratch_bytes,
            batch_rows: args.batch_rows,
            row_group_bytes: args.row_group_bytes,
            chunk_bytes: args.output_chunk_bytes,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub format: String,
    pub table: String,
    pub batch: String,
    pub source: String,
    #[serde(default)]
    pub source_layout: crate::cli::ParquetSourceLayout,
    #[serde(default)]
    pub preserve_paths: bool,
    #[serde(default)]
    pub skip_published: bool,
    pub destination: String,
    pub from: String,
    pub through: String,
    pub contract_sha256: String,
    pub survey: bool,
    pub dry_run: bool,
    pub retain_days: u32,
    pub batch_rows: usize,
    pub row_group_bytes: u64,
    pub chunk_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Day {
    pub date: String,
    pub prefix: String,
    pub sources: Vec<Source>,
}
#[derive(Serialize, Deserialize)]
struct Inventory {
    identity: Identity,
    imported_at: String,
    days: Vec<Day>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Status {
    state: String,
    reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestObject {
    pub source: Source,
    pub input_sha256: String,
    pub key: String,
    pub bytes: u64,
    pub rows: u64,
    pub sha256: String,
    pub receipt: Receipt,
}

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub table: String,
    pub batch: String,
    pub date: String,
    pub contract_sha256: String,
    pub git_commit: String,
    pub schema: arrow_schema::Schema,
    pub rows: u64,
    pub objects: Vec<ManifestObject>,
    pub dropped_columns: Vec<String>,
    pub schema_source: String,
    pub source_schema_sha256: String,
    /// Hash of the pinned target schema this partition was projected onto, empty when none was.
    #[serde(default)]
    pub target_schema_sha256: String,
    /// Columns written entirely as nulls because this partition predates the migration that added
    /// them. A null here is not a null that was in the source.
    #[serde(default)]
    pub padded_columns: Vec<String>,
    pub audit_limits: crate::limits::Limits,
    pub independent_revalidation: bool,
    pub field_audits: Vec<validation::FieldAudit>,
    pub incident_indicator_count: usize,
    pub clickhouse_insert_tested: bool,
    pub consumer_must_revalidate: bool,
    pub shape_review_signoff: bool,
    pub rotation_signoff: bool,
}

/// Worker seam: production uses an isolated process; tests exercise the same file audit in
/// process to avoid depending on an installed executable or a Linux host.
pub trait Worker: Send + Sync {
    fn check(&self, job: file::Job) -> BoxFuture<'_, Result<file::Checked>>;
}
pub struct ProcessWorker;
impl Worker for ProcessWorker {
    fn check(&self, job: file::Job) -> BoxFuture<'_, Result<file::Checked>> {
        Box::pin(async move {
            let job_path = job.work.join("job.json");
            atomic_json(&job_path, &job)?;
            let executable = std::env::current_exe().map_err(infrastructure)?;
            let mut child = tokio::process::Command::new(executable)
                .arg("parquet-worker")
                .arg(&job_path)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(infrastructure)?;
            let started = Instant::now();
            let cancel = job.work.parent().unwrap().join("CANCEL");
            let status = loop {
                if let Some(status) = child.try_wait().map_err(infrastructure)? {
                    break status;
                }
                if cancel.exists()
                    || job.stop_path.as_ref().is_some_and(|p| p.exists())
                    || started.elapsed().as_secs() >= job.overrides.limits.wall_clock_secs
                {
                    child.kill().await.map_err(infrastructure)?;
                    return infra("validation worker cancelled or exceeded wall-clock budget");
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            };
            match status.code() {
                Some(0) => read_json(&job.work.join("checked.json")),
                Some(3) => infra(
                    "validation worker infrastructure/resource failure; inspect worker-error.json",
                ),
                Some(2) => {
                    usage("validation worker configuration failure; inspect worker-error.json")
                }
                _ => abort(
                    "validation worker rejected input or terminated abnormally; inspect findings.jsonl and worker-error.json",
                ),
            }
        })
    }
}

pub fn worker_command(path: &Path) -> Result<()> {
    let job: file::Job = read_json(path)?;
    #[cfg(target_os = "linux")]
    rlimit::setrlimit(rlimit::Resource::AS, job.memory_bytes, job.memory_bytes)
        .map_err(infrastructure)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = job;
        usage(
            "isolated Parquet workers require Linux address-space limits; offline unit tests remain portable",
        )
    }
    #[cfg(target_os = "linux")]
    {
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(job.work.join("worker.lock"))
            .map_err(infrastructure)?;
        lock.try_lock().map_err(infrastructure)?;
        rlimit::setrlimit(
            rlimit::Resource::CPU,
            job.overrides.limits.wall_clock_secs,
            job.overrides.limits.wall_clock_secs,
        )
        .map_err(infrastructure)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| file::check(&job)))
            .unwrap_or_else(|_| abort("validation worker panicked; entire run stopped"));
        if let Err(error) = &result {
            if let Some(path) = &job.stop_path {
                stop::persist(path, error.reason())?;
            }
            atomic_json(
                &job.work.join("worker-error.json"),
                &Status {
                    state: format!("exit-{}", error.exit_code().as_i32()),
                    reason: error.reason().into(),
                },
            )?;
        }
        result.map(|_| ())
    }
}

/// Distinct source schemas one table may present across a run before it stops looking like a
/// migration. Also keeps SOURCE-SCHEMAS.json well inside `read_json`'s size ceiling.
const MAX_OBSERVED_SOURCE_SCHEMAS: usize = 16;

pub struct Pipeline {
    pub identity: Identity,
    pub work: PathBuf,
    pub destination: Location,
    pub ddl: String,
    pub native_policy: Option<policy::TablePolicy>,
    /// Pinned target schema for this table. Set when `--prod-schema-dir` supplied one; the output
    /// then follows it and migrated-in columns are padded with nulls.
    pub target_schema: Option<arrow_schema::Schema>,
    schema_lock: std::sync::Mutex<()>,
    published_store: Option<Arc<dyn published::PublishedStore>>,
    stop: Arc<stop::Stop>,
    pub overrides: Overrides,
    pub tuning: Tuning,
    pub imported_at: String,
    pub resume: bool,
    pub raw: Arc<dyn Store>,
    pub clean: Arc<dyn Store>,
    pub worker: Arc<dyn Worker>,
    downloads: Arc<Semaphore>,
    checks: Arc<Semaphore>,
    uploads: Arc<Semaphore>,
}

impl Pipeline {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: Identity,
        work: PathBuf,
        destination: Location,
        ddl: String,
        overrides: Overrides,
        tuning: Tuning,
        imported_at: String,
        resume: bool,
        raw: Arc<dyn Store>,
        clean: Arc<dyn Store>,
        worker: Arc<dyn Worker>,
    ) -> Self {
        let stop = Arc::new(stop::Stop::new(&work));
        let raw = Arc::new(stop::StoreWithStop {
            inner: raw,
            stop: stop.clone(),
        });
        let clean = Arc::new(stop::StoreWithStop {
            inner: clean,
            stop: stop.clone(),
        });
        Self {
            stop,
            downloads: Arc::new(Semaphore::new(tuning.downloads)),
            checks: Arc::new(Semaphore::new(tuning.checks)),
            uploads: Arc::new(Semaphore::new(tuning.uploads)),
            identity,
            work,
            destination,
            ddl,
            native_policy: None,
            target_schema: None,
            schema_lock: std::sync::Mutex::new(()),
            published_store: None,
            overrides,
            tuning,
            imported_at,
            resume,
            raw,
            clean,
            worker,
        }
    }

    fn output_key(&self, day: &Day, name: &str) -> String {
        if self.identity.preserve_paths {
            self.destination.key(&format!("{}/{name}", day.prefix))
        } else {
            self.destination
                .key(&format!("{}/{}/{name}", self.identity.batch, day.prefix))
        }
    }

    async fn run_day(&self, day: &Day) -> Result<u64> {
        if self.stop.stopped() {
            return abort("run stopped; partition not started");
        }
        tracing::info!(
            table = self.identity.table,
            day = day.date,
            files = day.sources.len(),
            verify = self.identity.dry_run,
            "partition started"
        );
        let result = std::panic::AssertUnwindSafe(async {
            if let Some(store) = &self.published_store
                && let Some(rows) = self
                    .stop
                    .transfer(published::reuse(self, day, store.as_ref()))
                    .await?
            {
                return Ok(rows);
            }
            self.day(day).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| abort("partition panicked; entire run stopped"));
        if let Err(error) = &result {
            self.stop.trip(error);
        }
        result
    }

    pub async fn run(&self, days: &[Day]) -> Result<()> {
        if self.native_policy.is_some() {
            self.stop.enable()?;
        }
        let started = Instant::now();
        let mut reports = BTreeMap::new();
        let mut failed = false;
        let mut infrastructure_failed = false;
        let mut completed = 0usize;
        let mut total_rows = 0u64;
        let mut work = futures::stream::iter(days.iter().take_while(|_| !self.stop.stopped()))
            .map(|day| async move {
                let result = self.run_day(day).await;
                (day.date.clone(), result)
            })
            .buffer_unordered(self.tuning.days);
        while let Some((date, result)) = work.next().await {
            let (state, reason) = match result {
                Ok(rows) => {
                    completed += 1;
                    total_rows = total_rows.saturating_add(rows);
                    ("complete", format!("{rows} rows"))
                }
                Err(e) => {
                    if e.exit_code() == ExitCode::Abort {
                        failed = true;
                    } else {
                        infrastructure_failed = true;
                    }
                    (
                        if e.exit_code() == ExitCode::Abort {
                            "failed"
                        } else {
                            "interrupted"
                        },
                        e.reason().to_owned(),
                    )
                }
            };
            tracing::info!(
                day = date,
                state,
                reason,
                elapsed_secs = started.elapsed().as_secs_f64(),
                "day finished"
            );
            reports.insert(
                date,
                Status {
                    state: state.into(),
                    reason,
                },
            );
            if let Err(error) = atomic_json(&self.work.join("report.json"), &reports) {
                self.stop.trip(&error);
                infrastructure_failed = true;
            }
        }
        finish_report(
            &self.work,
            self.identity.dry_run,
            self.identity.survey,
            failed || infrastructure_failed,
            completed,
            days.len(),
            total_rows,
        )?;
        if failed {
            abort("one or more days failed audit; those days were not published")
        } else if infrastructure_failed {
            infra("one or more days were interrupted; resume with the same inventory")
        } else {
            Ok(())
        }
    }

    async fn day(&self, day: &Day) -> Result<u64> {
        let work = self.work.join(&day.date);
        std::fs::create_dir_all(&work).map_err(infrastructure)?;
        let status_path = work.join("status.json");
        if status_path.exists() {
            if !self.resume {
                return usage(
                    "day already exists; use --resume for an infrastructure interruption or a new batch id",
                );
            }
            let status: Status = read_json(&status_path)?;
            if self.native_policy.is_some() && status.state != "complete" {
                return abort(
                    "previous partition attempt is incomplete or failed; inspect diagnostics and use a new batch",
                );
            }
            if status.state == "failed" {
                return abort("cannot resume a failed audit day; use a new batch id");
            }
            if status.state == "checking" {
                // A killed controller cannot leave an unobserved finding resumable. Inspect
                // durable findings first, then restart this entire uncommitted day from raw.
                for index in 0..day.sources.len() {
                    let dir = work.join(format!("file-{index:06}"));
                    if std::fs::metadata(dir.join("findings.jsonl")).is_ok_and(|m| m.len() > 0) {
                        atomic_json(
                            &status_path,
                            &Status {
                                state: "failed".into(),
                                reason: "finding recorded before controller interruption".into(),
                            },
                        )?;
                        return abort(
                            "interrupted day contains a recorded finding; use a new batch id",
                        );
                    }
                    let error = dir.join("worker-error.json");
                    if error.exists() && read_json::<Status>(&error)?.state == "exit-1" {
                        atomic_json(
                            &status_path,
                            &Status {
                                state: "failed".into(),
                                reason: "worker rejected input before controller interruption"
                                    .into(),
                            },
                        )?;
                        return abort(
                            "interrupted day contains a worker rejection; use a new batch id",
                        );
                    }
                }
                cleanup_data(&work, day.sources.len())?;
            }
            if status.state == "complete" {
                let count: u64 = read_json(&work.join("rows.json"))?;
                if !self.identity.survey && !self.identity.dry_run {
                    let path = work.join("MANIFEST.json");
                    let sha = file::hash_file(&path)?;
                    let key = self.output_key(day, "MANIFEST.json");
                    let _permit = self.uploads.acquire().await.map_err(infrastructure)?;
                    self.clean
                        .upload(&key, &path, &sha, &work.join("manifest-session.json"))
                        .await?;
                }
                return Ok(count);
            }
        }
        if day.sources.is_empty() {
            atomic_json(
                &status_path,
                &Status {
                    state: "absent".into(),
                    reason: "no Parquet objects for requested date".into(),
                },
            )?;
            return infra("requested date contains no Parquet objects; see inventory");
        }
        let raw_bytes = day.sources.iter().try_fold(0u64, |sum, s| {
            sum.checked_add(s.size)
                .ok_or_else(|| usage::<()>("day source size overflow").unwrap_err())
        })?;
        if raw_bytes >= self.tuning.day_scratch_bytes
            || day
                .sources
                .iter()
                .any(|s| s.size > self.overrides.limits.max_compressed_bytes || s.size < 12)
        {
            return usage(
                "day or source object exceeds scratch/pinned file limits; adjust budgets before processing",
            );
        }
        atomic_json(
            &status_path,
            &Status {
                state: "checking".into(),
                reason: String::new(),
            },
        )?;
        let outcome = self.day_inner(day, &work, raw_bytes).await;
        let state = match &outcome {
            Ok(_) => "complete",
            Err(e) if e.exit_code() == ExitCode::Abort => "failed",
            Err(_) => "interrupted",
        };
        atomic_json(
            &status_path,
            &Status {
                state: state.into(),
                reason: outcome
                    .as_ref()
                    .err()
                    .map_or(String::new(), |e| e.reason().into()),
            },
        )?;
        if outcome.is_err() || self.identity.survey || self.identity.dry_run {
            // Diagnostics and S3 multipart sessions survive, data does not occupy a released
            // day reservation. Infrastructure resume regenerates deterministic chunks from raw.
            cleanup_data(&work, day.sources.len())?;
        }
        outcome
    }

    async fn day_inner(&self, day: &Day, work: &Path, raw_bytes: u64) -> Result<u64> {
        let started = Instant::now();
        let cancel = work.join("CANCEL");
        if self.stop.stopped() {
            return abort("run stopped");
        }
        if cancel.exists() {
            std::fs::remove_file(&cancel).map_err(infrastructure)?;
        }
        let overhead = (day.sources.len() as u64 + 1).saturating_mul(4 * MIB);
        let output_pool = self
            .tuning
            .day_scratch_bytes
            .checked_sub(raw_bytes)
            .and_then(|v| v.checked_sub(overhead))
            .filter(|v| *v > 0)
            .ok_or_else(|| {
                usage::<()>("day scratch budget must also cover diagnostic/checkpoint reservations")
                    .unwrap_err()
            })?;
        let window = self.tuning.downloads + self.tuning.checks;
        let mut files = futures::stream::iter(day.sources.iter().enumerate())
            .map(|(index, source)| {
                let cancel = &cancel;
                async move {
                    if cancel.exists() || self.stop.stopped() {
                        return infra("day cancelled");
                    }
                    let file_work = work.join(format!("file-{index:06}"));
                    std::fs::create_dir_all(&file_work).map_err(infrastructure)?;
                    let checked_path = file_work.join("checked.json");
                    let checked = if self.resume && checked_path.exists() {
                        let checked: file::Checked = read_json(&checked_path)?;
                        for output in &checked.outputs {
                            if file::hash_file(&file_work.join(&output.name))? != output.sha256 {
                                return abort("local checkpoint output hash mismatch");
                            }
                        }
                        checked
                    } else {
                        let input = file_work.join("raw.parquet");
                        let download_wait = Instant::now();
                        let permit = self.downloads.acquire().await.map_err(infrastructure)?;
                        if cancel.exists() || self.stop.stopped() {
                            return infra("day cancelled");
                        }
                        let download_started = Instant::now();
                        let sha = stage_progress(
                            &self.identity.table,
                            &day.date,
                            index,
                            "download",
                            self.raw.download(source, &input),
                        )
                        .await?;
                        tracing::info!(
                            table = self.identity.table,
                            day = day.date,
                            file = index,
                            bytes = source.size,
                            wait_secs = download_wait.elapsed().as_secs_f64()
                                - download_started.elapsed().as_secs_f64(),
                            seconds = download_started.elapsed().as_secs_f64(),
                            "download complete"
                        );
                        drop(permit);
                        let _permit = self.checks.acquire().await.map_err(infrastructure)?;
                        if cancel.exists() || self.stop.stopped() {
                            return infra("day cancelled");
                        }
                        let output_budget = ((u128::from(output_pool) * u128::from(source.size))
                            / u128::from(raw_bytes))
                            as u64;
                        let checked = std::panic::AssertUnwindSafe(stage_progress(
                            &self.identity.table,
                            &day.date,
                            index,
                            "audit",
                            self.worker.check(file::Job {
                                table: self.identity.table.clone(),
                                input: input.clone(),
                                work: file_work.clone(),
                                ddl: self.ddl.clone(),
                                native_policy: self.native_policy.clone(),
                                target_schema: self.target_schema.clone(),
                                stop_path: self
                                    .native_policy
                                    .as_ref()
                                    .map(|_| self.stop.path.clone()),
                                overrides: self.overrides.clone(),
                                source_object: format!(
                                    "{}/{}",
                                    self.identity
                                        .source
                                        .trim_end_matches('/')
                                        .split('/')
                                        .take(3)
                                        .collect::<Vec<_>>()
                                        .join("/"),
                                    source.key
                                ),
                                batch: self.identity.batch.clone(),
                                imported_at: self.imported_at.clone(),
                                file_index: index as u32,
                                survey: self.identity.survey,
                                batch_rows: self.tuning.batch_rows,
                                row_group_bytes: self.tuning.row_group_bytes,
                                chunk_bytes: self.tuning.chunk_bytes,
                                memory_bytes: self.tuning.worker_memory_bytes,
                                output_budget,
                            }),
                        ))
                        .catch_unwind()
                        .await
                        .unwrap_or_else(|_| {
                            abort("validation worker panicked; entire run stopped")
                        });
                        if let Err(error) = &checked {
                            self.stop.trip(error);
                        }
                        let checked = checked?;
                        tracing::info!(
                            table = self.identity.table,
                            day = day.date,
                            file = index,
                            rows = checked.rows,
                            output_chunks = checked.outputs.len(),
                            decode_secs = checked.timings.decode_secs,
                            validation_secs = checked.timings.validation_secs,
                            profile_secs = checked.timings.profile_secs,
                            write_secs = checked.timings.write_secs,
                            "file audit complete"
                        );
                        if sha != checked.input_sha256 {
                            return abort("downloaded source changed before/during audit");
                        }
                        std::fs::remove_file(input).map_err(infrastructure)?;
                        checked
                    };
                    Ok::<_, SalvageError>((index, checked))
                }
            })
            .buffer_unordered(window);
        let mut checked = BTreeMap::new();
        let mut first_error = None;
        let mut metadata_bytes = 0u64;
        while let Some(result) = files.next().await {
            match result {
                Ok((index, result)) if first_error.is_none() => {
                    metadata_bytes +=
                        serde_json::to_vec(&result).map_err(infrastructure)?.len() as u64;
                    if metadata_bytes > 32 * MIB / self.tuning.days as u64 {
                        first_error = Some(infra::<()>("day checkpoint metadata exceeds controller reservation; reduce day concurrency or files per run").unwrap_err());
                        std::fs::write(&cancel, []).map_err(infrastructure)?;
                    } else {
                        checked.insert(index, result);
                    }
                }
                Err(e) => {
                    if first_error.as_ref().is_none_or(|previous: &SalvageError| {
                        e.exit_code() == ExitCode::Abort && previous.exit_code() != ExitCode::Abort
                    }) {
                        first_error = Some(e);
                    }
                    std::fs::write(&cancel, []).map_err(infrastructure)?;
                }
                _ => {}
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        let first = checked
            .values()
            .next()
            .ok_or_else(|| abort::<()>("day has no checked files").unwrap_err())?;
        let first_schema = &first.schema;
        if checked.values().any(|c| &c.schema != first_schema) {
            return abort("native Parquet schema differs between files in a day");
        }
        // Checked as its own question rather than left to the output comparison above: with a
        // pinned target every file in the day projects onto the same output schema by
        // construction, so that check would pass while the files disagreed about what they hold.
        // FIELD-AUDIT.json and the manifest's field audits are taken from one file and speak for
        // the whole partition, which is only true if the files agree.
        let first_input_schema = &first.input_schema;
        if checked
            .values()
            .any(|c| &c.input_schema != first_input_schema)
        {
            return abort("native Parquet source schema differs between files in a day");
        }
        // Pin the complete source schema, including dropped columns, across this table's days.
        // Publication is per partition; a later drift rejects that partition, never mutates the baseline.
        if self.native_policy.is_some() {
            let _lock = self.schema_lock.lock().map_err(infrastructure)?;
            if self.target_schema.is_some() {
                // The pinned target, not the first file observed, is what every day must agree
                // with -- that agreement was already enforced per file while building the
                // contract. Source schemas may now legitimately differ across the migration, so
                // they are recorded for the audit trail instead of gating.
                let path = self.work.join("SOURCE-SCHEMAS.json");
                let mut observed: Vec<arrow_schema::Schema> = if path.exists() {
                    read_json(&path)?
                } else {
                    Vec::new()
                };
                if !observed.iter().any(|s| s == first_input_schema) {
                    if observed.len() >= MAX_OBSERVED_SOURCE_SCHEMAS {
                        return abort(
                            "table presents more distinct source schemas than a migration explains",
                        );
                    }
                    observed.push(first_input_schema.clone());
                    atomic_json(&path, &observed)?;
                }
            } else {
                let reused_schema = self.work.join("REUSED-SOURCE-SCHEMA.json");
                if reused_schema.exists() {
                    let expected: String = read_json(&reused_schema)?;
                    let actual = crate::export::diff::sha256_hex(
                        &serde_json::to_vec(&first.input_schema).map_err(infrastructure)?,
                    );
                    if actual != expected {
                        return abort("source schema differs from reused published partitions");
                    }
                }
                let path = self.work.join("SOURCE-SCHEMA.json");
                let baseline = if path.exists() {
                    read_json::<arrow_schema::Schema>(&path)?
                } else {
                    let baseline = first.input_schema.clone();
                    atomic_json(&path, &baseline)?;
                    baseline
                };
                if checked.values().any(|c| c.input_schema != baseline) {
                    return abort("native source schema drift across files/days of the table");
                }
            }
        }
        atomic_json(
            &work.join("FIELD-AUDIT.json"),
            &checked.values().next().unwrap().field_audits,
        )?;
        let rows = checked.values().try_fold(0u64, |sum, c| {
            sum.checked_add(c.rows)
                .ok_or_else(|| abort::<()>("day row count overflow").unwrap_err())
        })?;
        atomic_json(
            &work.join("SHAPE-REVIEW.json"),
            &checked
                .iter()
                .map(|(i, c)| (i, &c.profile))
                .collect::<BTreeMap<_, _>>(),
        )?;
        atomic_json(
            &work.join("PAYLOAD-INVENTORY.json"),
            &checked
                .iter()
                .map(|(i, c)| (i, &c.finding_rows_by_column))
                .collect::<BTreeMap<_, _>>(),
        )?;
        if checked.values().any(|c| c.findings > 0) {
            return abort("survey found field/injection violations; day is not publishable");
        }
        if self.identity.survey || self.identity.dry_run {
            atomic_json(&work.join("rows.json"), &rows)?;
            return Ok(rows);
        }
        if self.stop.stopped() {
            return abort("run stopped before publication");
        }
        // The day barrier is here: no clean-store operation is reachable before every file has
        // passed schema, field and payload checks and schema reconciliation.
        atomic_json(
            &work.join("status.json"),
            &Status {
                state: "uploading".into(),
                reason: String::new(),
            },
        )?;
        let jobs: Vec<_> = checked
            .iter()
            .flat_map(|(index, c)| c.outputs.iter().map(move |o| (*index, c, o)))
            .collect();
        let mut uploads = futures::stream::iter(jobs)
            .map(|(index, checked, output)| async move {
                let _permit = self.uploads.acquire().await.map_err(infrastructure)?;
                let name = if self.identity.preserve_paths {
                    format!("{}-file-{index:06}-{}", self.identity.batch, output.name)
                } else {
                    format!("file-{index:06}-{}", output.name)
                };
                let key = self.output_key(day, &name);
                let dir = work.join(format!("file-{index:06}"));
                let receipt = stage_progress(
                    &self.identity.table,
                    &day.date,
                    index,
                    "upload",
                    self.clean.upload(
                        &key,
                        &dir.join(&output.name),
                        &output.sha256,
                        &dir.join(format!("{}.session.json", output.name)),
                    ),
                )
                .await?;
                tracing::info!(
                    table = self.identity.table,
                    day = day.date,
                    file = index,
                    chunk = output.name,
                    bytes = output.bytes,
                    rows = output.rows,
                    "upload complete"
                );
                Ok::<_, SalvageError>(ManifestObject {
                    source: day.sources[index].clone(),
                    input_sha256: checked.input_sha256.clone(),
                    key,
                    bytes: output.bytes,
                    rows: output.rows,
                    sha256: output.sha256.clone(),
                    receipt,
                })
            })
            .buffer_unordered(self.tuning.uploads);
        let mut objects = Vec::new();
        while let Some(result) = uploads.next().await {
            objects.push(result?);
        }
        objects.sort_by(|a, b| a.key.cmp(&b.key));
        let manifest = Manifest {
            format: FORMAT.into(),
            table: self.identity.table.clone(),
            batch: self.identity.batch.clone(),
            date: day.date.clone(),
            contract_sha256: self.identity.contract_sha256.clone(),
            git_commit: crate::export::plan::GIT_COMMIT.into(),
            schema: first_schema.clone(),
            rows,
            objects,
            dropped_columns: self
                .overrides
                .columns
                .iter()
                .filter(|(_, c)| c.drop)
                .map(|(name, _)| name.clone())
                .collect(),
            source_schema_sha256: crate::export::diff::sha256_hex(
                &serde_json::to_vec(&checked.values().next().unwrap().input_schema)
                    .map_err(infrastructure)?,
            ),
            audit_limits: self.overrides.limits.clone(),
            target_schema_sha256: match &self.target_schema {
                Some(target) => crate::export::diff::sha256_hex(
                    &serde_json::to_vec(target).map_err(infrastructure)?,
                ),
                None => String::new(),
            },
            // Taken from the same file as `field_audits` and `schema`, which the per-day source
            // schema check above proves speaks for every file in the partition.
            padded_columns: checked.values().next().unwrap().padded_columns.clone(),
            // A distinct value, not a flag: it makes a manifest written under projection
            // unreusable by a run without it, and the reverse, rather than leaving the two kinds
            // of partition to be told apart by a field that defaults to empty.
            schema_source: match (self.native_policy.is_some(), self.target_schema.is_some()) {
                (true, true) => "parquet+target",
                (true, false) => "parquet",
                (false, _) => "pinned-ddl",
            }
            .into(),
            independent_revalidation: false,
            field_audits: checked.values().next().unwrap().field_audits.clone(),
            incident_indicator_count: self.native_policy.as_ref().map_or(0, |p| p.iocs.len()),
            clickhouse_insert_tested: false,
            consumer_must_revalidate: true,
            shape_review_signoff: true,
            rotation_signoff: true,
        };
        for name in [
            "SHAPE-REVIEW.json",
            "PAYLOAD-INVENTORY.json",
            "FIELD-AUDIT.json",
        ] {
            let _permit = self.uploads.acquire().await.map_err(infrastructure)?;
            let path = work.join(name);
            self.clean
                .upload(
                    &self.output_key(day, name),
                    &path,
                    &file::hash_file(&path)?,
                    &work.join(format!("{name}.session.json")),
                )
                .await?;
        }
        let path = work.join("MANIFEST.json");
        atomic_json(&path, &manifest)?;
        let _permit = self.uploads.acquire().await.map_err(infrastructure)?;
        self.clean
            .upload(
                &self.output_key(day, "MANIFEST.json"),
                &path,
                &file::hash_file(&path)?,
                &work.join("manifest-session.json"),
            )
            .await?;
        atomic_json(&work.join("rows.json"), &rows)?;
        // Commit local completion before reclaiming scratch, so a crash during cleanup cannot
        // turn missing regenerated files into an ambiguous/incomplete audit on resume.
        atomic_json(
            &work.join("status.json"),
            &Status {
                state: "complete".into(),
                reason: String::new(),
            },
        )?;
        for (index, c) in &checked {
            for output in &c.outputs {
                if let Err(e) =
                    std::fs::remove_file(work.join(format!("file-{index:06}")).join(&output.name))
                {
                    tracing::warn!(error = %e, "committed output scratch cleanup failed");
                }
            }
        }
        tracing::info!(
            day = day.date,
            rows,
            source_bytes = raw_bytes,
            seconds = started.elapsed().as_secs_f64(),
            rows_per_sec = rows as f64 / started.elapsed().as_secs_f64().max(0.001),
            "day committed"
        );
        Ok(rows)
    }
}

/// Hash the pinned contract a resume must match.
///
/// With no prod schema the tuple is left exactly as it was, five elements and no placeholder, so
/// adding this feature does not change a single existing table's hash and every in-flight resume
/// keeps working. A prod schema appends its SQL, so editing that file after a run starts is
/// caught the same way an edited override is.
fn contract_hash(
    native: &policy::TablePolicy,
    overrides: &Overrides,
    prod: Option<&target::ProdSchema>,
) -> Result<String> {
    const HEAD: (&str, &str, &str) = (FORMAT, crate::export::plan::GIT_COMMIT, "parquet-schema");
    let contract = match prod {
        None => serde_json::to_vec(&(HEAD.0, HEAD.1, HEAD.2, native, overrides)),
        Some(prod) => {
            serde_json::to_vec(&(HEAD.0, HEAD.1, HEAD.2, native, overrides, prod.sql.as_str()))
        }
    }
    .map_err(infrastructure)?;
    Ok(crate::export::diff::sha256_hex(&contract))
}

fn source_day_prefix(
    layout: crate::cli::ParquetSourceLayout,
    date: time::Date,
    table: &str,
) -> String {
    let day = format!(
        "{:04}/{:02}/{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    );
    match layout {
        crate::cli::ParquetSourceLayout::DateTable => format!("{day}/{table}/"),
        crate::cli::ParquetSourceLayout::TableDate => format!("{table}/{day}/"),
    }
}

fn dates(from: &str, through: &str) -> Result<Vec<time::Date>> {
    let format = time::macros::format_description!("[year]-[month]-[day]");
    let start = time::Date::parse(from, &format)
        .map_err(|_| usage::<()>("--from must be YYYY-MM-DD").unwrap_err())?;
    let end = time::Date::parse(through, &format)
        .map_err(|_| usage::<()>("--through must be YYYY-MM-DD").unwrap_err())?;
    if start > end {
        return usage("--from must not be after --through");
    }
    let mut days = Vec::new();
    let mut next = start;
    loop {
        if days.len() >= 36600 {
            return usage("date range exceeds 100 years");
        }
        days.push(next);
        if next == end {
            return Ok(days);
        }
        next = next
            .next_day()
            .ok_or_else(|| usage::<()>("date range overflow").unwrap_err())?;
    }
}

fn finish_report(
    work: &Path,
    verify: bool,
    survey: bool,
    stopped: bool,
    completed: usize,
    partitions: usize,
    rows: u64,
) -> Result<()> {
    let status = if stopped {
        "stopped"
    } else if verify {
        "verified"
    } else if survey {
        "surveyed"
    } else {
        "published"
    };
    atomic_json(
        &work.join("RESULT.json"),
        &serde_json::json!({
            "status": status, "completed_partitions": completed, "selected_partitions": partitions,
            "rows_in_completed_partitions": rows, "s3_writes_disabled": verify || survey,
            "clickhouse_insert_tested": false, "independent_revalidation": false,
        }),
    )?;
    eprintln!(
        "Parquet run {status}: {completed}/{partitions} partitions, {rows} rows in completed partitions; report {}",
        work.join("RESULT.json").display()
    );
    Ok(())
}

fn destination_uri(args: &ParquetArgs) -> &str {
    args.destination
        .as_deref()
        .unwrap_or("s3://salvage-verify-unused")
}

pub fn command(common: &Common, args: &ParquetArgs) -> Result<()> {
    if args.database.is_some() {
        return database::command(common, args);
    }
    let table_ref = args
        .table
        .as_ref()
        .ok_or_else(|| usage::<()>("--table or --database is required").unwrap_err())?;
    let source = Location::parse(&args.source)?;
    let destination = Location::parse(destination_uri(args))?;
    if source.bucket == destination.bucket {
        return usage("raw and clean Parquet data require separate S3 buckets");
    }
    let from = args
        .from
        .as_deref()
        .ok_or_else(|| usage::<()>("--from is required for single-table mode").unwrap_err())?;
    let through = args
        .through
        .as_deref()
        .ok_or_else(|| usage::<()>("--through is required for single-table mode").unwrap_err())?;
    let dates = dates(from, through)?;
    let tuning = Tuning::resolve(args)?;
    let survey = matches!(args.mode, crate::cli::Mode::Survey) && !args.verify;
    if !(survey
        || common.dry_run
        || args.verify
        || args.shape_review_signoff && args.rotation_signoff)
    {
        return usage(
            "Parquet enforce publication requires --shape-review-signoff and --rotation-signoff",
        );
    }
    let table = table_ref.qualified();
    let (overrides, native_policy, prod) = policy::load_table(args, &table)?;
    let ddl = String::new();
    let contract_sha256 = contract_hash(&native_policy, &overrides, prod.as_ref())?;
    let identity = Identity {
        format: FORMAT.into(),
        table: table.clone(),
        batch: args.batch.batch.as_str().into(),
        source: args.source.trim_end_matches('/').into(),
        source_layout: args.source_layout,
        preserve_paths: false,
        skip_published: false,
        destination: destination_uri(args).trim_end_matches('/').into(),
        from: from.into(),
        through: through.into(),
        contract_sha256,
        survey,
        dry_run: common.dry_run || args.verify,
        retain_days: common.retain_days,
        batch_rows: tuning.batch_rows,
        row_group_bytes: tuning.row_group_bytes,
        chunk_bytes: tuning.chunk_bytes,
    };
    let work = common
        .work
        .join("parquet")
        .join(&table)
        .join(&identity.batch);
    std::fs::create_dir_all(&work).map_err(infrastructure)?;
    if work.join("STOP.json").exists() {
        return abort(
            "run was stopped; inspect STOP.json and use a new batch after resolving the cause",
        );
    }
    let run_lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(work.join("run.lock"))
        .map_err(infrastructure)?;
    run_lock
        .try_lock()
        .map_err(|_| usage::<()>("another process owns this Parquet run").unwrap_err())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(infrastructure)?;
    eprintln!(
        "Parquet pipeline: {} days, {} downloads, {} checks, {} uploads; {} bytes memory, {} bytes scratch",
        tuning.days,
        tuning.downloads,
        tuning.checks,
        tuning.uploads,
        tuning.memory_bytes,
        tuning.scratch_bytes
    );
    runtime.block_on(async {
        let raw: Arc<dyn Store> = Arc::new(
            store::S3Store::new(
                source.bucket.clone(),
                args.source_profile.as_deref(),
                overrides.limits.wall_clock_secs,
                0,
                tuning.downloads,
            )
            .await?,
        );
        let clean: Arc<dyn Store> = if common.dry_run || args.verify || survey {
            Arc::new(store::NoUploadStore)
        } else {
            Arc::new(
                store::S3Store::new(
                    destination.bucket.clone(),
                    args.destination_profile.as_deref(),
                    overrides.limits.wall_clock_secs,
                    common.retain_days,
                    tuning.uploads,
                )
                .await?,
            )
        };
        let inventory_path = work.join("INVENTORY.json");
        let inventory = if inventory_path.exists() {
            if !args.resume {
                return usage("Parquet run already exists; use --resume or a new batch id");
            }
            let inventory: Inventory = read_json(&inventory_path)?;
            if inventory.identity != identity {
                return abort("resume configuration/contract differs from pinned inventory");
            }
            inventory
        } else {
            if args.resume {
                return usage("no Parquet inventory exists to resume");
            }
            let mut days = Vec::new();
            let mut inventory_bytes = 0usize;
            for date in dates {
                let prefix = format!(
                    "{:04}/{:02}/{:02}/{}",
                    date.year(),
                    u8::from(date.month()),
                    date.day(),
                    table_ref.table()
                );
                let input_prefix = source_day_prefix(args.source_layout, date, table_ref.table());
                let sources = raw.list(&source.key(&input_prefix)).await?;
                inventory_bytes = inventory_bytes
                    .checked_add(serde_json::to_vec(&sources).map_err(infrastructure)?.len())
                    .ok_or_else(|| usage::<()>("inventory size overflow").unwrap_err())?;
                if inventory_bytes > 16 * MIB as usize {
                    return usage(
                        "source inventory exceeds controller reservation; use a shorter date range",
                    );
                }
                days.push(Day {
                    date: date.to_string(),
                    prefix,
                    sources,
                });
            }
            let inventory = Inventory {
                identity: identity.clone(),
                imported_at: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(infrastructure)?,
                days,
            };
            atomic_json(&inventory_path, &inventory)?;
            inventory
        };
        // Resolved before any partition starts: the target decides the published shape, so
        // deriving it later would make the output depend on which day happened to run first.
        let target_schema = match &prod {
            Some(prod) => {
                // The pinned copy is authoritative on resume; see `database::pin_target`.
                let path = work.join("TARGET-SCHEMA.json");
                if path.exists() {
                    Some(read_json::<arrow_schema::Schema>(&path)?)
                } else {
                    let missing = || {
                        abort::<()>("table has no source objects to read a schema from")
                            .unwrap_err()
                    };
                    let newest = inventory
                        .days
                        .iter()
                        .rev()
                        .find_map(|day| day.sources.first())
                        .ok_or_else(missing)?;
                    let oldest = inventory
                        .days
                        .iter()
                        .find_map(|day| day.sources.first())
                        .ok_or_else(missing)?;
                    let newest_schema =
                        target::reference_schema(raw.as_ref(), newest, &work).await?;
                    let oldest_schema =
                        target::reference_schema(raw.as_ref(), oldest, &work).await?;
                    let built = target::build(
                        prod,
                        target::References {
                            newest: &newest_schema,
                            oldest: &oldest_schema,
                        },
                        &overrides,
                    )?;
                    atomic_json(&path, &built)?;
                    Some(built)
                }
            }
            None => None,
        };
        let mut pipeline = Pipeline::new(
            identity,
            work.clone(),
            destination,
            ddl,
            overrides,
            tuning,
            inventory.imported_at,
            args.resume,
            raw,
            clean,
            Arc::new(ProcessWorker),
        );
        pipeline.native_policy = Some(native_policy);
        pipeline.target_schema = target_schema;
        pipeline.run(&inventory.days).await
    })
}

fn cleanup_data(work: &Path, files: usize) -> Result<()> {
    for index in 0..files {
        let dir = work.join(format!("file-{index:06}"));
        if !dir.exists() {
            continue;
        }
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join("worker.lock"))
            .map_err(infrastructure)?;
        lock.try_lock().map_err(|_| infra::<()>("an orphaned validation worker is still using this day; wait for it to exit before resuming").unwrap_err())?;
        for entry in std::fs::read_dir(dir).map_err(infrastructure)? {
            let entry = entry.map_err(infrastructure)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "checked.json"
                || name == "raw.parquet"
                || name == "raw.partial"
                || name.ends_with(".parquet")
                || name.ends_with(".parquet.partial")
            {
                std::fs::remove_file(entry.path()).map_err(infrastructure)?;
            }
        }
    }
    Ok(())
}

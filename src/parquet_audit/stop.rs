//! Shared, durable fail-fast latch for the entire native Parquet invocation.
use super::*;
use futures::{
    FutureExt,
    future::{Either, select},
};
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) struct Stop {
    pub enabled: AtomicBool,
    flag: AtomicBool,
    pub path: PathBuf,
}
impl Stop {
    pub fn new(work: &Path) -> Self {
        Self {
            enabled: AtomicBool::new(false),
            flag: AtomicBool::new(false),
            path: work.join("STOP.json"),
        }
    }
    pub fn stopped(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
            && (self.flag.load(Ordering::SeqCst) || self.path.exists())
    }
    pub fn enable(&self) -> Result<()> {
        self.enabled.store(true, Ordering::SeqCst);
        if self.path.exists() {
            self.flag.store(true, Ordering::SeqCst);
            return abort(
                "run was stopped; inspect STOP.json and use a new batch after resolving the cause",
            );
        }
        Ok(())
    }
    pub fn trip(&self, error: &SalvageError) {
        if !self.enabled.load(Ordering::SeqCst) || self.flag.swap(true, Ordering::SeqCst) {
            return;
        }
        // The memory latch is immediate even if the disk has failed. A missing marker on a disk
        // failure is additionally covered by the incomplete day checkpoint on restart.
        let result = persist(&self.path, error.reason());
        if result.is_err() {
            tracing::error!("could not persist STOP.json; run remains stopped");
        }
    }
    async fn wait(&self) {
        while !self.stopped() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    pub(super) async fn transfer<T>(
        &self,
        future: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        if self.stopped() {
            return abort("run stopped; no further transfers allowed");
        }
        let result = match select(
            Box::pin(std::panic::AssertUnwindSafe(future).catch_unwind()),
            Box::pin(self.wait()),
        )
        .await
        {
            Either::Left((result, _)) => {
                result.unwrap_or_else(|_| abort("transfer panicked; entire run stopped"))
            }
            Either::Right(_) => abort("transfer cancelled because the run stopped"),
        };
        if let Err(error) = &result {
            self.trip(error);
        }
        result
    }
}

pub(super) struct StoreWithStop {
    pub inner: Arc<dyn Store>,
    pub stop: Arc<Stop>,
}
impl Store for StoreWithStop {
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<Source>>> {
        Box::pin(self.stop.transfer(self.inner.list(prefix)))
    }
    fn download<'a>(&'a self, source: &'a Source, path: &'a Path) -> BoxFuture<'a, Result<String>> {
        Box::pin(self.stop.transfer(self.inner.download(source, path)))
    }
    fn upload<'a>(
        &'a self,
        key: &'a str,
        path: &'a Path,
        sha: &'a str,
        session: &'a Path,
    ) -> BoxFuture<'a, Result<Receipt>> {
        Box::pin(
            self.stop
                .transfer(self.inner.upload(key, path, sha, session)),
        )
    }
}

/// The marker's existence is the latch, including a partial write after a disk failure.
pub(super) fn persist(path: &Path, reason: &str) -> Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(path.parent().unwrap()).map_err(infrastructure)?;
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(infrastructure(e)),
    };
    let data = serde_json::to_vec(&Status {
        state: "stopped".into(),
        reason: reason.into(),
    })
    .map_err(infrastructure)?;
    file.write_all(&data).map_err(infrastructure)?;
    file.sync_all().map_err(infrastructure)
}

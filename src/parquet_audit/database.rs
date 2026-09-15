//! Database discovery and one globally bounded scheduler across all tables.
use super::*;
use crate::cli::{ParquetSourceLayout, TableRef};

#[derive(Serialize, Deserialize)]
struct DatabaseInventory {
    database: String,
    imported_at: String,
    tables: Vec<Inventory>,
    #[serde(default)]
    excluded_partitions: Vec<String>,
}

/// Match exclusions exactly against discovery so typos cannot silently omit data.
pub(super) fn exclude_partitions(
    tables: &mut BTreeMap<String, Vec<Day>>,
    excluded: &[String],
) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for partition in excluded {
        if !seen.insert(partition) {
            return usage("duplicate excluded partition");
        }
        let Some((table, day)) = partition.split_once('/') else {
            return usage("excluded partition must be database.table/YYYY-MM-DD");
        };
        if !tables
            .get(table)
            .is_some_and(|days| days.iter().any(|d| d.date == day))
        {
            return usage("excluded partition was not found in the selected source/date range");
        }
    }
    for partition in excluded {
        let (table, day) = partition.split_once('/').unwrap();
        tables.get_mut(table).unwrap().retain(|d| d.date != day);
    }
    tables.retain(|_, days| !days.is_empty());
    if tables.is_empty() {
        return usage("exclusions removed every selected partition");
    }
    Ok(())
}

/// A database prefix contains table/YYYY/MM/DD/file.parquet, with no guessed layouts.
pub(super) fn discover(
    root: &Location,
    database: &str,
    sources: Vec<Source>,
    from: Option<&str>,
    through: Option<&str>,
) -> Result<BTreeMap<String, Vec<Day>>> {
    let parse_date = |value: &str| -> Result<time::Date> { Ok(dates(value, value)?[0]) };
    let start = from.map(parse_date).transpose()?;
    let end = through.map(parse_date).transpose()?;
    if start.zip(end).is_some_and(|(a, b)| a > b) {
        return usage("--from must not be after --through");
    }
    let prefix = root.key("");
    let mut grouped: BTreeMap<String, BTreeMap<String, Day>> = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    for source in sources {
        if !seen.insert(source.key.clone()) {
            return abort("duplicate source object in database inventory");
        }
        let relative = source
            .key
            .strip_prefix(&prefix)
            .ok_or_else(|| abort::<()>("object outside database prefix").unwrap_err())?;
        let parts: Vec<_> = relative.split('/').collect();
        if parts.len() != 5 || !parts[4].ends_with(".parquet") || parts[4] == ".parquet" {
            return usage("database sources must use table/YYYY/MM/DD/file.parquet");
        }
        let table: TableRef = format!("{database}.{}", parts[0])
            .parse()
            .map_err(|e: String| usage::<()>(e).unwrap_err())?;
        let date_text = format!("{}-{}-{}", parts[1], parts[2], parts[3]);
        let date = parse_date(&date_text)?;
        if source_day_prefix(ParquetSourceLayout::TableDate, date, table.table())
            != format!("{}/{}/{}/{}/", parts[0], parts[1], parts[2], parts[3])
        {
            return usage("database date directories must be zero-padded YYYY/MM/DD");
        }
        if start.is_some_and(|s| date < s) || end.is_some_and(|e| date > e) {
            continue;
        }
        let days = grouped.entry(table.qualified()).or_default();
        days.entry(date_text.clone())
            .or_insert_with(|| Day {
                date: date_text,
                prefix: format!(
                    "{database}/{}/{}/{}/{}",
                    parts[0], parts[1], parts[2], parts[3]
                ),
                sources: Vec::new(),
            })
            .sources
            .push(source);
        if grouped.len() > 256 {
            return usage("database exceeds 256 tables; select a single table instead");
        }
    }
    if grouped.is_empty() {
        return usage("no Parquet objects found in the selected database/date range");
    }
    Ok(grouped
        .into_iter()
        .map(|(table, days)| {
            let days = days
                .into_values()
                .map(|mut day| {
                    day.sources.sort_by(|a, b| a.key.cmp(&b.key));
                    day
                })
                .collect();
            (table, days)
        })
        .collect())
}

fn identity(
    common: &Common,
    args: &ParquetArgs,
    tuning: &Tuning,
    table: &str,
    native: &policy::TablePolicy,
    overrides: &Overrides,
    prod: Option<&target::ProdSchema>,
) -> Result<Identity> {
    let contract_sha256 = contract_hash(native, overrides, prod)?;
    Ok(Identity {
        format: FORMAT.into(),
        table: table.into(),
        batch: args.batch.batch.as_str().into(),
        source: args.source.trim_end_matches('/').into(),
        source_layout: ParquetSourceLayout::TableDate,
        preserve_paths: true,
        skip_published: args.skip_published,
        destination: destination_uri(args).trim_end_matches('/').into(),
        from: args.from.clone().unwrap_or_default(),
        through: args.through.clone().unwrap_or_default(),
        contract_sha256,
        survey: matches!(args.mode, crate::cli::Mode::Survey) && !args.verify,
        dry_run: common.dry_run || args.verify,
        retain_days: common.retain_days,
        batch_rows: tuning.batch_rows,
        row_group_bytes: tuning.row_group_bytes,
        chunk_bytes: tuning.chunk_bytes,
    })
}

/// Resolve and pin this table's target schema, reusing the pinned one on resume.
///
/// The reference object is the newest selected day's first file: the shape the table has now is
/// the shape the whole table is published as. On resume the pinned copy is authoritative and is
/// re-derived only to check it has not moved, so a second run cannot quietly republish a
/// different shape into the same destination.
async fn pin_target(
    prod: &target::ProdSchema,
    table: &Inventory,
    work: &Path,
    raw: &dyn Store,
    overrides: &Overrides,
) -> Result<arrow_schema::Schema> {
    let path = work.join("TARGET-SCHEMA.json");
    // The pinned copy is authoritative on resume. Re-deriving it would re-download a reference
    // object per table to reach the same answer: the SQL is already in `contract_sha256`, which a
    // resume checks, and the reference object is pinned by INVENTORY.json's key and ETag.
    if path.exists() {
        return read_json(&path);
    }
    let newest = table
        .days
        .iter()
        .max_by(|a, b| a.date.cmp(&b.date))
        .and_then(|day| day.sources.first())
        .ok_or_else(|| {
            abort::<()>("table has no source objects to read a schema from").unwrap_err()
        })?;
    let oldest = table
        .days
        .iter()
        .min_by(|a, b| a.date.cmp(&b.date))
        .and_then(|day| day.sources.first())
        .ok_or_else(|| {
            abort::<()>("table has no source objects to read a schema from").unwrap_err()
        })?;
    let newest_schema = target::reference_schema(raw, newest, work).await?;
    let oldest_schema = target::reference_schema(raw, oldest, work).await?;
    let built = target::build(
        prod,
        target::References {
            newest: &newest_schema,
            oldest: &oldest_schema,
        },
        overrides,
    )?;
    atomic_json(&path, &built)?;
    Ok(built)
}

/// Share transfer/check permits; the one outer scheduler admits only `days` total days.
pub(super) async fn run(
    pipelines: &mut [Pipeline],
    inventories: &[Inventory],
    work: &Path,
    tuning: &Tuning,
) -> Result<()> {
    let downloads = Arc::new(Semaphore::new(tuning.downloads));
    let checks = Arc::new(Semaphore::new(tuning.checks));
    let uploads = Arc::new(Semaphore::new(tuning.uploads));
    let stop = Arc::new(stop::Stop::new(work));
    if pipelines.iter().any(|p| p.native_policy.is_some()) {
        stop.enable()?;
    }
    for pipeline in pipelines.iter_mut() {
        pipeline.raw = Arc::new(stop::StoreWithStop {
            inner: pipeline.raw.clone(),
            stop: stop.clone(),
        });
        pipeline.clean = Arc::new(stop::StoreWithStop {
            inner: pipeline.clean.clone(),
            stop: stop.clone(),
        });
        pipeline.stop = stop.clone();
        pipeline.downloads = downloads.clone();
        pipeline.checks = checks.clone();
        pipeline.uploads = uploads.clone();
    }
    let jobs = pipelines
        .iter()
        .zip(inventories)
        .flat_map(|(pipeline, inventory)| inventory.days.iter().map(move |day| (pipeline, day)))
        .take_while(|(pipeline, _)| !pipeline.stop.stopped());
    let mut pending = futures::stream::iter(jobs)
        .map(|(pipeline, day)| async move {
            let result = pipeline.run_day(day).await;
            (format!("{}/{}", pipeline.identity.table, day.date), result)
        })
        .buffer_unordered(tuning.days);
    let mut reports = BTreeMap::new();
    let mut failed = false;
    let mut interrupted = false;
    let mut report_error = None;
    let started = Instant::now();
    let selected: usize = inventories.iter().map(|i| i.days.len()).sum();
    let mut completed = 0usize;
    let mut total_rows = 0u64;
    let mut reused = 0usize;
    while let Some((key, result)) = pending.next().await {
        let status = match result {
            Ok(rows) => {
                completed += 1;
                total_rows = total_rows.saturating_add(rows);
                let reused_partition = work.join(&key).join("REUSED.json").exists();
                if reused_partition {
                    reused += 1;
                }
                Status {
                    state: if reused_partition {
                        "reused"
                    } else {
                        "complete"
                    }
                    .into(),
                    reason: format!("{rows} rows"),
                }
            }
            Err(e) => {
                let rejected = e.exit_code() == ExitCode::Abort;
                failed |= rejected;
                interrupted |= !rejected;
                Status {
                    state: if rejected { "failed" } else { "interrupted" }.into(),
                    reason: e.reason().into(),
                }
            }
        };
        tracing::info!(
            partition = key,
            completed_partitions = completed,
            reused_partitions = reused,
            selected_partitions = selected,
            rows_in_completed_partitions = total_rows,
            elapsed_secs = started.elapsed().as_secs_f64(),
            state = status.state,
            reason = status.reason,
            "database partition finished"
        );
        reports.insert(key, status);
        // Drain workers even if report storage fails; do not abandon live subprocesses.
        if let Err(e) = atomic_json(&work.join("report.json"), &reports) {
            stop.trip(&e);
            report_error = Some(e);
        }
    }
    if let Some(e) = report_error {
        return Err(e);
    }
    if let Some(p) = pipelines.first() {
        finish_report(
            work,
            p.identity.dry_run,
            p.identity.survey,
            failed || interrupted,
            completed,
            inventories.iter().map(|i| i.days.len()).sum(),
            total_rows,
        )?;
    }
    let result_path = work.join("RESULT.json");
    if result_path.exists() {
        let mut result: serde_json::Value = read_json(&result_path)?;
        let exclusions_path = work.join("EXCLUDED-PARTITIONS.json");
        let excluded: Vec<String> = if exclusions_path.exists() {
            read_json(&exclusions_path)?
        } else {
            Vec::new()
        };
        result["excluded_partition_count"] = excluded.len().into();
        result["excluded_partitions"] = serde_json::to_value(excluded).map_err(infrastructure)?;
        result["reused_partitions"] = reused.into();
        result["newly_completed_partitions"] = (completed - reused).into();
        atomic_json(&result_path, &result)?;
    }
    if failed {
        abort("one or more database partitions failed audit; those partitions were not published")
    } else if interrupted {
        infra("one or more database partitions were interrupted; resume the same batch")
    } else {
        Ok(())
    }
}

pub(super) fn command(common: &Common, args: &ParquetArgs) -> Result<()> {
    let database = args.database.as_deref().expect("database dispatch");
    if args.skip_published && matches!(args.mode, crate::cli::Mode::Survey) {
        return usage("--skip-published requires an upload run in enforce mode");
    }
    let _: TableRef = format!("{database}.placeholder")
        .parse()
        .map_err(|e: String| usage::<()>(e).unwrap_err())?;
    let source = Location::parse(&args.source)?;
    let destination = Location::parse(destination_uri(args))?;
    if source.bucket == destination.bucket {
        return usage("raw and clean Parquet data require separate S3 buckets");
    }
    let tuning = Tuning::resolve(args)?;
    if !(matches!(args.mode, crate::cli::Mode::Survey)
        || common.dry_run
        || args.verify
        || args.shape_review_signoff && args.rotation_signoff)
    {
        return usage(
            "Parquet enforce publication requires --shape-review-signoff and --rotation-signoff",
        );
    }
    // Validate date filters before listing anything.
    if let Some(from) = &args.from {
        dates(from, from)?;
    }
    if let Some(through) = &args.through {
        dates(through, through)?;
    }
    if args
        .from
        .as_ref()
        .zip(args.through.as_ref())
        .is_some_and(|(a, b)| a > b)
    {
        return usage("--from must not be after --through");
    }
    let work = common
        .work
        .join("parquet-database")
        .join(database)
        .join(args.batch.batch.as_str());
    std::fs::create_dir_all(&work).map_err(infrastructure)?;
    if work.join("STOP.json").exists() {
        return abort(
            "run was stopped; inspect STOP.json and use a new batch after resolving the cause",
        );
    }
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(work.join("run.lock"))
        .map_err(infrastructure)?;
    lock.try_lock()
        .map_err(|_| usage::<()>("another process owns this database run").unwrap_err())?;
    let inventory_path = work.join("INVENTORY.json");
    if inventory_path.exists() != args.resume {
        return usage(if args.resume {
            "no database inventory exists to resume"
        } else {
            "database run exists; use --resume or a new batch id"
        });
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(infrastructure)?;
    runtime.block_on(async {
        // Listing has its own finite deadline; per-table transfers use pinned table deadlines below.
        let listing = store::S3Store::new(source.bucket.clone(), args.source_profile.as_deref(), 3600, 0, tuning.downloads).await?;
        let inventory = if args.resume { read_json::<DatabaseInventory>(&inventory_path)? } else {
            let sources = listing.list(&source.key("")).await?;
            if serde_json::to_vec(&sources).map_err(infrastructure)?.len() > 16 * MIB as usize {
                return usage("database inventory exceeds 16 MiB; narrow the source/date scope");
            }
            let mut discovered = discover(&source, database, sources, args.from.as_deref(), args.through.as_deref())?;
            exclude_partitions(&mut discovered, &args.exclude_partition)?;
            let imported_at = time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).map_err(infrastructure)?;
            let mut tables = Vec::new();
            for (table, days) in discovered {
                let (overrides, native, prod) = policy::load_table(args, &table)?;
                tables.push(Inventory { identity: identity(common, args, &tuning, &table, &native, &overrides, prod.as_ref())?, imported_at: imported_at.clone(), days });
            }
            DatabaseInventory { database: database.into(), imported_at, tables, excluded_partitions: args.exclude_partition.clone() }
        };
        if inventory.database != database || inventory.tables.is_empty() || inventory.tables.len() > 256 { return abort("invalid database inventory"); }
        atomic_json(&work.join("EXCLUDED-PARTITIONS.json"), &inventory.excluded_partitions)?;
        for partition in &inventory.excluded_partitions {
            eprintln!("Excluded by operator: {partition} (not counted as published)");
        }
        let mut pipelines = Vec::new();
        let clean_store = if common.dry_run || args.verify || matches!(args.mode, crate::cli::Mode::Survey) { None } else {
            Some(store::S3Store::new(destination.bucket.clone(), args.destination_profile.as_deref(), 3600, common.retain_days, tuning.uploads).await?)
        };
        // Load and verify every pinned contract before admitting any download/check/upload work.
        for table in &inventory.tables {
            let table_ref: TableRef = table.identity.table.parse().map_err(|e: String| usage::<()>(e).unwrap_err())?;
            if table_ref.database() != database { return abort("inventory table belongs to another database"); }
            let (overrides, native, prod) = policy::load_table(args, &table.identity.table)?;
            if table.identity != identity(common, args, &tuning, &table.identity.table, &native, &overrides, prod.as_ref())? { return abort("resume configuration/contract differs from pinned database inventory"); }
            let raw = Arc::new(listing.with_timeout(overrides.limits.wall_clock_secs));
            let clean: Arc<dyn Store> = match &clean_store { Some(s) => Arc::new(s.with_timeout(overrides.limits.wall_clock_secs)), None => Arc::new(store::NoUploadStore) };
            let table_work = work.join(&table.identity.table);
            // Resolve the target before any partition starts: it decides the published shape, so
            // deriving it later would make the output depend on which day happened to run first.
            let target_schema = match &prod {
                Some(prod) => Some(pin_target(prod, table, &table_work, raw.as_ref(), &overrides).await?),
                None => None,
            };
            let mut pipeline = Pipeline::new(table.identity.clone(), table_work, destination.clone(), String::new(), overrides, tuning.clone(), inventory.imported_at.clone(), args.resume, raw, clean, Arc::new(ProcessWorker));
            pipeline.native_policy = Some(native);
            pipeline.target_schema = target_schema;
            if args.skip_published {
                pipeline.published_store = clean_store.as_ref().map(|s| Arc::new(s.with_timeout(pipeline.overrides.limits.wall_clock_secs)) as Arc<dyn published::PublishedStore>);
            }
            pipelines.push(pipeline);
        }
        if !args.resume {
            if serde_json::to_vec(&inventory).map_err(infrastructure)?.len() > 16 * MIB as usize { return usage("database inventory exceeds 16 MiB"); }
            atomic_json(&inventory_path, &inventory)?;
        }
        eprintln!("Database {database}: {} tables, {} partitions; {} active days, {} downloads, {} checks, {} uploads", inventory.tables.len(), inventory.tables.iter().map(|t| t.days.len()).sum::<usize>(), tuning.days, tuning.downloads, tuning.checks, tuning.uploads);
        run(&mut pipelines, &inventory.tables, &work, &tuning).await
    })
}

//! `salvage` -- fail-closed ClickHouse salvage from a compromised cluster.
//!
//! This file does four things and nothing else: install the panic hook, parse, dispatch, and map
//! the outcome to an exit code. All the judgement lives in the library.
//!
//! # Exit codes
//!
//! ```text
//! 0  clean
//! 1  ABORT -- a finding. The batch is dead. Never "partially succeeded"
//! 2  usage error
//! 3  infrastructure error (no cluster, no bucket, no runtime) -- distinct from a finding
//! ```
//!
//! The 1/3 split is load-bearing rather than cosmetic: a finding means the data is suspect and the
//! table's batch dies, while an infrastructure error means we never got to look and a single page
//! may be retried. `--resume` is allowed to act on the second and never on the first.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode as ProcessExitCode;

use clap::Parser;

use salvage::abort::{ExitCode, Result, SalvageError};
use salvage::audit::secrets;
use salvage::cli::{Cli, Command};
use salvage::clickhouse::client::{Endpoint, HttpRunner};
use salvage::clickhouse::ddl;
use salvage::export::plan;
use salvage::gcs::{self, HttpStore, ObjectStore as _, TokenSource};
use salvage::limits::TransferBudget;
use salvage::{audit, export};

fn main() -> ProcessExitCode {
    install_panic_hook();

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // `--help` and `--version` are successful outcomes that clap reports as errors.
            // Route the mapping explicitly so it has a test rather than an accident.
            let _ = e.print();
            return match e.kind() {
                clap::error::ErrorKind::DisplayHelp
                | clap::error::ErrorKind::DisplayVersion
                | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                    to_process_exit(ExitCode::Ok)
                }
                _ => to_process_exit(ExitCode::Usage),
            };
        }
    };

    init_logging(&cli);

    // A panic anywhere below is a bug -- an input we failed to classify -- not a finding. It is
    // caught here rather than aborting the process so that unwinding runs the Drop impls that
    // guarantee no partial output survives. This is why the release profile pins panic = "unwind".
    let outcome = catch_unwind(AssertUnwindSafe(|| dispatch(&cli)));

    let code = match outcome {
        Ok(Ok(())) => ExitCode::Ok,
        Ok(Err(e)) => {
            eprintln!("{e}");
            e.exit_code()
        }
        Err(_) => {
            eprintln!("ABORT: panicked while processing input; treating as a finding");
            ExitCode::Abort
        }
    };

    to_process_exit(code)
}

fn dispatch(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Plan(args) => cmd_plan(cli, args),
        Command::Export(args) => cmd_export(cli, args),
        Command::Audit(args) => cmd_audit(cli, args),
        Command::Secrets => cmd_secrets(cli),
        Command::Teardown(args) => cmd_teardown(cli, args),
    }
}

/// `salvage teardown` -- release holds, and force the source disposition to be recorded.
fn cmd_teardown(cli: &Cli, args: &salvage::cli::TeardownArgs) -> Result<()> {
    use salvage::teardown::{Disposition, TeardownPlan, run_teardown, write_report};

    let table = args.table.table.qualified();
    let batch = args.batch.batch.as_str().to_owned();
    // Teardown touches no table data, so it has no per-table limits to derive a budget from.
    let store = object_store(cli, None)?;

    std::fs::create_dir_all(&cli.common.work).map_err(|e| SalvageError::Infra {
        reason: format!("could not create the work dir: {e}"),
        context: Vec::new(),
    })?;

    let plan = TeardownPlan {
        raw_prefix: format!("{table}/{batch}"),
        table,
        batch,
        disposition: match args.disposition {
            salvage::cli::Disposition::Wipe => Disposition::Wipe,
            salvage::cli::Disposition::SnapshotThenWipe => Disposition::SnapshotThenWipe,
            salvage::cli::Disposition::Retain => Disposition::Retain,
        },
        owner: args.owner.clone(),
        accepted: args.accepted,
        rotation_complete: args.rotation_complete,
        dry_run: cli.common.dry_run,
        recorded_at: {
            let now = time::OffsetDateTime::now_utc();
            format!(
                "{:04}-{:02}-{:02}",
                now.year(),
                u8::from(now.month()),
                now.day()
            )
        },
    };

    let body = run_teardown(&plan, &store)?;
    let path = write_report(&body, &cli.common.work)?;
    println!("{}", path.display());
    Ok(())
}

/// `salvage audit` -- pull, frame, bound, profile, regenerate, promote.
fn cmd_audit(cli: &Cli, args: &salvage::cli::AuditArgs) -> Result<()> {
    let table = args.table.table.qualified();
    let batch = args.batch.batch.as_str().to_owned();
    let (ddl, overrides) = ddl::load_one(&cli.common.ddl_dir, &cli.common.overrides_dir, &table)?;
    let store = object_store(cli, Some(&overrides.limits))?;
    let clean_store = clean_object_store(cli, Some(&overrides.limits))?;

    // `PAGES.json` is the completion sentinel. Its absence means the export never finished, and a
    // prefix without it is an incomplete run a consumer must treat as absent.
    let raw_prefix = format!("{table}/{batch}");
    let local_ledger = cli.common.work.join(&batch).join("PAGES.json");
    let ledger_text = if local_ledger.exists() {
        std::fs::read_to_string(&local_ledger).map_err(|e| SalvageError::Infra {
            reason: format!("could not read the local ledger: {e}"),
            context: vec![("path", local_ledger.display().to_string())],
        })?
    } else {
        let name = salvage::gcs::ObjectName::new(format!("{raw_prefix}/PAGES.json"))?;
        // Section 5: the Controller pins and approves version ids, and a reader never resolves
        // "latest under prefix". `PAGES.json` is the root of trust for every page generation and
        // hash in the run, so resolving it live makes the producer the authority over its own
        // output -- exactly what section 1 forbids. Require the pinned value, or an explicit
        // acknowledgement that this run is doing without one.
        let generation = match cli.common.pages_generation {
            Some(g) => salvage::gcs::Generation(g),
            None if cli.common.unpinned_ledger => {
                let stat = store.stat(&name)?.ok_or_else(|| SalvageError::Abort {
                    reason: "no PAGES.json: the export never finished".to_owned(),
                    context: vec![("prefix", raw_prefix.clone())],
                })?;
                tracing::warn!(
                    generation = %stat.generation,
                    "--unpinned-ledger: reading the live PAGES.json generation. The Controller's \
                     pinned value is the control this replaces."
                );
                stat.generation
            }
            None => {
                return Err(SalvageError::Usage {
                    reason: "--pages-generation is required: the Controller pins it out of band"
                        .to_owned(),
                    context: vec![
                        ("prefix", raw_prefix.clone()),
                        (
                            "alternative",
                            "pass --unpinned-ledger to read the live generation and record that                              this run had no Controller pin"
                                .to_owned(),
                        ),
                    ],
                });
            }
        };
        let dest = cli.common.work.join("PAGES.json");
        std::fs::create_dir_all(&cli.common.work).ok();
        store.get_pinned(&name, generation, &dest)?;
        std::fs::read_to_string(&dest).map_err(|e| SalvageError::Infra {
            reason: format!("could not read the pulled ledger: {e}"),
            context: Vec::new(),
        })?
    };

    let ledger: salvage::models::PagesJson =
        serde_json::from_str(&ledger_text).map_err(|e| SalvageError::Abort {
            reason: format!("the ledger does not parse: {e}"),
            context: Vec::new(),
        })?;

    let opts = audit::AuditOptions {
        retain_days: cli.common.retain_days,
        batch: batch.clone(),
        work: cli.common.work.clone(),
        raw_prefix,
        clean_prefix: format!("{table}/{batch}"),
        mode: match args.mode {
            salvage::cli::Mode::Survey => audit::Mode::Survey,
            salvage::cli::Mode::Enforce => audit::Mode::Enforce,
        },
        dry_run: cli.common.dry_run,
        contract_version: plan::CONTRACT_VERSION.to_owned(),
        git_commit: plan::GIT_COMMIT.to_owned(),
        shape_review_signoff: args.shape_review_signoff,
        rotation_signoff: args.rotation_signoff,
    };

    // Section 7's pre-flight. The image is pinned by digest, never by tag: section 3 wants
    // independently verified images, and a tag is mutable so a tag is not a pin.
    let inserter = salvage::audit::insert::SubprocessTester {
        target: salvage::audit::insert::InsertTarget {
            runner: match args.runner {
                salvage::cli::Runner::Docker => "docker".to_owned(),
                salvage::cli::Runner::Podman => "podman".to_owned(),
                salvage::cli::Runner::Local => "clickhouse-client".to_owned(),
            },
            image: cli.common.clickhouse_image.clone().unwrap_or_default(),
            host: cli.common.insert_host.clone(),
            max_memory_usage: overrides.limits.max_uncompressed_bytes,
            max_insert_block_size: overrides.limits.max_rows_per_page.min(65_536),
        },
        dry_run: cli.common.dry_run,
    };

    let report = audit::run_audit(
        &ddl,
        &overrides,
        &store,
        &clean_store,
        &inserter,
        &ledger,
        &opts,
    )?;
    if cli.common.json {
        let rendered = serde_json::to_string_pretty(&report).map_err(|e| SalvageError::Infra {
            reason: format!("could not render the report: {e}"),
            context: Vec::new(),
        })?;
        println!("{rendered}");
    } else {
        println!("{}", cli.common.work.join("report.json").display());
    }
    Ok(())
}

/// `salvage export` -- page, diff, pack, push.
///
/// Needs both a cluster and a bucket, and says which is missing rather than defaulting either.
fn cmd_export(cli: &Cli, args: &salvage::cli::ExportArgs) -> Result<()> {
    let table = args.table.table.qualified();
    let batch = args.batch.batch.as_str().to_owned();
    let (ddl, overrides) = ddl::load_one(&cli.common.ddl_dir, &cli.common.overrides_dir, &table)?;

    let url = cli
        .common
        .clickhouse_url
        .as_ref()
        .ok_or_else(|| SalvageError::Usage {
            reason: "--clickhouse-url is required to export".to_owned(),
            context: Vec::new(),
        })?;
    let store = object_store(cli, Some(&overrides.limits))?;
    let runner = query_runner(cli, url, ddl.database.as_str(), &overrides.limits)?;

    std::fs::create_dir_all(&cli.common.work).map_err(|e| SalvageError::Infra {
        reason: format!("could not create the work dir: {e}"),
        context: vec![("path", cli.common.work.display().to_string())],
    })?;

    // The cross-check runs before a single row is read. Section 4: the server's answer is a
    // cross-check, never the authority -- and a table that is not what source control says it is
    // must not be exported at all.
    plan::assert_settings_known(&runner)?;
    let cutoff = salvage::pages::cutoff_predicate(&ddl, &overrides)?;
    let facts = plan::introspect(&runner, &ddl, &cutoff)?;
    plan::cross_check(&ddl, &facts)?;
    let doc = plan::build(&ddl, &overrides, Some(&facts))?;

    let opts = export::ExportOptions {
        retain_days: cli.common.retain_days,
        batch: batch.clone(),
        work: cli.common.work.clone(),
        bucket_prefix: format!("{table}/{batch}"),
        dry_run: cli.common.dry_run,
        resume: args.resume,
        contract_version: plan::CONTRACT_VERSION.to_owned(),
        git_commit: plan::GIT_COMMIT.to_owned(),
    };

    let pages = export::run_export(
        &ddl,
        &overrides,
        &runner,
        &store,
        &facts,
        doc.rows_per_page,
        &opts,
    )?;

    if cli.common.json {
        let rendered = serde_json::to_string_pretty(&pages).map_err(|e| SalvageError::Infra {
            reason: format!("could not render the ledger: {e}"),
            context: Vec::new(),
        })?;
        println!("{rendered}");
    } else {
        println!("{}", cli.common.work.join(&batch).display());
    }
    tracing::info!(
        table = %pages.table,
        pages = pages.pages.len(),
        rows = pages.total_rows,
        "export complete"
    );
    Ok(())
}

/// `salvage plan` -- derive the contract, then ask the cluster to agree.
///
/// Section 4: the allowlist comes from source control and the server's answer is a cross-check,
/// never the authority. So the plan is built from `ddl/` and `overrides/` first, and the cluster is
/// consulted second -- or not at all, which `plan.json` records rather than hides.
fn cmd_plan(cli: &Cli, args: &salvage::cli::PlanArgs) -> Result<()> {
    let table = args.table.table.qualified();
    let (ddl, overrides) = ddl::load_one(&cli.common.ddl_dir, &cli.common.overrides_dir, &table)?;

    std::fs::create_dir_all(&cli.common.work).map_err(|e| SalvageError::Infra {
        reason: format!("could not create the work dir: {e}"),
        context: vec![("path", cli.common.work.display().to_string())],
    })?;

    let cutoff = salvage::pages::cutoff_predicate(&ddl, &overrides)?;
    let facts = match &cli.common.clickhouse_url {
        Some(url) => {
            let runner = query_runner(cli, url, ddl.database.as_str(), &overrides.limits)?;
            // Addition A1's first caller: a pinned setting the server does not recognise is a
            // setting we silently failed to pin, so it is checked before anything else is asked.
            plan::assert_settings_known(&runner)?;
            let facts = plan::introspect(&runner, &ddl, &cutoff)?;
            plan::cross_check(&ddl, &facts)?;
            Some(facts)
        }
        None => {
            tracing::warn!(
                "no --clickhouse-url: deriving the contract from pinned source control only. \
                 plan.json will record that the cluster was not cross-checked."
            );
            None
        }
    };

    let doc = plan::build(&ddl, &overrides, facts.as_ref())?;
    let path = cli.common.work.join("plan.json");
    let rendered = serde_json::to_string_pretty(&doc).map_err(|e| SalvageError::Infra {
        reason: format!("could not render plan.json: {e}"),
        context: Vec::new(),
    })?;
    let mut guard = salvage::abort::PartialOutput::new(path.with_extension("json.partial"));
    std::fs::write(guard.path(), &rendered).map_err(|e| SalvageError::Infra {
        reason: format!("could not write plan.json: {e}"),
        context: vec![("path", path.display().to_string())],
    })?;
    guard.commit_as(&path)?;

    if cli.common.json {
        println!("{rendered}");
    } else {
        println!("{}", path.display());
    }
    tracing::info!(
        table = %doc.table,
        columns = doc.columns.len(),
        output_columns = doc.output_columns.len(),
        dropped = doc.dropped_columns.len(),
        cursor = ?doc.cursor_columns,
        rows_per_page = doc.rows_per_page,
        cross_checked = doc.cluster_cross_checked,
        "plan written"
    );
    Ok(())
}

/// Build the query runner. Constructed once, and only for the subcommands that talk to the source.
fn query_runner(
    cli: &Cli,
    url: &str,
    database: &str,
    limits: &salvage::limits::Limits,
) -> Result<HttpRunner> {
    let budget = TransferBudget::from_limits(limits);
    // Read, never written: `std::env::set_var` is unsafe in edition 2024 and this crate forbids
    // unsafe, so no test can set one either.
    let password = std::env::var("SALVAGE_CH_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty());
    HttpRunner::new(
        Endpoint {
            base_url: url.to_owned(),
            database: database.to_owned(),
            user: cli.common.clickhouse_user.clone(),
            password,
        },
        budget,
        cli.common.work.join("queries.log"),
    )
}

/// `salvage secrets` -- the rotation inventory (addition A3).
///
/// Reads pinned DDL and column names only: no cluster, no bucket, no data. That is what lets it
/// run first, at incident time, before anything moves. Section A3: rotation proceeds regardless of
/// whether the batch ever ships.
fn cmd_secrets(cli: &Cli) -> Result<()> {
    let tables = ddl::load_pinned(&cli.common.ddl_dir, &cli.common.overrides_dir)?;
    let inventory = secrets::inventory(&tables);

    std::fs::create_dir_all(&cli.common.work).map_err(|e| SalvageError::Infra {
        reason: format!("could not create the work dir: {e}"),
        context: vec![("path", cli.common.work.display().to_string())],
    })?;
    let path = secrets::write_report(&inventory, &cli.common.work)?;

    if cli.common.json {
        let doc = serde_json::json!({
            "report": path.display().to_string(),
            "summary": secrets::summary(&inventory),
        });
        println!("{doc}");
    } else {
        println!("{}", path.display());
    }

    let unassigned = inventory.unassigned().len();
    tracing::info!(
        tables = inventory.tables.len(),
        classified = inventory.classified.len(),
        review = inventory.review.len(),
        unassigned,
        "rotation inventory written"
    );
    if unassigned > 0 {
        // Not a failure: the inventory is the deliverable and an unowned row is what it is for.
        // ROTATION_SIGNOFF is the gate, and it is a human one.
        tracing::warn!(
            unassigned,
            "columns have no rotation owner; set `rotation_owner` in the overrides"
        );
    }
    Ok(())
}

/// Build the object store for the subcommands that move bytes.
///
/// Constructed once per invocation and passed down as `&dyn ObjectStore`. `reqwest::blocking`
/// spins its own runtime thread, and building one inside a `Drop` would deadlock -- a live risk
/// given how much of this design lives in destructors.
///
/// `--bucket` is a usage error when missing rather than a default, because there is no safe
/// default destination for data pulled off a compromised cluster.
fn object_store(cli: &Cli, limits: Option<&salvage::limits::Limits>) -> Result<HttpStore> {
    let bucket = cli
        .common
        .bucket
        .as_ref()
        .ok_or_else(|| SalvageError::Usage {
            reason: "--bucket is required for this subcommand".to_owned(),
            context: Vec::new(),
        })?;
    store_for(cli, limits, bucket.as_str())
}

/// The clean-side store. A distinct bucket, not a distinct prefix -- see [`Common::clean_bucket`].
fn clean_object_store(cli: &Cli, limits: Option<&salvage::limits::Limits>) -> Result<HttpStore> {
    let bucket = cli
        .common
        .clean_bucket
        .as_ref()
        .ok_or_else(|| SalvageError::Usage {
            reason: "--clean-bucket is required for this subcommand".to_owned(),
            context: Vec::new(),
        })?;
    store_for(cli, limits, bucket.as_str())
}

fn store_for(
    cli: &Cli,
    limits: Option<&salvage::limits::Limits>,
    bucket: &str,
) -> Result<HttpStore> {
    let session_dir = cli
        .common
        .session_dir
        .clone()
        .unwrap_or_else(|| cli.common.work.join("sessions"));
    std::fs::create_dir_all(&session_dir).map_err(|e| SalvageError::Infra {
        reason: format!("could not create session dir: {e}"),
        context: vec![("path", session_dir.display().to_string())],
    })?;

    // The token is read from the environment here and never written -- `std::env::set_var` is
    // unsafe in edition 2024 and this crate forbids unsafe, so no test can set one either.
    // Without an override the GCE metadata server answers, downscoped: `?scopes=` alone does not
    // downscope a metadata token, `enforce_scopes=true` is also required.
    let tokens = match std::env::var("SALVAGE_GCS_TOKEN") {
        Ok(t) if !t.is_empty() => TokenSource::Static(t),
        _ => TokenSource::Metadata {
            scopes: gcs::SCOPE_READ_WRITE,
        },
    };

    // From the pinned per-table limits when we have them. `teardown` has no table overrides, so it
    // falls back to a conservative default -- but every path that moves data uses the pinned
    // values, or `wall_clock_secs` and `max_compressed_bytes` would be correctly-spelled keys that
    // are silently never read, which is the exact failure `deny_unknown_fields` exists to prevent
    // everywhere else in this crate.
    let budget = limits.map_or(
        TransferBudget {
            wall_clock: std::time::Duration::from_secs(3600),
            max_bytes: 256 * 1024 * 1024,
        },
        TransferBudget::from_limits,
    );

    HttpStore::new(bucket, tokens, budget, session_dir)
}

fn init_logging(cli: &Cli) {
    // The human log always goes to stderr, so `--json` can own stdout.
    //
    // Note the filter is built from the verbosity flag rather than from RUST_LOG: std::env::set_var
    // is unsafe in edition 2024 and this crate forbids unsafe, so no code or test may set an
    // environment variable. Configuration arrives through flags and pinned TOML instead.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(cli.common.verbosity.tracing_level_filter())
        .init();
}

fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Print and return. Deliberately no process::exit here: exiting from the hook would skip
        // the Drop impls, and those unlinking the in-progress files is the whole guarantee.
        eprintln!("ABORT: {info}");
        previous(info);
    }));
}

fn to_process_exit(code: ExitCode) -> ProcessExitCode {
    match code {
        ExitCode::Ok => ProcessExitCode::SUCCESS,
        ExitCode::Abort => ProcessExitCode::from(1),
        ExitCode::Usage => ProcessExitCode::from(2),
        ExitCode::Infra => ProcessExitCode::from(3),
    }
}

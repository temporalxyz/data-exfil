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
use salvage::cli::{Cli, Command};
use salvage::gcs::HttpStore;
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
    // Constructed once. reqwest::blocking spins its own runtime thread, and building one inside a
    // Drop would deadlock -- a live risk given how much of this design lives in destructors.
    let store = HttpStore;

    match &cli.command {
        Command::Plan(_) => Err(not_implemented("plan")),
        Command::Export(args) => {
            let runner = no_runner()?;
            export::run(args, runner.as_ref(), &store)
        }
        Command::Audit(args) => audit::run(args, &store),
        Command::Secrets => Err(not_implemented("secrets")),
        Command::Teardown(_) => Err(not_implemented("teardown")),
    }
}

/// Every unbuilt phase fails closed. A stub that returned `Ok` would report success for work it
/// did not do, which is the one failure mode this tool cannot tolerate.
fn not_implemented(phase: &str) -> SalvageError {
    SalvageError::Infra {
        reason: format!("{phase}: not implemented"),
        context: Vec::new(),
    }
}

/// The ClickHouse client does not exist yet, so there is no runner to hand to `export`.
fn no_runner() -> Result<Box<dyn salvage::clickhouse::QueryRunner>> {
    Err(not_implemented("clickhouse client"))
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

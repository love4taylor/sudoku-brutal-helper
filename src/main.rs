mod command;
mod config;
mod guard;

use crate::command::NativeRunner;
use crate::config::{DEFAULT_CONFIG_PATH, Settings};
use crate::guard::Guard;
use anyhow::{Context, Result};
use clap::Parser;
use log::{Level, error, info, warn};
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
#[command(
    name = "sudoku-brutal-helper",
    about = "Monitor the Sudoku listening port and manage TCP Brutal client rules"
)]
struct Args {
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[arg(
        long,
        help = "Print mutations without applying them; sock_diag scans still run"
    )]
    dry_run: bool,
    #[arg(long, help = "Exit after one connection scan")]
    once: bool,
}

fn main() -> Result<()> {
    init_logger();
    let args = Args::parse();

    let settings = Settings::load(&args.config)?;
    let listen_port = settings.resolve_listen_port()?;
    let runner = NativeRunner::new(&settings, args.dry_run);
    let mut guard = Guard::new(
        runner,
        settings.state_file.clone(),
        settings.max_ips,
        settings.rate_mbps,
        listen_port,
    );
    guard.load_state()?;
    guard.reconcile()?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop);
    ctrlc::set_handler(move || stop_handler.store(true, Ordering::Relaxed))
        .context("failed to register the shutdown signal handler")?;

    info!(
        "monitoring Sudoku TCP port {} with a {} ms scan interval",
        listen_port, settings.poll_interval_ms
    );
    let mut previous_clients = HashSet::new();
    let mut initial_scan = true;
    while !stop.load(Ordering::Relaxed) {
        match guard.scan_clients() {
            Ok(clients) => {
                let current_clients: HashSet<_> = clients.iter().copied().collect();
                for ip in clients {
                    if initial_scan || !previous_clients.contains(&ip) || guard.needs_attention(ip)
                    {
                        if let Err(error) = guard.observe(ip, initial_scan) {
                            error!("failed to process client {ip}: {error:#}");
                        }
                    }
                }
                previous_clients = current_clients;
                initial_scan = false;
                if args.once {
                    break;
                }
            }
            Err(error) => {
                warn!("connection scan failed: {error:#}");
                if args.once {
                    return Err(error);
                }
            }
        }
        sleep_until_next_scan(Duration::from_millis(settings.poll_interval_ms), &stop);
    }
    info!("monitoring stopped");
    Ok(())
}

fn init_logger() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buffer, record| {
            if matches!(record.level(), Level::Warn | Level::Error) {
                writeln!(buffer, "[{}] {}", record.level(), record.args())
            } else {
                writeln!(buffer, "{}", record.args())
            }
        })
        .init();
}

fn sleep_until_next_scan(duration: Duration, stop: &AtomicBool) {
    let deadline = Instant::now() + duration;
    while !stop.load(Ordering::Relaxed) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}

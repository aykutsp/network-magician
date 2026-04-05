pub mod cli;
pub mod model;
pub mod output;
pub mod scanner;
pub mod target;
pub mod util;
pub mod wifi;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, WifiCommands};
use output::{print_diff, print_scan_summary, print_wifi_summary, write_json};
use scanner::scan_targets;
use std::path::Path;
use util::{load_report, parse_scan_ports};
use wifi::scan_wifi_networks;

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            ports,
            udp_ports,
            timeout_ms,
            concurrency,
            no_progress,
            json,
        } => {
            let port_selection = parse_scan_ports(ports.as_deref(), udp_ports.as_deref())?;
            let json_to_stdout = matches!(json.as_deref(), Some(path) if path == Path::new("-"));
            let report = scan_targets(
                &target,
                &port_selection.tcp_ports,
                &port_selection.udp_ports,
                timeout_ms,
                concurrency,
                !no_progress && !json_to_stdout,
            )?;

            if !json_to_stdout {
                print_scan_summary(&report);
            }

            if let Some(path) = json {
                write_json(&path, &report)?;
                if !json_to_stdout {
                    eprintln!("saved report to {}", path.display());
                }
            }
        }
        Commands::Diff { old, new } => {
            let old_report = load_report(&old)?;
            let new_report = load_report(&new)?;
            let diff = old_report.diff(&new_report);
            print_diff(&diff);
        }
        Commands::Wifi { command } => match command {
            WifiCommands::Scan { json } => {
                let json_to_stdout =
                    matches!(json.as_deref(), Some(path) if path == Path::new("-"));
                let report = scan_wifi_networks()?;

                if !json_to_stdout {
                    print_wifi_summary(&report);
                }

                if let Some(path) = json {
                    write_json(&path, &report)?;
                    if !json_to_stdout {
                        eprintln!("saved report to {}", path.display());
                    }
                }
            }
        },
    }

    Ok(())
}

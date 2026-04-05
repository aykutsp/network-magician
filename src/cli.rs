use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "network-magician")]
#[command(version, about = "Scan local hosts and selected ports")]
#[command(arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan a CIDR block, an IPv4 range, or a single IPv4 address
    Scan {
        /// Target to scan, for example 192.168.1.0/24 or 192.168.1.10-192.168.1.50
        target: String,
        /// Comma-separated TCP port list or ranges, for example 22,80,443,8000-8010
        #[arg(long, value_name = "PORTS")]
        ports: Option<String>,
        /// Comma-separated UDP port list or ranges
        #[arg(long, value_name = "PORTS")]
        udp_ports: Option<String>,
        /// Connect timeout per port probe in milliseconds
        #[arg(long, default_value_t = 250)]
        timeout_ms: u64,
        /// Maximum worker count
        #[arg(long, default_value_t = 256)]
        concurrency: usize,
        /// Disable the progress bar
        #[arg(long)]
        no_progress: bool,
        /// Write JSON report to a file. Use '-' to write to stdout.
        #[arg(long, value_name = "PATH")]
        json: Option<PathBuf>,
    },
    /// Compare two JSON scan reports
    Diff { old: PathBuf, new: PathBuf },
    /// Scan nearby Wi-Fi networks and show channel and signal information
    Wifi {
        #[command(subcommand)]
        command: WifiCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum WifiCommands {
    /// List visible Wi-Fi networks
    Scan {
        /// Write JSON report to a file. Use '-' to write to stdout.
        #[arg(long, value_name = "PATH")]
        json: Option<PathBuf>,
    },
}

use crate::model::{DiffReport, HostReport, ScanReport, WifiScanReport};
use anyhow::Result;
use serde::Serialize;
use std::fs;
use std::io;
use std::path::Path;

pub fn print_scan_summary(report: &ScanReport) {
    println!("Target: {}", report.target);
    println!("TCP ports: {}", join_or_dash(&report.tcp_ports));
    println!("UDP ports: {}", join_or_dash(&report.udp_ports));
    println!("Scanned hosts: {}", report.scanned_hosts);
    println!("Reachable hosts: {}", report.reachable_hosts.len());
    println!("Elapsed: {} ms", report.duration_ms);
    println!();

    if report.reachable_hosts.is_empty() {
        println!("No reachable hosts were discovered with the requested port set.");
        return;
    }

    for host in &report.reachable_hosts {
        println!("{:<15}  {}", host.ip, host_services_summary(host));
    }
}

pub fn print_diff(diff: &DiffReport) {
    if diff.added_hosts.is_empty() && diff.removed_hosts.is_empty() && diff.changed_hosts.is_empty()
    {
        println!("No differences detected.");
        return;
    }

    if !diff.added_hosts.is_empty() {
        println!("Added hosts:");
        for host in &diff.added_hosts {
            println!("  {}  {}", host.ip, host_services_summary(host));
        }
        println!();
    }

    if !diff.removed_hosts.is_empty() {
        println!("Removed hosts:");
        for host in &diff.removed_hosts {
            println!("  {}  {}", host.ip, host_services_summary(host));
        }
        println!();
    }

    if !diff.changed_hosts.is_empty() {
        println!("Changed hosts:");
        for host in &diff.changed_hosts {
            let mut segments = Vec::new();

            if !host.added_tcp_ports.is_empty() || !host.removed_tcp_ports.is_empty() {
                segments.push(format!(
                    "tcp +{} -{}",
                    join_or_dash(&host.added_tcp_ports),
                    join_or_dash(&host.removed_tcp_ports)
                ));
            }

            if !host.added_udp_ports.is_empty() || !host.removed_udp_ports.is_empty() {
                segments.push(format!(
                    "udp +{} -{}",
                    join_or_dash(&host.added_udp_ports),
                    join_or_dash(&host.removed_udp_ports)
                ));
            }

            if !host.added_udp_open_filtered_ports.is_empty()
                || !host.removed_udp_open_filtered_ports.is_empty()
            {
                segments.push(format!(
                    "udp? +{} -{}",
                    join_or_dash(&host.added_udp_open_filtered_ports),
                    join_or_dash(&host.removed_udp_open_filtered_ports)
                ));
            }

            println!("  {}  {}", host.ip, segments.join("  "));
        }
    }
}

pub fn print_wifi_summary(report: &WifiScanReport) {
    println!("Backend: {}", report.backend);
    if let Some(interface) = &report.interface {
        println!("Interface: {}", interface);
    }
    println!("Networks found: {}", report.networks.len());
    println!("Elapsed: {} ms", report.duration_ms);
    println!();

    if report.networks.is_empty() {
        println!("No Wi-Fi networks were found.");
        return;
    }

    let uses_dbm = report
        .networks
        .iter()
        .any(|network| network.signal_dbm.is_some());
    if uses_dbm {
        println!(
            "{:<28} {:<20} {:>10} {:>8}  {}",
            "SSID", "BSSID", "RSSI(dBm)", "Channel", "Security"
        );
        for network in &report.networks {
            println!(
                "{:<28} {:<20} {:>10} {:>8}  {}",
                truncate(&network.ssid, 28),
                network.bssid.as_deref().unwrap_or("-"),
                network
                    .signal_dbm
                    .map(|signal| signal.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                network.channel.as_deref().unwrap_or("-"),
                network.security.as_deref().unwrap_or("-"),
            );
        }
    } else {
        println!(
            "{:<28} {:<20} {:>10} {:>8}  {}",
            "SSID", "BSSID", "Signal", "Channel", "Security"
        );
        for network in &report.networks {
            let signal = network
                .signal_percent
                .map(|signal| format!("{signal}%"))
                .unwrap_or_else(|| "-".to_string());

            println!(
                "{:<28} {:<20} {:>10} {:>8}  {}",
                truncate(&network.ssid, 28),
                network.bssid.as_deref().unwrap_or("-"),
                signal,
                network.channel.as_deref().unwrap_or("-"),
                network.security.as_deref().unwrap_or("-"),
            );
        }
    }
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if path == Path::new("-") {
        serde_json::to_writer_pretty(io::stdout().lock(), value)?;
        println!();
        return Ok(());
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string_pretty(value)?;
    fs::write(path, content)?;
    Ok(())
}

fn join_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn join_or_dash(ports: &[u16]) -> String {
    if ports.is_empty() {
        "-".to_string()
    } else {
        join_ports(ports)
    }
}

fn host_services_summary(host: &HostReport) -> String {
    let mut segments = Vec::new();

    if !host.tcp_open_ports.is_empty() {
        segments.push(format!("tcp: {}", join_ports(&host.tcp_open_ports)));
    }

    if !host.udp_open_ports.is_empty() {
        segments.push(format!("udp: {}", join_ports(&host.udp_open_ports)));
    }

    if !host.udp_open_filtered_ports.is_empty() {
        segments.push(format!(
            "udp?: {}",
            join_ports(&host.udp_open_filtered_ports)
        ));
    }

    if segments.is_empty() {
        "-".to_string()
    } else {
        segments.join("  ")
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();
    if count <= max_chars {
        return value.to_string();
    }

    value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>()
        + "…"
}

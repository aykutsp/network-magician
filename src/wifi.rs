use crate::model::{WifiNetwork, WifiScanReport};
use anyhow::{anyhow, bail, Context, Result};
use std::cmp::Reverse;
use std::process::Command;
use std::time::Instant;

pub fn scan_wifi_networks() -> Result<WifiScanReport> {
    let started = Instant::now();
    let mut report = scan_wifi_networks_inner()?;
    report.duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    sort_networks(&mut report.networks);
    Ok(report)
}

#[cfg(target_os = "windows")]
fn scan_wifi_networks_inner() -> Result<WifiScanReport> {
    let output = run_command("netsh", &["wlan", "show", "networks", "mode=bssid"])?;
    parse_netsh_output(&output)
}

#[cfg(target_os = "macos")]
fn scan_wifi_networks_inner() -> Result<WifiScanReport> {
    let airport =
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
    let output = run_command(airport, &["-s"])?;
    parse_airport_output(&output)
}

#[cfg(target_os = "linux")]
fn scan_wifi_networks_inner() -> Result<WifiScanReport> {
    let output = run_command(
        "nmcli",
        &[
            "-t",
            "-f",
            "SSID,BSSID,SIGNAL,CHAN,SECURITY",
            "dev",
            "wifi",
            "list",
            "--rescan",
            "yes",
        ],
    )?;
    parse_nmcli_output(&output)
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn scan_wifi_networks_inner() -> Result<WifiScanReport> {
    bail!("Wi-Fi scanning is not supported on this platform");
}

pub fn parse_netsh_output(output: &str) -> Result<WifiScanReport> {
    let mut interface = None;
    let mut networks = Vec::new();

    let mut current_ssid = None;
    let mut current_auth = None;
    let mut current_encrypt = None;
    let mut current_bssid = None;
    let mut current_signal_percent = None;
    let mut current_channel = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if label_matches(trimmed, "Interface name") {
            interface = value_after_colon(trimmed).map(ToOwned::to_owned);
            continue;
        }

        if trimmed.starts_with("SSID ") {
            push_windows_bssid(
                &mut networks,
                &current_ssid,
                &current_auth,
                &current_encrypt,
                &mut current_bssid,
                &mut current_signal_percent,
                &mut current_channel,
            );

            current_ssid = value_after_colon(trimmed).map(hidden_to_placeholder);
            current_auth = None;
            current_encrypt = None;
            continue;
        }

        if label_matches(trimmed, "Authentication") {
            current_auth = value_after_colon(trimmed).map(ToOwned::to_owned);
            continue;
        }

        if label_matches(trimmed, "Encryption") {
            current_encrypt = value_after_colon(trimmed).map(ToOwned::to_owned);
            continue;
        }

        if trimmed.starts_with("BSSID ") {
            push_windows_bssid(
                &mut networks,
                &current_ssid,
                &current_auth,
                &current_encrypt,
                &mut current_bssid,
                &mut current_signal_percent,
                &mut current_channel,
            );

            current_bssid = value_after_colon(trimmed).map(ToOwned::to_owned);
            continue;
        }

        if label_matches(trimmed, "Signal") {
            current_signal_percent = value_after_colon(trimmed)
                .and_then(|value| value.trim_end_matches('%').parse::<u8>().ok());
            continue;
        }

        if label_matches(trimmed, "Channel") {
            current_channel = value_after_colon(trimmed).map(ToOwned::to_owned);
            continue;
        }
    }

    push_windows_bssid(
        &mut networks,
        &current_ssid,
        &current_auth,
        &current_encrypt,
        &mut current_bssid,
        &mut current_signal_percent,
        &mut current_channel,
    );

    Ok(WifiScanReport {
        backend: "netsh".to_string(),
        interface,
        networks,
        duration_ms: 0,
    })
}

pub fn parse_airport_output(output: &str) -> Result<WifiScanReport> {
    let mut networks = Vec::new();

    for line in output.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(bssid_index) = tokens.iter().position(|token| looks_like_bssid(token)) else {
            continue;
        };

        if tokens.len() < bssid_index + 6 {
            continue;
        }

        let ssid = tokens[..bssid_index].join(" ");
        let security = tokens[bssid_index + 5..].join(" ");

        networks.push(WifiNetwork {
            ssid: hidden_to_placeholder(if ssid.is_empty() { "<hidden>" } else { &ssid }),
            bssid: Some(tokens[bssid_index].to_string()),
            signal_dbm: tokens[bssid_index + 1].parse::<i32>().ok(),
            signal_percent: None,
            channel: Some(tokens[bssid_index + 2].to_string()),
            security: empty_to_none(security),
        });
    }

    Ok(WifiScanReport {
        backend: "airport".to_string(),
        interface: Some("airport".to_string()),
        networks,
        duration_ms: 0,
    })
}

pub fn parse_nmcli_output(output: &str) -> Result<WifiScanReport> {
    let mut networks = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let fields = split_escaped(trimmed, ':');
        if fields.len() < 5 {
            continue;
        }

        let ssid = if fields[0].is_empty() {
            "<hidden>".to_string()
        } else {
            fields[0].clone()
        };

        networks.push(WifiNetwork {
            ssid,
            bssid: empty_to_none(fields[1].clone()),
            signal_dbm: None,
            signal_percent: fields[2].parse::<u8>().ok(),
            channel: empty_to_none(fields[3].clone()),
            security: empty_to_none(fields[4].clone()),
        });
    }

    Ok(WifiScanReport {
        backend: "nmcli".to_string(),
        interface: None,
        networks,
        duration_ms: 0,
    })
}

fn run_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stderr.is_empty() {
            format!("{program} exited with status {}", output.status)
        } else {
            format!("{program} exited with status {}: {stderr}", output.status)
        };
        bail!(message);
    }

    String::from_utf8(output.stdout).map_err(|_| anyhow!("command output was not valid UTF-8"))
}

fn push_windows_bssid(
    networks: &mut Vec<WifiNetwork>,
    current_ssid: &Option<String>,
    current_auth: &Option<String>,
    current_encrypt: &Option<String>,
    current_bssid: &mut Option<String>,
    current_signal_percent: &mut Option<u8>,
    current_channel: &mut Option<String>,
) {
    let Some(bssid) = current_bssid.take() else {
        return;
    };

    let security = match (current_auth.as_deref(), current_encrypt.as_deref()) {
        (Some(auth), Some(encryption)) => Some(format!("{auth} / {encryption}")),
        (Some(auth), None) => Some(auth.to_string()),
        (None, Some(encryption)) => Some(encryption.to_string()),
        (None, None) => None,
    };

    networks.push(WifiNetwork {
        ssid: current_ssid
            .clone()
            .unwrap_or_else(|| "<hidden>".to_string()),
        bssid: Some(bssid),
        signal_dbm: None,
        signal_percent: current_signal_percent.take(),
        channel: current_channel.take(),
        security,
    });
}

fn sort_networks(networks: &mut [WifiNetwork]) {
    networks.sort_by_key(|network| {
        (
            Reverse(network.signal_dbm.unwrap_or(i32::MIN)),
            Reverse(network.signal_percent.unwrap_or(0)),
            network.channel.clone().unwrap_or_default(),
            network.ssid.clone(),
        )
    });
}

fn split_escaped(input: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if ch == separator {
            parts.push(current.trim().to_string());
            current.clear();
            continue;
        }

        current.push(ch);
    }

    parts.push(current.trim().to_string());
    parts
}

fn label_matches(line: &str, label: &str) -> bool {
    line.split_once(':')
        .map(|(name, _)| name.trim().eq_ignore_ascii_case(label))
        .unwrap_or(false)
}

fn value_after_colon(line: &str) -> Option<&str> {
    line.split_once(':').map(|(_, value)| value.trim())
}

fn looks_like_bssid(token: &str) -> bool {
    token.len() == 17
        && token.chars().enumerate().all(|(index, ch)| {
            if matches!(index, 2 | 5 | 8 | 11 | 14) {
                ch == ':'
            } else {
                ch.is_ascii_hexdigit()
            }
        })
}

fn hidden_to_placeholder(value: &str) -> String {
    if value.trim().is_empty() {
        "<hidden>".to_string()
    } else {
        value.trim().to_string()
    }
}

fn empty_to_none<T>(value: T) -> Option<String>
where
    T: Into<String>,
{
    let value = value.into();
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "--" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

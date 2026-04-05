use crate::model::ScanReport;
use anyhow::{anyhow, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const DEFAULT_TCP_PORTS: &[u16] = &[22, 53, 80, 139, 443, 445, 502, 3389, 8080];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPortSelection {
    pub tcp_ports: Vec<u16>,
    pub udp_ports: Vec<u16>,
}

pub fn parse_scan_ports(
    tcp_input: Option<&str>,
    udp_input: Option<&str>,
) -> Result<ScanPortSelection> {
    let udp_ports = parse_optional_ports(udp_input)?.unwrap_or_default();
    let tcp_ports = match normalize_port_input(tcp_input) {
        Some(raw) => parse_port_spec(raw)?,
        None if udp_ports.is_empty() => DEFAULT_TCP_PORTS.to_vec(),
        None => Vec::new(),
    };

    if tcp_ports.is_empty() && udp_ports.is_empty() {
        return Err(anyhow!("at least one TCP or UDP port must be selected"));
    }

    Ok(ScanPortSelection {
        tcp_ports,
        udp_ports,
    })
}

pub fn load_report(path: &Path) -> Result<ScanReport> {
    let content = fs::read_to_string(path)?;
    let report = serde_json::from_str(&content)?;
    Ok(report)
}

fn parse_optional_ports(input: Option<&str>) -> Result<Option<Vec<u16>>> {
    match normalize_port_input(input) {
        Some(raw) => Ok(Some(parse_port_spec(raw)?)),
        None => Ok(None),
    }
}

fn normalize_port_input(input: Option<&str>) -> Option<&str> {
    input.map(str::trim).filter(|value| !value.is_empty())
}

fn parse_port_spec(raw: &str) -> Result<Vec<u16>> {
    let mut ports = BTreeSet::new();

    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(anyhow!("empty port entry in list"));
        }

        if let Some((start, end)) = part.split_once('-') {
            let start = parse_port(start.trim())?;
            let end = parse_port(end.trim())?;

            if start > end {
                return Err(anyhow!("invalid port range: {part}"));
            }

            for port in start..=end {
                ports.insert(port);
            }
        } else {
            ports.insert(parse_port(part)?);
        }
    }

    if ports.is_empty() {
        return Err(anyhow!("no valid ports provided"));
    }

    Ok(ports.into_iter().collect())
}

fn parse_port(value: &str) -> Result<u16> {
    let port: u16 = value
        .parse()
        .map_err(|_| anyhow!("invalid port: {value}"))?;

    if port == 0 {
        return Err(anyhow!("port must be greater than zero"));
    }

    Ok(port)
}

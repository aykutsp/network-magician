use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostReport {
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_open_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp_open_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp_open_filtered_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanReport {
    pub target: String,
    pub scanned_hosts: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp_ports: Vec<u16>,
    pub reachable_hosts: Vec<HostReport>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WifiNetwork {
    pub ssid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WifiScanReport {
    pub backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    pub networks: Vec<WifiNetwork>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffReport {
    pub added_hosts: Vec<HostReport>,
    pub removed_hosts: Vec<HostReport>,
    pub changed_hosts: Vec<HostChange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostChange {
    pub ip: Ipv4Addr,
    pub added_tcp_ports: Vec<u16>,
    pub removed_tcp_ports: Vec<u16>,
    pub added_udp_ports: Vec<u16>,
    pub removed_udp_ports: Vec<u16>,
    pub added_udp_open_filtered_ports: Vec<u16>,
    pub removed_udp_open_filtered_ports: Vec<u16>,
}

impl ScanReport {
    pub fn diff(&self, other: &Self) -> DiffReport {
        let left: BTreeMap<Ipv4Addr, &HostReport> = self
            .reachable_hosts
            .iter()
            .map(|host| (host.ip, host))
            .collect();
        let right: BTreeMap<Ipv4Addr, &HostReport> = other
            .reachable_hosts
            .iter()
            .map(|host| (host.ip, host))
            .collect();

        let mut added_hosts = Vec::new();
        let mut removed_hosts = Vec::new();
        let mut changed_hosts = Vec::new();

        for (ip, host) in &right {
            if !left.contains_key(ip) {
                added_hosts.push((**host).clone());
            }
        }

        for (ip, host) in &left {
            if !right.contains_key(ip) {
                removed_hosts.push((**host).clone());
            }
        }

        for ip in left.keys().filter(|ip| right.contains_key(*ip)) {
            let old_host = left[ip];
            let new_host = right[ip];

            let (added_tcp_ports, removed_tcp_ports) =
                diff_ports(&old_host.tcp_open_ports, &new_host.tcp_open_ports);
            let (added_udp_ports, removed_udp_ports) =
                diff_ports(&old_host.udp_open_ports, &new_host.udp_open_ports);
            let (added_udp_open_filtered_ports, removed_udp_open_filtered_ports) = diff_ports(
                &old_host.udp_open_filtered_ports,
                &new_host.udp_open_filtered_ports,
            );

            if !added_tcp_ports.is_empty()
                || !removed_tcp_ports.is_empty()
                || !added_udp_ports.is_empty()
                || !removed_udp_ports.is_empty()
                || !added_udp_open_filtered_ports.is_empty()
                || !removed_udp_open_filtered_ports.is_empty()
            {
                changed_hosts.push(HostChange {
                    ip: *ip,
                    added_tcp_ports,
                    removed_tcp_ports,
                    added_udp_ports,
                    removed_udp_ports,
                    added_udp_open_filtered_ports,
                    removed_udp_open_filtered_ports,
                });
            }
        }

        DiffReport {
            added_hosts,
            removed_hosts,
            changed_hosts,
        }
    }
}

fn diff_ports(old_ports: &[u16], new_ports: &[u16]) -> (Vec<u16>, Vec<u16>) {
    let old: BTreeSet<u16> = old_ports.iter().copied().collect();
    let new: BTreeSet<u16> = new_ports.iter().copied().collect();

    let added = new.difference(&old).copied().collect();
    let removed = old.difference(&new).copied().collect();

    (added, removed)
}

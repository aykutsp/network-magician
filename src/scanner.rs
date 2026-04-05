use crate::model::{HostReport, ScanReport};
use crate::target::TargetSpec;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::io::ErrorKind;
use std::io::IsTerminal;
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

pub fn scan_targets(
    target: &str,
    tcp_ports: &[u16],
    udp_ports: &[u16],
    timeout_ms: u64,
    concurrency: usize,
    show_progress: bool,
) -> Result<ScanReport> {
    let spec = TargetSpec::parse(target)?;
    let hosts = spec.hosts().to_vec();
    let worker_count = concurrency.max(1).min(hosts.len().max(1));
    let timeout = Duration::from_millis(timeout_ms);
    let started_at = Instant::now();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .build()?;

    let progress = build_progress_bar(hosts.len(), show_progress);
    let progress_handle = progress.clone();

    let mut reachable_hosts: Vec<HostReport> = pool.install(|| {
        hosts
            .par_iter()
            .filter_map(|ip| {
                let tcp_open_ports = probe_tcp_host(*ip, tcp_ports, timeout);
                let (udp_open_ports, udp_open_filtered_ports) =
                    probe_udp_host(*ip, udp_ports, timeout);
                progress_handle.inc(1);

                (!tcp_open_ports.is_empty()
                    || !udp_open_ports.is_empty()
                    || !udp_open_filtered_ports.is_empty())
                .then_some(HostReport {
                    ip: *ip,
                    tcp_open_ports,
                    udp_open_ports,
                    udp_open_filtered_ports,
                })
            })
            .collect()
    });

    progress.finish_and_clear();
    reachable_hosts.sort_by_key(|host| host.ip);

    Ok(ScanReport {
        target: spec.label().to_string(),
        scanned_hosts: hosts.len(),
        tcp_ports: tcp_ports.to_vec(),
        udp_ports: udp_ports.to_vec(),
        reachable_hosts,
        duration_ms: started_at.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

fn build_progress_bar(host_count: usize, show_progress: bool) -> ProgressBar {
    if !show_progress || !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }

    let progress = ProgressBar::new(host_count as u64);
    if let Ok(style) =
        ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len}")
    {
        progress.set_style(style.progress_chars("##-"));
    }
    progress
}

fn probe_tcp_host(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> Vec<u16> {
    let mut open_ports = Vec::new();

    for &port in ports {
        let socket = SocketAddrV4::new(ip, port);
        if TcpStream::connect_timeout(&socket.into(), timeout).is_ok() {
            open_ports.push(port);
        }
    }

    open_ports
}

fn probe_udp_host(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> (Vec<u16>, Vec<u16>) {
    let mut open_ports = Vec::new();
    let mut open_filtered_ports = Vec::new();

    for &port in ports {
        match probe_udp_port(ip, port, timeout) {
            UdpProbeResult::Open => open_ports.push(port),
            UdpProbeResult::OpenOrFiltered => open_filtered_ports.push(port),
            UdpProbeResult::Closed => {}
        }
    }

    (open_ports, open_filtered_ports)
}

fn probe_udp_port(ip: Ipv4Addr, port: u16, timeout: Duration) -> UdpProbeResult {
    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(socket) => socket,
        Err(_) => return UdpProbeResult::Closed,
    };

    let _ = socket.set_read_timeout(Some(timeout));
    let _ = socket.set_write_timeout(Some(timeout));

    if socket.connect(SocketAddrV4::new(ip, port)).is_err() {
        return UdpProbeResult::Closed;
    }

    match socket.send(&[0]) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
            return UdpProbeResult::Closed;
        }
        Err(_) => return UdpProbeResult::Closed,
    }

    let mut buffer = [0u8; 2048];
    match socket.recv(&mut buffer) {
        Ok(_) => UdpProbeResult::Open,
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            UdpProbeResult::OpenOrFiltered
        }
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => UdpProbeResult::Closed,
        Err(_) => UdpProbeResult::Closed,
    }
}

enum UdpProbeResult {
    Open,
    OpenOrFiltered,
    Closed,
}

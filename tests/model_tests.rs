use network_magician::model::{HostReport, ScanReport};
use std::net::Ipv4Addr;

#[test]
fn diff_detects_added_removed_and_changed_hosts() {
    let old = ScanReport {
        target: "192.168.1.0/24".into(),
        scanned_hosts: 254,
        tcp_ports: vec![22, 80, 443],
        udp_ports: vec![53, 161],
        reachable_hosts: vec![
            HostReport {
                ip: Ipv4Addr::new(192, 168, 1, 10),
                tcp_open_ports: vec![22, 80],
                udp_open_ports: vec![161],
                udp_open_filtered_ports: vec![],
            },
            HostReport {
                ip: Ipv4Addr::new(192, 168, 1, 20),
                tcp_open_ports: vec![80],
                udp_open_ports: vec![],
                udp_open_filtered_ports: vec![53],
            },
        ],
        duration_ms: 500,
    };

    let new = ScanReport {
        target: "192.168.1.0/24".into(),
        scanned_hosts: 254,
        tcp_ports: vec![22, 80, 443],
        udp_ports: vec![53, 161],
        reachable_hosts: vec![
            HostReport {
                ip: Ipv4Addr::new(192, 168, 1, 10),
                tcp_open_ports: vec![22, 443],
                udp_open_ports: vec![],
                udp_open_filtered_ports: vec![53],
            },
            HostReport {
                ip: Ipv4Addr::new(192, 168, 1, 30),
                tcp_open_ports: vec![80],
                udp_open_ports: vec![161],
                udp_open_filtered_ports: vec![],
            },
        ],
        duration_ms: 450,
    };

    let diff = old.diff(&new);

    assert_eq!(diff.added_hosts.len(), 1);
    assert_eq!(diff.removed_hosts.len(), 1);
    assert_eq!(diff.changed_hosts.len(), 1);
    assert_eq!(diff.changed_hosts[0].ip, Ipv4Addr::new(192, 168, 1, 10));
    assert_eq!(diff.changed_hosts[0].added_tcp_ports, vec![443]);
    assert_eq!(diff.changed_hosts[0].removed_tcp_ports, vec![80]);
    assert_eq!(diff.changed_hosts[0].added_udp_ports, Vec::<u16>::new());
    assert_eq!(diff.changed_hosts[0].removed_udp_ports, vec![161]);
    assert_eq!(
        diff.changed_hosts[0].added_udp_open_filtered_ports,
        vec![53]
    );
    assert_eq!(
        diff.changed_hosts[0].removed_udp_open_filtered_ports,
        Vec::<u16>::new()
    );
}

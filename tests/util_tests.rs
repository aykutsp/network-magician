use network_magician::util::parse_scan_ports;

#[test]
fn parses_port_lists_and_ranges() {
    let selection =
        parse_scan_ports(Some("80,443,8000-8002,443"), Some("53,161")).expect("ports should parse");
    assert_eq!(selection.tcp_ports, vec![80, 443, 8000, 8001, 8002]);
    assert_eq!(selection.udp_ports, vec![53, 161]);
}

#[test]
fn keeps_default_ports_when_input_is_missing() {
    let selection = parse_scan_ports(None, None).expect("default ports should parse");
    assert_eq!(
        selection.tcp_ports,
        vec![22, 53, 80, 139, 443, 445, 502, 3389, 8080]
    );
    assert!(selection.udp_ports.is_empty());
}

#[test]
fn supports_udp_only_scans() {
    let selection = parse_scan_ports(None, Some("53,67-68")).expect("UDP ports should parse");
    assert!(selection.tcp_ports.is_empty());
    assert_eq!(selection.udp_ports, vec![53, 67, 68]);
}

#[test]
fn rejects_invalid_port_ranges() {
    let error = parse_scan_ports(Some("9000-8999"), None).expect_err("range should fail");
    assert!(error.to_string().contains("invalid port range"));
}

use network_magician::target::TargetSpec;
use std::net::Ipv4Addr;

#[test]
fn parses_single_host_target() {
    let target = TargetSpec::parse("192.168.1.44").expect("target should parse");
    assert_eq!(target.hosts(), &[Ipv4Addr::new(192, 168, 1, 44)]);
}

#[test]
fn parses_ipv4_range_target() {
    let target = TargetSpec::parse("192.168.1.10-192.168.1.12").expect("range should parse");
    assert_eq!(
        target.hosts(),
        &[
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 11),
            Ipv4Addr::new(192, 168, 1, 12),
        ]
    );
}

#[test]
fn rejects_reversed_ranges() {
    let error = TargetSpec::parse("192.168.1.12-192.168.1.10").expect_err("range should fail");
    assert!(error.to_string().contains("range start"));
}

use network_magician::wifi::{parse_airport_output, parse_netsh_output, parse_nmcli_output};

#[test]
fn parses_windows_wifi_scan_output() {
    let report = parse_netsh_output(
        r#"
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : OfficeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 34:12:98:aa:bb:cc
         Signal             : 88%
         Radio type         : 802.11ax
         Channel            : 36

SSID 2 : Lab IoT
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 98:76:54:44:33:22
         Signal             : 54%
         Radio type         : 802.11n
         Channel            : 6
"#,
    )
    .expect("netsh output should parse");

    assert_eq!(report.backend, "netsh");
    assert_eq!(report.interface.as_deref(), Some("Wi-Fi"));
    assert_eq!(report.networks.len(), 2);
    assert_eq!(report.networks[0].ssid, "OfficeNet");
    assert_eq!(report.networks[0].signal_percent, Some(88));
    assert_eq!(report.networks[0].channel.as_deref(), Some("36"));
}

#[test]
fn parses_macos_wifi_scan_output() {
    let report = parse_airport_output(
        r#"
SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
OfficeNet 34:12:98:aa:bb:cc -47 36 Y US WPA2/WPA3 Personal
Workshop 98:76:54:44:33:22 -61 11 Y US WPA2 Personal
"#,
    )
    .expect("airport output should parse");

    assert_eq!(report.backend, "airport");
    assert_eq!(report.networks.len(), 2);
    assert_eq!(report.networks[0].ssid, "OfficeNet");
    assert_eq!(report.networks[0].signal_dbm, Some(-47));
    assert_eq!(report.networks[0].channel.as_deref(), Some("36"));
}

#[test]
fn parses_linux_wifi_scan_output() {
    let report = parse_nmcli_output(
        r#"
OfficeNet:34\:12\:98\:aa\:bb\:cc:81:36:WPA2 WPA3
Lab\ IoT:98\:76\:54\:44\:33\:22:57:6:WPA2
"#,
    )
    .expect("nmcli output should parse");

    assert_eq!(report.backend, "nmcli");
    assert_eq!(report.networks.len(), 2);
    assert_eq!(report.networks[0].ssid, "OfficeNet");
    assert_eq!(report.networks[0].signal_percent, Some(81));
    assert_eq!(report.networks[1].ssid, "Lab IoT");
    assert_eq!(report.networks[1].channel.as_deref(), Some("6"));
}

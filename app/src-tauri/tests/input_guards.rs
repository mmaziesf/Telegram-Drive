//! Input guards on commands that reach the network or the local database.
//!
//! These run without a Telegram session or a WebView. They pin the address
//! and hostname rules that keep "upload from URL" (and the crash reporter)
//! away from local and reserved networks.

use std::net::IpAddr;

use app_lib::commands::fs::{is_public_remote_ip, validate_remote_url_syntax};

fn ip(text: &str) -> IpAddr {
    text.parse()
        .unwrap_or_else(|error| panic!("bad test address {text}: {error}"))
}

#[test]
fn reserved_and_local_addresses_are_not_public() {
    for address in [
        // IPv4 special-purpose registry entries that are not globally reachable.
        "0.1.2.3",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.8",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        // IPv6 loopback, unspecified, IPv4-compatible and IPv4-mapped forms.
        "::",
        "::1",
        "::7f00:1",
        "::a9fe:a9fe",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:0:127.0.0.1",
        // NAT64 with an embedded private IPv4, and local-use NAT64.
        "64:ff9b::127.0.0.1",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1::8.8.8.8",
        // 6to4 with an embedded private IPv4.
        "2002:7f00:1::",
        "2002:c0a8:101::1",
        "2002:a9fe:a9fe::1",
        // Discard, IETF assignments (Teredo, benchmarking), documentation.
        "100::1",
        "2001::1",
        "2001:2::1",
        "2001:1ff::1",
        "2001:db8::1",
        "3fff::1",
        "3fff:fff::1",
        // SRv6, ULA, deprecated site-local, link-local, multicast.
        "5f00::1",
        "fc00::1",
        "fd12:3456::1",
        "fec0::1",
        "feff::1",
        "fe80::1",
        "ff02::1",
    ] {
        assert!(
            !is_public_remote_ip(ip(address)),
            "{address} must be refused"
        );
    }
}

#[test]
fn ordinary_public_addresses_are_allowed() {
    for address in [
        "1.1.1.1",
        "8.8.8.8",
        "93.184.215.14",
        "149.154.167.50",
        "::ffff:8.8.8.8",
        "64:ff9b::8.8.8.8",
        "2002:808:808::1",
        "2001:200::1",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
        "3fff:1000::1",
    ] {
        assert!(
            is_public_remote_ip(ip(address)),
            "{address} must be allowed"
        );
    }
}

#[test]
fn upload_urls_naming_local_hosts_are_refused_before_any_lookup() {
    for text in [
        "http://localhost/file",
        "http://printer/file",
        "http://nas.local/file",
        "http://router.home.arpa/file",
        "http://wiki.intranet/file",
        "http://db.corp./file",
        "http://127.1/file",
        "http://0x7f.0.0.1/file",
        "http://2130706433/file",
        "http://[::1]/file",
        "http://[::ffff:169.254.169.254]/file",
        "http://[64:ff9b::a00:1]/file",
        "http://[2002:a00:1::]/file",
        "http://[fec0::1]/file",
        "ftp://example.com/file",
        "file:///etc/passwd",
        "https://user:secret@example.com/file",
    ] {
        let url = reqwest::Url::parse(text)
            .unwrap_or_else(|error| panic!("bad test URL {text}: {error}"));
        assert!(
            validate_remote_url_syntax(&url).is_err(),
            "{text} must be refused"
        );
    }
    for text in [
        "https://example.com/file.zip",
        "http://8.8.8.8/file",
        "https://[2606:4700:4700::1111]/file",
        "https://files.example.org./file",
    ] {
        let url = reqwest::Url::parse(text)
            .unwrap_or_else(|error| panic!("bad test URL {text}: {error}"));
        assert_eq!(validate_remote_url_syntax(&url), Ok(()), "{text}");
    }
}

use tagotip_codec::parse::parse_uplink;
use tagotip_codec::types::*;

const AUTH: &str = "4deedd7bab8817ec";

#[test]
fn ping_basic() {
    let input = format!("PING|{AUTH}|sensor_01");
    let frame = parse_uplink(&input).unwrap();
    assert_eq!(frame.method, Method::Ping);
    assert_eq!(frame.auth, AUTH);
    assert_eq!(frame.serial, "sensor_01");
    assert!(frame.seq.is_none());
    assert!(frame.push_body.is_none());
    assert!(frame.pull_body.is_none());
}

#[test]
fn ping_with_seq() {
    let input = format!("PING|!5|{AUTH}|sensor_01");
    let frame = parse_uplink(&input).unwrap();
    assert_eq!(frame.method, Method::Ping);
    assert_eq!(frame.seq, Some(5));
}

#[test]
fn ping_missing_serial_rejected() {
    let input = format!("PING|{AUTH}");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn ping_invalid_auth_rejected() {
    let input = "PING|invalid_auth|sensor_01";
    assert!(parse_uplink(input).is_err());
}

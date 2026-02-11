use tagotip_codec::parse::parse_uplink;
use tagotip_codec::types::*;

const AUTH: &str = "ate2bd319014b24e0a8aca9f00aea4c0d0";

#[test]
fn pull_single_variable() {
    let input = format!("PULL|{AUTH}|weather_denver|[temperature]");
    let frame = parse_uplink(&input).unwrap();
    assert_eq!(frame.method, Method::Pull);
    assert_eq!(frame.serial, "weather_denver");
    let pull = frame.pull_body.unwrap();
    assert_eq!(pull.variables.len(), 1);
    assert_eq!(pull.variables[0], "temperature");
}

#[test]
fn pull_multiple_variables() {
    let input = format!("PULL|{AUTH}|sensor_01|[temperature;humidity;pressure]");
    let frame = parse_uplink(&input).unwrap();
    let pull = frame.pull_body.unwrap();
    assert_eq!(pull.variables.len(), 3);
    assert_eq!(pull.variables[0], "temperature");
    assert_eq!(pull.variables[1], "humidity");
    assert_eq!(pull.variables[2], "pressure");
}

#[test]
fn pull_with_seq() {
    let input = format!("PULL|!7|{AUTH}|weather_denver|[temperature]");
    let frame = parse_uplink(&input).unwrap();
    assert_eq!(frame.seq, Some(7));
    assert_eq!(frame.method, Method::Pull);
}

#[test]
fn pull_empty_rejected() {
    let input = format!("PULL|{AUTH}|sensor_01|[]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn pull_missing_body_rejected() {
    let input = format!("PULL|{AUTH}|sensor_01");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn pull_missing_brackets_rejected() {
    let input = format!("PULL|{AUTH}|sensor_01|temperature");
    assert!(parse_uplink(&input).is_err());
}

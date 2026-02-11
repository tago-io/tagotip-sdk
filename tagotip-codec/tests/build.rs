use tagotip_codec::build::{build_ack, build_headless, build_uplink};
use tagotip_codec::inline_vec::InlineVec;
use tagotip_codec::parse::{parse_ack, parse_headless, parse_uplink};
use tagotip_codec::types::*;

const AUTH: &str = "ate2bd319014b24e0a8aca9f00aea4c0d0";

fn build_to_string(
    f: impl FnOnce(&mut [u8]) -> Result<usize, tagotip_codec::BuildError>,
) -> String {
    let mut buf = [0u8; 4096];
    let n = f(&mut buf).unwrap();
    core::str::from_utf8(&buf[..n]).unwrap().to_string()
}

#[test]
fn build_simple_push() {
    let mut vars = InlineVec::new();
    vars.push(Variable {
        name: "temperature",
        operator: Operator::Number,
        value: Value::Number("32"),
        unit: None,
        timestamp: None,
        group: None,
        meta: None,
    })
    .unwrap();

    let frame = UplinkFrame {
        method: Method::Push,
        seq: None,
        auth: AUTH,
        serial: "sensor_01",
        push_body: Some(PushBody::Structured(StructuredBody {
            group: None,
            timestamp: None,
            body_meta: None,
            variables: vars,
            meta_pool: InlineVec::new(),
        })),
        pull_body: None,
    };

    let output = build_to_string(|buf| build_uplink(&frame, buf));
    assert_eq!(output, format!("PUSH|{AUTH}|sensor_01|[temperature:=32]"));
}

#[test]
fn build_push_with_seq() {
    let mut vars = InlineVec::new();
    vars.push(Variable {
        name: "temp",
        operator: Operator::Number,
        value: Value::Number("25"),
        unit: None,
        timestamp: None,
        group: None,
        meta: None,
    })
    .unwrap();

    let frame = UplinkFrame {
        method: Method::Push,
        seq: Some(42),
        auth: AUTH,
        serial: "sensor_01",
        push_body: Some(PushBody::Structured(StructuredBody {
            group: None,
            timestamp: None,
            body_meta: None,
            variables: vars,
            meta_pool: InlineVec::new(),
        })),
        pull_body: None,
    };

    let output = build_to_string(|buf| build_uplink(&frame, buf));
    assert_eq!(output, format!("PUSH|!42|{AUTH}|sensor_01|[temp:=25]"));
}

#[test]
fn build_ping() {
    let frame = UplinkFrame {
        method: Method::Ping,
        seq: None,
        auth: AUTH,
        serial: "sensor_01",
        push_body: None,
        pull_body: None,
    };

    let output = build_to_string(|buf| build_uplink(&frame, buf));
    assert_eq!(output, format!("PING|{AUTH}|sensor_01"));
}

#[test]
fn build_pull() {
    let mut vars = InlineVec::new();
    vars.push("temperature").unwrap();
    vars.push("humidity").unwrap();

    let frame = UplinkFrame {
        method: Method::Pull,
        seq: None,
        auth: AUTH,
        serial: "sensor_01",
        push_body: None,
        pull_body: Some(PullBody { variables: vars }),
    };

    let output = build_to_string(|buf| build_uplink(&frame, buf));
    assert_eq!(
        output,
        format!("PULL|{AUTH}|sensor_01|[temperature;humidity]")
    );
}

#[test]
fn build_ack_ok_count() {
    let ack = AckFrame {
        seq: None,
        status: AckStatus::Ok,
        detail: Some(AckDetail::Count(3)),
    };
    let output = build_to_string(|buf| build_ack(&ack, buf));
    assert_eq!(output, "ACK|OK|3");
}

#[test]
fn build_ack_pong() {
    let ack = AckFrame {
        seq: Some(1),
        status: AckStatus::Pong,
        detail: None,
    };
    let output = build_to_string(|buf| build_ack(&ack, buf));
    assert_eq!(output, "ACK|!1|PONG");
}

#[test]
fn build_ack_err() {
    let ack = AckFrame {
        seq: Some(5),
        status: AckStatus::Err,
        detail: Some(AckDetail::Error {
            code: ErrorCode::InvalidToken,
            text: "invalid_token",
        }),
    };
    let output = build_to_string(|buf| build_ack(&ack, buf));
    assert_eq!(output, "ACK|!5|ERR|invalid_token");
}

#[test]
fn build_passthrough_hex() {
    let frame = UplinkFrame {
        method: Method::Push,
        seq: None,
        auth: AUTH,
        serial: "dev1",
        push_body: Some(PushBody::Passthrough(PassthroughBody {
            encoding: PassthroughEncoding::Hex,
            data: "DEADBEEF",
        })),
        pull_body: None,
    };

    let output = build_to_string(|buf| build_uplink(&frame, buf));
    assert_eq!(output, format!("PUSH|{AUTH}|dev1|>xDEADBEEF"));
}

#[test]
fn build_headless_push() {
    let mut vars = InlineVec::new();
    vars.push(Variable {
        name: "temp",
        operator: Operator::Number,
        value: Value::Number("32"),
        unit: None,
        timestamp: None,
        group: None,
        meta: None,
    })
    .unwrap();

    let headless = HeadlessFrame {
        serial: "sensor_01",
        push_body: Some(PushBody::Structured(StructuredBody {
            group: None,
            timestamp: None,
            body_meta: None,
            variables: vars,
            meta_pool: InlineVec::new(),
        })),
        pull_body: None,
    };

    let output = build_to_string(|buf| build_headless(Method::Push, &headless, buf));
    assert_eq!(output, "sensor_01|[temp:=32]");
}

#[test]
fn build_headless_ping() {
    let headless = HeadlessFrame {
        serial: "sensor_01",
        push_body: None,
        pull_body: None,
    };

    let output = build_to_string(|buf| build_headless(Method::Ping, &headless, buf));
    assert_eq!(output, "sensor_01");
}

// --- Roundtrip tests ---

fn roundtrip_uplink(input: &str) {
    let parsed = parse_uplink(input).unwrap();
    let output = build_to_string(|buf| build_uplink(&parsed, buf));
    assert_eq!(output, input, "roundtrip failed");
}

#[test]
fn roundtrip_simple_push() {
    roundtrip_uplink(&format!(
        "PUSH|{AUTH}|sensor_01|[temperature:=32;humidity:=65]"
    ));
}

#[test]
fn roundtrip_push_with_seq() {
    roundtrip_uplink(&format!(
        "PUSH|!1|{AUTH}|weather_denver|[temperature:=32;humidity:=65]"
    ));
}

#[test]
fn roundtrip_typed_values() {
    roundtrip_uplink(&format!(
        "PUSH|{AUTH}|sensor_0a1f|[temperature:=32.5#C;status=online;active?=true]"
    ));
}

#[test]
fn roundtrip_location() {
    roundtrip_uplink(&format!(
        "PUSH|{AUTH}|drone_07|[position@=39.74,-104.99,305]"
    ));
}

#[test]
fn roundtrip_passthrough_hex() {
    roundtrip_uplink(&format!("PUSH|{AUTH}|sensor_01|>xDEADBEEF01020304"));
}

#[test]
fn roundtrip_ping() {
    roundtrip_uplink(&format!("PING|{AUTH}|sensor_01"));
}

#[test]
fn roundtrip_pull() {
    roundtrip_uplink(&format!(
        "PULL|{AUTH}|weather_denver|[temperature;humidity;pressure]"
    ));
}

#[test]
fn roundtrip_ack_ok() {
    let input = "ACK|OK|3";
    let parsed = parse_ack(input).unwrap();
    let output = build_to_string(|buf| build_ack(&parsed, buf));
    assert_eq!(output, input);
}

#[test]
fn roundtrip_ack_pong_with_seq() {
    let input = "ACK|!1|PONG";
    let parsed = parse_ack(input).unwrap();
    let output = build_to_string(|buf| build_ack(&parsed, buf));
    assert_eq!(output, input);
}

#[test]
fn roundtrip_ack_err() {
    let input = "ACK|!5|ERR|invalid_token";
    let parsed = parse_ack(input).unwrap();
    let output = build_to_string(|buf| build_ack(&parsed, buf));
    assert_eq!(output, input);
}

#[test]
fn roundtrip_headless_push() {
    let input = "sensor_01|[temp:=32;humidity:=65]";
    let parsed = parse_headless(Method::Push, input).unwrap();
    let output = build_to_string(|buf| build_headless(Method::Push, &parsed, buf));
    assert_eq!(output, input);
}

#[test]
fn roundtrip_body_modifiers() {
    roundtrip_uplink(&format!(
        "PUSH|{AUTH}|sensor_01|^batch_42@1694567890000{{firmware=2.1}}[temperature:=32#C;humidity:=65#%]"
    ));
}

#[test]
fn roundtrip_all_suffixes() {
    roundtrip_uplink(&format!(
        "PUSH|{AUTH}|dev1|[temp:=32.5#C@1694567890000^group1{{source=dht22,quality=high}}]"
    ));
}

#[test]
fn buffer_too_small_error() {
    let frame = UplinkFrame {
        method: Method::Ping,
        seq: None,
        auth: AUTH,
        serial: "sensor_01",
        push_body: None,
        pull_body: None,
    };

    let mut buf = [0u8; 5];
    let result = build_uplink(&frame, &mut buf);
    assert!(result.is_err());
}

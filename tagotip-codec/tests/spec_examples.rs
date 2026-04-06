//! Tests for every example from TagoTiP.md §11.

use tagotip_codec::build::build_uplink;
use tagotip_codec::parse::parse_uplink;
use tagotip_codec::types::*;

const AUTH: &str = "4deedd7bab8817ec";

fn roundtrip(input: &str) {
  let parsed = parse_uplink(input).unwrap();
  let mut buf = [0u8; 4096];
  let n = build_uplink(&parsed, &mut buf).unwrap();
  let output = core::str::from_utf8(&buf[..n]).unwrap();
  assert_eq!(output, input, "roundtrip failed for: {input}");
}

/// §11.1 Simple Push
#[test]
fn spec_11_1_simple_push() {
  let input = format!("PUSH|{AUTH}|weather_denver|[temperature:=32;humidity:=65]");
  let frame = parse_uplink(&input).unwrap();
  assert_eq!(frame.method, Method::Push);
  assert_eq!(frame.serial, "weather_denver");
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  assert_eq!(body.variables.len(), 2);
  roundtrip(&input);
}

/// §11.2 Push with Sequence Counter
#[test]
fn spec_11_2_push_with_seq() {
  let input = format!("PUSH|!1|{AUTH}|weather_denver|[temperature:=32;humidity:=65]");
  let frame = parse_uplink(&input).unwrap();
  assert_eq!(frame.seq, Some(1));
  roundtrip(&input);
}

/// §11.3 Typed Values
#[test]
fn spec_11_3_typed_values() {
  let input = format!("PUSH|{AUTH}|sensor_0a1f|[temperature:=32.5#C;status=online;active?=true]");
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  assert_eq!(body.variables[0].value, Value::Number("32.5"));
  assert_eq!(body.variables[1].value, Value::String("online"));
  assert_eq!(body.variables[2].value, Value::Boolean(true));
  roundtrip(&input);
}

/// §11.3 Negative number
#[test]
fn spec_11_3_negative_number() {
  let input = format!("PUSH|{AUTH}|sensor_0a1f|[temperature:=-15.3#C]");
  roundtrip(&input);
}

/// §11.4 Location as value (@= operator)
#[test]
fn spec_11_4_location_altitude() {
  let input = format!("PUSH|{AUTH}|drone_07|[position@=39.74,-104.99,305]");
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  assert_eq!(body.variables[0].operator, Operator::Location);
  roundtrip(&input);
}

/// §11.4 Location suffix on non-location value
#[test]
fn spec_11_4_location_suffix() {
  let input = format!("PUSH|{AUTH}|drone_07|[speed:=10#km/h@=39.74,-104.99,305]");
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  let var = &body.variables[0];
  assert_eq!(var.operator, Operator::Number);
  assert_eq!(var.unit, Some("km/h"));
  let loc = var.location.unwrap();
  assert_eq!(loc.lat, "39.74");
  assert_eq!(loc.lng, "-104.99");
  assert_eq!(loc.alt, Some("305"));
  roundtrip(&input);
}

/// §11.5 With Metadata
#[test]
fn spec_11_5_metadata() {
  let input = format!("PUSH|{AUTH}|sensor_01|[temperature:=32{{source=dht22,quality=high}}]");
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  let meta = body.variable_metadata(&body.variables[0]);
  assert_eq!(meta.len(), 2);
  roundtrip(&input);
}

/// §11.6 Body-Level Defaults (with body-level location)
#[test]
fn spec_11_6_body_defaults() {
  let input = format!(
    "PUSH|{AUTH}|sensor_01|@=39.74,-104.99@1694567890000^batch_42{{firmware=2.1}}[temperature:=32#C;humidity:=65#%]"
  );
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  let loc = body.location.unwrap();
  assert_eq!(loc.lat, "39.74");
  assert_eq!(loc.lng, "-104.99");
  assert_eq!(body.group, Some("batch_42"));
  assert_eq!(body.timestamp, Some("1694567890000"));
  roundtrip(&input);
}

/// §11.7 Variable-Level Timestamps (Datalogger)
#[test]
fn spec_11_7_datalogger() {
  let input =
    format!("PUSH|{AUTH}|datalogger_7|[temp:=32@1694567890000;temp:=33@1694567900000;temp:=31@1694567910000]");
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  assert_eq!(body.variables.len(), 3);
  // Same variable name repeated
  assert_eq!(body.variables[0].name, "temp");
  assert_eq!(body.variables[1].name, "temp");
  assert_eq!(body.variables[2].name, "temp");
  roundtrip(&input);
}

/// §11.8 Passthrough (Hex)
#[test]
fn spec_11_8_passthrough_hex() {
  let input = format!("PUSH|{AUTH}|sensor_01|>xDEADBEEF01020304");
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Passthrough(p) => p,
    _ => panic!("expected passthrough"),
  };
  assert_eq!(body.encoding, PassthroughEncoding::Hex);
  assert_eq!(body.data, "DEADBEEF01020304");
  roundtrip(&input);
}

/// §11.9 Passthrough (Base64)
#[test]
fn spec_11_9_passthrough_base64() {
  let input = format!("PUSH|{AUTH}|sensor_01|>b3q2+7wECAwQ=");
  roundtrip(&input);
}

/// §11.10 Retrieve Last Value
#[test]
fn spec_11_10_pull() {
  let input = format!("PULL|{AUTH}|weather_denver|[temperature]");
  let frame = parse_uplink(&input).unwrap();
  assert_eq!(frame.method, Method::Pull);
  let pull = frame.pull_body.unwrap();
  assert_eq!(pull.variables[0], "temperature");
  roundtrip(&input);
}

/// §11.11 Retrieve Last Value with Sequence Counter
#[test]
fn spec_11_11_pull_with_seq() {
  let input = format!("PULL|!7|{AUTH}|weather_denver|[temperature]");
  let frame = parse_uplink(&input).unwrap();
  assert_eq!(frame.seq, Some(7));
  roundtrip(&input);
}

/// §11.12 Keepalive
#[test]
fn spec_11_12_ping() {
  let input = format!("PING|{AUTH}|sensor_01");
  let frame = parse_uplink(&input).unwrap();
  assert_eq!(frame.method, Method::Ping);
  roundtrip(&input);
}

/// §11.13 Full Conversation Flow — uplink frames
#[test]
fn spec_11_13_conversation_ping() {
  let input = format!("PING|{AUTH}|weather_denver");
  roundtrip(&input);
}

#[test]
fn spec_11_13_conversation_push() {
  let input = format!("PUSH|{AUTH}|weather_denver|[temperature:=32#F;humidity:=65#%;active?=true]");
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  assert_eq!(body.variables.len(), 3);
  roundtrip(&input);
}

#[test]
fn spec_11_13_conversation_pull() {
  let input = format!("PULL|{AUTH}|weather_denver|[temperature]");
  roundtrip(&input);
}

/// §11.14 Conversation with Sequence Counter — uplink frames
#[test]
fn spec_11_14_ping_with_seq() {
  let input = format!("PING|!1|{AUTH}|weather_denver");
  let frame = parse_uplink(&input).unwrap();
  assert_eq!(frame.seq, Some(1));
  roundtrip(&input);
}

#[test]
fn spec_11_14_push_with_seq() {
  let input = format!("PUSH|!2|{AUTH}|weather_denver|[temperature:=32#F]");
  roundtrip(&input);
}

#[test]
fn spec_11_14_second_push() {
  let input = format!("PUSH|!3|{AUTH}|weather_denver|[humidity:=65#%]");
  roundtrip(&input);
}

/// §11.14 Replay attempt (valid frame, seq enforcement is server-side)
#[test]
fn spec_11_14_replay_attempt() {
  let input = format!("PUSH|!2|{AUTH}|weather_denver|[pressure:=1013#hPa]");
  // This is a valid frame — seq validation is server-side policy
  roundtrip(&input);
}

/// ACK examples from §9.3 and §11.13–§11.14
#[test]
fn spec_ack_examples() {
  use tagotip_codec::build::build_ack;
  use tagotip_codec::parse::parse_ack;

  let cases = [
    "ACK|OK|2",
    "ACK|OK|[temperature:=32#F@1694567890000]",
    "ACK|PONG",
    "ACK|CMD|reboot",
    "ACK|ERR|invalid_token",
    "ACK|ERR|invalid_payload",
    "ACK|!1|OK|2",
    "ACK|!2|OK|[temperature:=32#F@1694567890000]",
    "ACK|!3|PONG",
    "ACK|!5|ERR|invalid_token",
    "ACK|!6|ERR|invalid_seq",
    "ACK|!7|ERR|invalid_payload",
  ];

  for input in cases {
    let parsed = parse_ack(input).unwrap();
    let mut buf = [0u8; 4096];
    let n = build_ack(&parsed, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, input, "ACK roundtrip failed for: {input}");
  }
}

// =========================================================================
// Revision D — Location Suffix Tests
// =========================================================================

/// Location suffix with all other suffixes
#[test]
fn revision_d_all_suffixes() {
  let input = format!(
    "PUSH|{AUTH}|dev1|[temperature:=32.5#C@=39.74,-104.99@1694567890000^reading_001{{source=dht22,quality=high}}]"
  );
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  let var = &body.variables[0];
  assert_eq!(var.unit, Some("C"));
  let loc = var.location.unwrap();
  assert_eq!(loc.lat, "39.74");
  assert_eq!(loc.lng, "-104.99");
  assert_eq!(var.timestamp, Some("1694567890000"));
  assert_eq!(var.group, Some("reading_001"));
  roundtrip(&input);
}

/// Location suffix without unit
#[test]
fn revision_d_location_suffix_no_unit() {
  let input = format!("PUSH|{AUTH}|dev1|[speed:=10@=39.74,-104.99]");
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  let var = &body.variables[0];
  assert_eq!(var.unit, None);
  let loc = var.location.unwrap();
  assert_eq!(loc.lat, "39.74");
  assert_eq!(loc.lng, "-104.99");
  assert_eq!(loc.alt, None);
  roundtrip(&input);
}

/// Body-level location cascading
#[test]
fn revision_d_body_level_location() {
  let input = format!("PUSH|{AUTH}|sensor_01|@=39.74,-104.99@1694567890000[temp:=32#C;humidity:=65#%]");
  roundtrip(&input);
}

/// Variable-level location override
#[test]
fn revision_d_variable_location_override() {
  let input = format!(
    "PUSH|{AUTH}|sensor_01|@=39.74,-104.99@1694567890000[temp:=32@=39.75,-105.00@1694567891000;humidity:=65]"
  );
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  let body_loc = body.location.unwrap();
  assert_eq!(body_loc.lat, "39.74");
  let temp_loc = body.variables[0].location.unwrap();
  assert_eq!(temp_loc.lat, "39.75");
  assert_eq!(body.variables[1].location, None);
  roundtrip(&input);
}

/// @= suffix MUST NOT appear with @= operator
#[test]
fn revision_d_location_suffix_with_location_operator_rejected() {
  let input = format!("PUSH|{AUTH}|dev1|[position@=39.74,-104.99@=40.00,-105.00]");
  assert!(parse_uplink(&input).is_err());
}

/// Body-level @= only (no timestamp)
#[test]
fn revision_d_body_location_only() {
  let input = format!("PUSH|{AUTH}|dev1|@=39.74,-104.99[temp:=32]");
  let frame = parse_uplink(&input).unwrap();
  let body = match frame.push_body.unwrap() {
    PushBody::Structured(s) => s,
    _ => panic!("expected structured"),
  };
  let loc = body.location.unwrap();
  assert_eq!(loc.lat, "39.74");
  assert_eq!(loc.lng, "-104.99");
  assert_eq!(body.timestamp, None);
  roundtrip(&input);
}

/// PULL response with location suffix
#[test]
fn revision_d_ack_with_location_suffix() {
  use tagotip_codec::build::build_ack;
  use tagotip_codec::parse::parse_ack;

  let input = "ACK|OK|[speed:=10#km/h@=39.74,-104.99@1694567890000]";
  let parsed = parse_ack(input).unwrap();
  let mut buf = [0u8; 4096];
  let n = build_ack(&parsed, &mut buf).unwrap();
  let output = core::str::from_utf8(&buf[..n]).unwrap();
  assert_eq!(output, input);
}

/// §13 Size comparison example (Revision D)
#[test]
fn revision_d_size_comparison() {
  let input = format!(
    "PUSH|{AUTH}|sensor_01|@1694567890000^batch_42[temperature:=32#F@=39.74,-104.99{{source=dht22}}]"
  );
  roundtrip(&input);
}

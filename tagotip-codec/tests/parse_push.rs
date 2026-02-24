use tagotip_codec::parse::parse_uplink;
use tagotip_codec::types::*;

const AUTH: &str = "4deedd7bab8817ec";

#[test]
fn simple_push_two_variables() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temperature:=32;humidity:=65]");
    let frame = parse_uplink(&input).unwrap();
    assert_eq!(frame.method, Method::Push);
    assert_eq!(frame.auth, AUTH);
    assert_eq!(frame.serial, "sensor_01");
    assert!(frame.seq.is_none());

    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured body"),
    };
    assert_eq!(body.variables.len(), 2);
    assert_eq!(body.variables[0].name, "temperature");
    assert_eq!(body.variables[0].operator, Operator::Number);
    assert_eq!(body.variables[0].value, Value::Number("32"));
    assert_eq!(body.variables[1].name, "humidity");
    assert_eq!(body.variables[1].value, Value::Number("65"));
}

#[test]
fn push_with_seq() {
    let input = format!("PUSH|!42|{AUTH}|sensor_01|[temp:=25]");
    let frame = parse_uplink(&input).unwrap();
    assert_eq!(frame.seq, Some(42));
    assert_eq!(frame.serial, "sensor_01");
}

#[test]
fn push_typed_values() {
    let input = format!("PUSH|{AUTH}|sensor_0a1f|[temperature:=32.5#C;status=online;active?=true]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured body"),
    };
    assert_eq!(body.variables.len(), 3);
    assert_eq!(body.variables[0].operator, Operator::Number);
    assert_eq!(body.variables[0].value, Value::Number("32.5"));
    assert_eq!(body.variables[0].unit, Some("C"));
    assert_eq!(body.variables[1].operator, Operator::String);
    assert_eq!(body.variables[1].value, Value::String("online"));
    assert_eq!(body.variables[2].operator, Operator::Boolean);
    assert_eq!(body.variables[2].value, Value::Boolean(true));
}

#[test]
fn push_negative_number() {
    let input = format!("PUSH|{AUTH}|sensor_0a1f|[temperature:=-15.3#C]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured body"),
    };
    assert_eq!(body.variables[0].value, Value::Number("-15.3"));
}

#[test]
fn push_location_with_altitude() {
    let input = format!("PUSH|{AUTH}|drone_07|[altitude:=305#m;position@=39.74,-104.99,305]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured body"),
    };
    assert_eq!(body.variables[0].name, "altitude");
    assert_eq!(body.variables[0].unit, Some("m"));
    assert_eq!(body.variables[1].name, "position");
    assert_eq!(body.variables[1].operator, Operator::Location);
    assert_eq!(
        body.variables[1].value,
        Value::Location {
            lat: "39.74",
            lng: "-104.99",
            alt: Some("305")
        }
    );
}

#[test]
fn push_with_metadata() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temperature:=32{{source=dht22,quality=high}}]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured body"),
    };
    let meta = body.variable_metadata(&body.variables[0]);
    assert_eq!(meta.len(), 2);
    assert_eq!(meta[0].key, "source");
    assert_eq!(meta[0].value, "dht22");
    assert_eq!(meta[1].key, "quality");
    assert_eq!(meta[1].value, "high");
}

#[test]
fn push_body_level_modifiers() {
    let input = format!(
        "PUSH|{AUTH}|sensor_01|@1694567890000^batch_42{{firmware=2.1}}[temperature:=32#C;humidity:=65#%]"
    );
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured body"),
    };
    assert_eq!(body.group, Some("batch_42"));
    assert_eq!(body.timestamp, Some("1694567890000"));
    let meta = body.body_metadata();
    assert_eq!(meta[0].key, "firmware");
    assert_eq!(meta[0].value, "2.1");
    assert_eq!(body.variables.len(), 2);
}

#[test]
fn push_all_suffixes() {
    let input = format!(
        "PUSH|{AUTH}|dev1|[temp:=32.5#C@1694567890000^group1{{source=dht22,quality=high}}]"
    );
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured body"),
    };
    let var = &body.variables[0];
    assert_eq!(var.name, "temp");
    assert_eq!(var.value, Value::Number("32.5"));
    assert_eq!(var.unit, Some("C"));
    assert_eq!(var.timestamp, Some("1694567890000"));
    assert_eq!(var.group, Some("group1"));
    let meta = body.variable_metadata(var);
    assert_eq!(meta.len(), 2);
}

#[test]
fn push_passthrough_hex() {
    let input = format!("PUSH|{AUTH}|dev1|>xDEADBEEF01020304");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Passthrough(p) => p,
        _ => panic!("expected passthrough body"),
    };
    assert_eq!(body.encoding, PassthroughEncoding::Hex);
    assert_eq!(body.data, "DEADBEEF01020304");
}

#[test]
fn push_passthrough_base64() {
    let input = format!("PUSH|{AUTH}|sensor_01|>b3q2+7wECAwQ=");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Passthrough(p) => p,
        _ => panic!("expected passthrough body"),
    };
    assert_eq!(body.encoding, PassthroughEncoding::Base64);
    assert_eq!(body.data, "3q2+7wECAwQ=");
}

#[test]
fn push_datalogger_repeated_variable() {
    let input = format!(
        "PUSH|{AUTH}|datalogger_7|[temp:=32@1694567890000;temp:=33@1694567900000;temp:=31@1694567910000]"
    );
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured body"),
    };
    assert_eq!(body.variables.len(), 3);
    assert_eq!(body.variables[0].name, "temp");
    assert_eq!(body.variables[0].timestamp, Some("1694567890000"));
    assert_eq!(body.variables[1].timestamp, Some("1694567900000"));
    assert_eq!(body.variables[2].timestamp, Some("1694567910000"));
}

// --- Error cases ---

#[test]
fn push_empty_variable_block_rejected() {
    let input = format!("PUSH|{AUTH}|dev1|[]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_missing_body_rejected() {
    let input = format!("PUSH|{AUTH}|dev1");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_unit_with_location_rejected() {
    let input = format!("PUSH|{AUTH}|dev1|[pos@=39.74,-104.99#m]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_body_modifiers_out_of_order_rejected() {
    let input = format!("PUSH|{AUTH}|dev1|^batch_42@1694567890000[temp:=32]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_empty_hex_passthrough_rejected() {
    let input = format!("PUSH|{AUTH}|dev1|>x");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_odd_hex_passthrough_rejected() {
    let input = format!("PUSH|{AUTH}|dev1|>xABC");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_empty_string_value_rejected() {
    let input = format!("PUSH|{AUTH}|dev1|[status=]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_invalid_boolean_rejected() {
    let input = format!("PUSH|{AUTH}|dev1|[active?=yes]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_invalid_number_leading_zero_rejected() {
    let input = format!("PUSH|{AUTH}|dev1|[temp:=032]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_empty_metadata_rejected() {
    let input = format!("PUSH|{AUTH}|dev1|[temp:=32{{}}]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_nul_byte_rejected() {
    let mut input = format!("PUSH|{AUTH}|dev1|[temp:=32]");
    unsafe {
        input.as_bytes_mut()[10] = 0;
    }
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn push_trailing_newline_accepted() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32]\n");
    let frame = parse_uplink(&input).unwrap();
    assert_eq!(frame.method, Method::Push);
}

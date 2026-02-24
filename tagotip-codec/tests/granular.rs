use tagotip_codec::build::{build_metadata, build_pull_body, build_push_body, build_variable};
use tagotip_codec::parse::{
    ParsedVariable, extract_serial, parse_metadata, parse_method, parse_pull_body, parse_push_body,
    parse_seq, parse_variable, validate_auth,
};
use tagotip_codec::types::*;

// =========================================================================
// Standalone parse tests
// =========================================================================

#[test]
fn parse_method_push() {
    assert_eq!(parse_method("PUSH").unwrap(), Method::Push);
}

#[test]
fn parse_method_pull() {
    assert_eq!(parse_method("PULL").unwrap(), Method::Pull);
}

#[test]
fn parse_method_ping() {
    assert_eq!(parse_method("PING").unwrap(), Method::Ping);
}

#[test]
fn parse_method_invalid() {
    assert!(parse_method("INVALID").is_err());
}

#[test]
fn validate_auth_valid() {
    assert!(validate_auth("4deedd7bab8817ec").is_ok());
}

#[test]
fn validate_auth_uppercase() {
    assert!(validate_auth("4DEEDD7BAB8817EC").is_ok());
}

#[test]
fn validate_auth_too_short() {
    assert!(validate_auth("4deedd7bab8817e").is_err());
}

#[test]
fn validate_auth_too_long() {
    assert!(validate_auth("4deedd7bab8817ec0").is_err());
}

#[test]
fn validate_auth_non_hex() {
    assert!(validate_auth("4deedd7bab8817gz").is_err());
}

#[test]
fn parse_seq_valid() {
    assert_eq!(parse_seq("!42").unwrap(), 42);
}

#[test]
fn parse_seq_zero() {
    assert_eq!(parse_seq("!0").unwrap(), 0);
}

#[test]
fn parse_seq_missing_bang() {
    assert!(parse_seq("42").is_err());
}

#[test]
fn parse_seq_leading_zero() {
    assert!(parse_seq("!042").is_err());
}

#[test]
fn extract_serial_valid() {
    assert_eq!(extract_serial("sensor_01").unwrap(), "sensor_01");
}

#[test]
fn extract_serial_with_hyphens() {
    assert_eq!(extract_serial("my-device").unwrap(), "my-device");
}

#[test]
fn extract_serial_invalid_chars() {
    assert!(extract_serial("sensor.01").is_err());
}

#[test]
fn parse_variable_number() {
    let parsed = parse_variable("temperature:=32.5").unwrap();
    assert_eq!(parsed.variable.name, "temperature");
    assert_eq!(parsed.variable.operator, Operator::Number);
    assert_eq!(parsed.variable.value, Value::Number("32.5"));
}

#[test]
fn parse_variable_string() {
    let parsed = parse_variable("status=online").unwrap();
    assert_eq!(parsed.variable.name, "status");
    assert_eq!(parsed.variable.operator, Operator::String);
    assert_eq!(parsed.variable.value, Value::String("online"));
}

#[test]
fn parse_variable_boolean() {
    let parsed = parse_variable("active?=true").unwrap();
    assert_eq!(parsed.variable.name, "active");
    assert_eq!(parsed.variable.operator, Operator::Boolean);
    assert_eq!(parsed.variable.value, Value::Boolean(true));
}

#[test]
fn parse_variable_location() {
    let parsed = parse_variable("pos@=39.74,-104.99,305").unwrap();
    assert_eq!(parsed.variable.name, "pos");
    assert_eq!(parsed.variable.operator, Operator::Location);
    assert_eq!(
        parsed.variable.value,
        Value::Location {
            lat: "39.74",
            lng: "-104.99",
            alt: Some("305"),
        }
    );
}

#[test]
fn parse_variable_with_unit() {
    let parsed = parse_variable("temperature:=32.5#C").unwrap();
    assert_eq!(parsed.variable.unit, Some("C"));
}

#[test]
fn parse_variable_with_timestamp() {
    let parsed = parse_variable("temp:=32@1694567890000").unwrap();
    assert_eq!(parsed.variable.timestamp, Some("1694567890000"));
}

#[test]
fn parse_variable_with_group() {
    let parsed = parse_variable("temp:=32^batch_01").unwrap();
    assert_eq!(parsed.variable.group, Some("batch_01"));
}

#[test]
fn parse_variable_with_metadata() {
    let parsed = parse_variable("temp:=32{source=dht22,quality=high}").unwrap();
    let meta = parsed.meta_pairs.unwrap();
    assert_eq!(meta.len(), 2);
    assert_eq!(meta[0].key, "source");
    assert_eq!(meta[0].value, "dht22");
    assert_eq!(meta[1].key, "quality");
    assert_eq!(meta[1].value, "high");
}

#[test]
fn parse_metadata_single_pair() {
    let block = parse_metadata("key=value").unwrap();
    assert_eq!(block.len(), 1);
    assert_eq!(block[0].key, "key");
    assert_eq!(block[0].value, "value");
}

#[test]
fn parse_metadata_multiple_pairs() {
    let block = parse_metadata("a=1,b=2,c=3").unwrap();
    assert_eq!(block.len(), 3);
    assert_eq!(block[0].key, "a");
    assert_eq!(block[2].key, "c");
}

#[test]
fn parse_metadata_empty_rejected() {
    assert!(parse_metadata("").is_err());
}

#[test]
fn parse_push_body_structured() {
    let body = parse_push_body("[temperature:=32;humidity:=65]").unwrap();
    match body {
        PushBody::Structured(s) => {
            assert_eq!(s.variables.len(), 2);
            assert_eq!(s.variables[0].name, "temperature");
            assert_eq!(s.variables[1].name, "humidity");
        }
        _ => panic!("expected structured body"),
    }
}

#[test]
fn parse_push_body_passthrough_hex() {
    let body = parse_push_body(">xdeadbeef").unwrap();
    match body {
        PushBody::Passthrough(pt) => {
            assert_eq!(pt.encoding, PassthroughEncoding::Hex);
            assert_eq!(pt.data, "deadbeef");
        }
        _ => panic!("expected passthrough body"),
    }
}

#[test]
fn parse_push_body_with_modifiers() {
    let body = parse_push_body("@1694567890000^batch_01{fw=2.1}[temp:=32]").unwrap();
    match body {
        PushBody::Structured(s) => {
            assert_eq!(s.group, Some("batch_01"));
            assert_eq!(s.timestamp, Some("1694567890000"));
            assert!(s.body_meta.is_some());
            assert_eq!(s.variables.len(), 1);
        }
        _ => panic!("expected structured body"),
    }
}

#[test]
fn parse_pull_body_single() {
    let body = parse_pull_body("[temperature]").unwrap();
    assert_eq!(body.variables.len(), 1);
    assert_eq!(body.variables[0], "temperature");
}

#[test]
fn parse_pull_body_multiple() {
    let body = parse_pull_body("[temp;humidity;pressure]").unwrap();
    assert_eq!(body.variables.len(), 3);
}

// =========================================================================
// Standalone build tests
// =========================================================================

#[test]
fn build_variable_number() {
    let var = Variable {
        name: "temperature",
        operator: Operator::Number,
        value: Value::Number("32"),
        unit: None,
        timestamp: None,
        group: None,
        meta: None,
    };
    let mut buf = [0u8; 256];
    let n = build_variable(&var, &[], &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, "temperature:=32");
}

#[test]
fn build_variable_with_unit() {
    let var = Variable {
        name: "temperature",
        operator: Operator::Number,
        value: Value::Number("32"),
        unit: Some("C"),
        timestamp: None,
        group: None,
        meta: None,
    };
    let mut buf = [0u8; 256];
    let n = build_variable(&var, &[], &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, "temperature:=32#C");
}

#[test]
fn build_variable_with_metadata() {
    let meta_pool = [
        MetaPair {
            key: "source",
            value: "dht22",
        },
        MetaPair {
            key: "quality",
            value: "high",
        },
    ];
    let var = Variable {
        name: "temp",
        operator: Operator::Number,
        value: Value::Number("32"),
        unit: None,
        timestamp: None,
        group: None,
        meta: Some(MetaRange { start: 0, len: 2 }),
    };
    let mut buf = [0u8; 256];
    let n = build_variable(&var, &meta_pool, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, "temp:=32{source=dht22,quality=high}");
}

#[test]
fn build_metadata_pairs() {
    let pairs = [
        MetaPair {
            key: "fw",
            value: "2.1",
        },
        MetaPair {
            key: "hw",
            value: "1.0",
        },
    ];
    let mut buf = [0u8; 256];
    let n = build_metadata(&pairs, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, "{fw=2.1,hw=1.0}");
}

#[test]
fn build_push_body_structured() {
    let mut variables = tagotip_codec::inline_vec::InlineVec::new();
    let _ = variables.push(Variable {
        name: "temp",
        operator: Operator::Number,
        value: Value::Number("32"),
        unit: None,
        timestamp: None,
        group: None,
        meta: None,
    });
    let body = PushBody::Structured(StructuredBody {
        group: None,
        timestamp: None,
        body_meta: None,
        variables,
        meta_pool: tagotip_codec::inline_vec::InlineVec::new(),
    });
    let mut buf = [0u8; 256];
    let n = build_push_body(&body, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, "[temp:=32]");
}

#[test]
fn build_pull_body_multiple() {
    let mut variables = tagotip_codec::inline_vec::InlineVec::new();
    let _ = variables.push("temp");
    let _ = variables.push("humidity");
    let body = PullBody { variables };
    let mut buf = [0u8; 256];
    let n = build_pull_body(&body, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, "[temp;humidity]");
}

// =========================================================================
// Roundtrip tests: parse standalone then build standalone
// =========================================================================

#[test]
fn roundtrip_push_body() {
    let input = "[temperature:=32;humidity:=65]";
    let parsed = parse_push_body(input).unwrap();
    let mut buf = [0u8; 512];
    let n = build_push_body(&parsed, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, input);
}

#[test]
fn roundtrip_pull_body() {
    let input = "[temp;humidity;pressure]";
    let parsed = parse_pull_body(input).unwrap();
    let mut buf = [0u8; 256];
    let n = build_pull_body(&parsed, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, input);
}

#[test]
fn roundtrip_push_body_with_modifiers() {
    let input = "@1694567890000^batch_01{fw=2.1}[temp:=32#C;humidity:=65#%]";
    let parsed = parse_push_body(input).unwrap();
    let mut buf = [0u8; 512];
    let n = build_push_body(&parsed, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, input);
}

#[test]
fn roundtrip_variable() {
    let input = "temperature:=32.5#C@1694567890000^batch_01";
    let ParsedVariable {
        variable: var,
        meta_pairs: _,
    } = parse_variable(input).unwrap();
    let mut buf = [0u8; 256];
    let n = build_variable(&var, &[], &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, input);
}

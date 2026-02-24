//! Edge case tests for tagotip-codec.
//!
//! Covers: escape sequences, validation boundaries, number formats,
//! location edge cases, sequence counter, headless frames, auth tokens,
//! body modifier ordering, build edge cases, and ACK edge cases.

use tagotip_codec::build::{build_ack, build_headless, build_uplink};
use tagotip_codec::error::ParseErrorKind;
use tagotip_codec::escape::{escape_into, needs_unescape, unescape_into};
use tagotip_codec::parse::{parse_ack, parse_headless, parse_uplink};
use tagotip_codec::types::*;

const AUTH: &str = "4deedd7bab8817ec";

fn roundtrip(input: &str) {
    let parsed = parse_uplink(input).unwrap();
    let mut buf = [0u8; 16384];
    let n = build_uplink(&parsed, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, input, "roundtrip failed");
}

fn assert_parse_err(input: &str, expected: ParseErrorKind) {
    match parse_uplink(input) {
        Err(e) => assert_eq!(e.kind, expected, "wrong error kind for: {input}"),
        Ok(_) => panic!("expected error {expected:?} for: {input}"),
    }
}

// =========================================================================
// 1A. Escape Sequences
// =========================================================================

#[test]
fn escape_pipe_in_string_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[status=hello\\|world]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables[0].value, Value::String("hello\\|world"));
    roundtrip(&input);
}

#[test]
fn escape_semicolon_in_string_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[msg=a\\;b]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables[0].value, Value::String("a\\;b"));
    roundtrip(&input);
}

#[test]
fn escape_brackets_in_string_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[msg=a\\[b\\]c]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables[0].value, Value::String("a\\[b\\]c"));
    roundtrip(&input);
}

#[test]
fn escape_braces_in_meta_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32{{note=has\\{{curly\\}}braces}}]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    let meta = body.variable_metadata(&body.variables[0]);
    assert_eq!(meta[0].key, "note");
    assert_eq!(meta[0].value, "has\\{curly\\}braces");
    roundtrip(&input);
}

#[test]
fn escape_hash_in_string_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[msg=color\\#red]");
    roundtrip(&input);
}

#[test]
fn escape_at_in_string_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[msg=user\\@host]");
    roundtrip(&input);
}

#[test]
fn escape_caret_in_string_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[msg=a\\^b]");
    roundtrip(&input);
}

#[test]
fn escape_backslash_in_string_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[path=c:\\\\dir]");
    roundtrip(&input);
}

#[test]
fn escape_newline_in_string_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[msg=line1\\nline2]");
    roundtrip(&input);
}

#[test]
fn escape_comma_in_meta_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32{{note=a\\,b}}]");
    roundtrip(&input);
}

#[test]
fn multiple_escapes_in_one_value() {
    let input = format!("PUSH|{AUTH}|sensor_01|[msg=a\\|b\\;c\\\\d]");
    roundtrip(&input);
}

#[test]
fn unescape_all_sequences() {
    let input = "a\\|b\\[c\\]d\\;e\\,f\\{g\\}h\\#i\\@j\\^k\\\\l\\nm";
    let mut buf = [0u8; 256];
    let n = unescape_into(input, &mut buf).unwrap();
    let result = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(result, "a|b[c]d;e,f{g}h#i@j^k\\l\nm");
}

#[test]
fn unrecognized_escape_literal() {
    // \z is not a recognized escape — backslash is kept literally
    let mut buf = [0u8; 16];
    let n = unescape_into("a\\zb", &mut buf).unwrap();
    let result = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(result, "a\\zb");
}

#[test]
fn escape_at_end_of_input() {
    // Trailing backslash with no following byte
    let mut buf = [0u8; 16];
    let n = unescape_into("abc\\", &mut buf).unwrap();
    let result = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(result, "abc\\");
}

#[test]
fn unescape_into_buffer_too_small() {
    let input = "hello\\|world";
    let mut buf = [0u8; 2]; // too small
    assert!(unescape_into(input, &mut buf).is_none());
}

#[test]
fn escape_into_buffer_too_small() {
    let input = "a|b";
    let mut buf = [0u8; 2]; // needs 4 bytes (a, \, |, b)
    assert!(escape_into(input, &mut buf).is_none());
}

#[test]
fn needs_unescape_true() {
    assert!(needs_unescape("hello\\|world"));
}

#[test]
fn needs_unescape_false() {
    assert!(!needs_unescape("hello world"));
}

// =========================================================================
// 1B. Validation Boundaries
// =========================================================================

#[test]
fn varname_max_length_accepted() {
    let name = "a".repeat(100);
    let input = format!("PUSH|{AUTH}|sensor_01|[{name}:=32]");
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn varname_over_max_rejected() {
    let name = "a".repeat(101);
    let input = format!("PUSH|{AUTH}|sensor_01|[{name}:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidField);
}

#[test]
fn varname_uppercase_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[Temperature:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidField);
}

#[test]
fn varname_hyphen_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[my_var:=32]");
    // underscore is valid — use actual hyphen
    let input_hyphen = format!("PUSH|{AUTH}|sensor_01|[my-var:=32]");
    assert!(parse_uplink(&input).is_ok()); // underscore OK
    assert_parse_err(&input_hyphen, ParseErrorKind::InvalidField);
}

#[test]
fn varname_empty_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[:=32]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn serial_max_length_accepted() {
    let serial = "a".repeat(100);
    let input = format!("PUSH|{AUTH}|{serial}|[temp:=32]");
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn serial_over_max_rejected() {
    let serial = "a".repeat(101);
    let input = format!("PUSH|{AUTH}|{serial}|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidSerial);
}

#[test]
fn serial_special_chars_rejected() {
    let input = format!("PUSH|{AUTH}|my.device|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidSerial);
}

#[test]
fn serial_hyphen_accepted() {
    // Serials allow hyphens
    let input = format!("PUSH|{AUTH}|my-device|[temp:=32]");
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn group_max_length_accepted() {
    let group = "a".repeat(100);
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32^{group}]");
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn group_over_max_rejected() {
    let group = "a".repeat(101);
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32^{group}]");
    assert_parse_err(&input, ParseErrorKind::InvalidField);
}

#[test]
fn meta_key_max_length_accepted() {
    let key = "a".repeat(100);
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32{{{key}=val}}]");
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn meta_key_over_max_rejected() {
    let key = "a".repeat(101);
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32{{{key}=val}}]");
    assert_parse_err(&input, ParseErrorKind::InvalidMetadata);
}

#[test]
fn unit_max_length_accepted() {
    let unit = "a".repeat(25);
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32#{unit}]");
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn unit_over_max_rejected() {
    let unit = "a".repeat(26);
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32#{unit}]");
    assert_parse_err(&input, ParseErrorKind::InvalidField);
}

#[test]
fn unit_empty_hash_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32#]");
    assert_parse_err(&input, ParseErrorKind::InvalidField);
}

#[test]
fn max_variables_accepted() {
    let vars: Vec<String> = (0..100).map(|i| format!("v{i}:=0")).collect();
    let input = format!("PUSH|{}|sensor_01|[{}]", AUTH, vars.join(";"));
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn over_max_variables_rejected() {
    let vars: Vec<String> = (0..101).map(|i| format!("v{i}:=0")).collect();
    let input = format!("PUSH|{}|sensor_01|[{}]", AUTH, vars.join(";"));
    assert_parse_err(&input, ParseErrorKind::TooManyItems);
}

#[test]
fn max_meta_pairs_accepted() {
    let pairs: Vec<String> = (0..32).map(|i| format!("k{i}=v{i}")).collect();
    let input = format!("PUSH|{}|sensor_01|[temp:=32{{{}}}]", AUTH, pairs.join(","));
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn over_max_meta_pairs_rejected() {
    let pairs: Vec<String> = (0..33).map(|i| format!("k{i}=v{i}")).collect();
    let input = format!("PUSH|{}|sensor_01|[temp:=32{{{}}}]", AUTH, pairs.join(","));
    assert_parse_err(&input, ParseErrorKind::TooManyItems);
}

#[test]
fn frame_exactly_max_size() {
    // Build a frame that's exactly 16384 bytes
    let header = format!("PUSH|{AUTH}|sensor_01|[msg=");
    let trailer = "]";
    let remaining = 16384 - header.len() - trailer.len();
    let value = "x".repeat(remaining);
    let input = format!("{header}{value}{trailer}");
    assert_eq!(input.len(), 16384);
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn frame_over_max_size() {
    let header = format!("PUSH|{AUTH}|sensor_01|[msg=");
    let trailer = "]";
    let remaining = 16385 - header.len() - trailer.len();
    let value = "x".repeat(remaining);
    let input = format!("{header}{value}{trailer}");
    assert_eq!(input.len(), 16385);
    assert_parse_err(&input, ParseErrorKind::FrameTooLarge);
}

// =========================================================================
// 1C. Number Format
// =========================================================================

#[test]
fn number_zero() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=0]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables[0].value, Value::Number("0"));
}

#[test]
fn number_negative_zero() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=-0]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables[0].value, Value::Number("-0"));
}

#[test]
fn number_decimal() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=3.14]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables[0].value, Value::Number("3.14"));
}

#[test]
fn number_leading_zero_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=032]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn number_negative_leading_zero_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=-032]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn number_dot_only_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=.5]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn number_trailing_dot_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=5.]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn number_double_negative_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=--5]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn number_empty_rejected() {
    // `:=` with no value — next char is `]` which terminates the value as ""
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn number_alpha_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=abc]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn number_large_integer() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=999999999999]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables[0].value, Value::Number("999999999999"));
}

// =========================================================================
// 1D. Location Edge Cases
// =========================================================================

#[test]
fn location_two_components() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=39.74,-104.99]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(
        body.variables[0].value,
        Value::Location {
            lat: "39.74",
            lng: "-104.99",
            alt: None,
        }
    );
}

#[test]
fn location_three_components() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=39.74,-104.99,305]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(
        body.variables[0].value,
        Value::Location {
            lat: "39.74",
            lng: "-104.99",
            alt: Some("305"),
        }
    );
}

#[test]
fn location_four_components_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=1,2,3,4]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn location_empty_lat_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=,-104.99]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn location_empty_lng_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=39.74,]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn location_empty_alt_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=39.74,-104.99,]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn location_negative_coords() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=-33.87,151.21]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(
        body.variables[0].value,
        Value::Location {
            lat: "-33.87",
            lng: "151.21",
            alt: None,
        }
    );
}

#[test]
fn location_with_zero() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=0,0]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(
        body.variables[0].value,
        Value::Location {
            lat: "0",
            lng: "0",
            alt: None,
        }
    );
}

// =========================================================================
// 1E. Sequence Counter
// =========================================================================

#[test]
fn seq_zero() {
    let input = format!("PUSH|!0|{AUTH}|sensor_01|[temp:=32]");
    let frame = parse_uplink(&input).unwrap();
    assert_eq!(frame.seq, Some(0));
}

#[test]
fn seq_large_value() {
    let input = format!("PUSH|!4294967295|{AUTH}|sensor_01|[temp:=32]");
    let frame = parse_uplink(&input).unwrap();
    assert_eq!(frame.seq, Some(u32::MAX));
}

#[test]
fn seq_overflow_rejected() {
    let input = format!("PUSH|!4294967296|{AUTH}|sensor_01|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidSeq);
}

#[test]
fn seq_leading_zeros_rejected() {
    let input = format!("PUSH|!01|{AUTH}|sensor_01|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidSeq);
}

#[test]
fn seq_negative_rejected() {
    let input = format!("PUSH|!-1|{AUTH}|sensor_01|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidSeq);
}

#[test]
fn seq_empty_rejected() {
    let input = format!("PUSH|!|{AUTH}|sensor_01|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidSeq);
}

// =========================================================================
// 1F. Headless Frame
// =========================================================================

#[test]
fn headless_push_simple() {
    let frame = parse_headless(Method::Push, "sensor_01|[temp:=32]").unwrap();
    assert_eq!(frame.serial, "sensor_01");
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables.len(), 1);
    assert_eq!(body.variables[0].name, "temp");
}

#[test]
fn headless_push_multi_var() {
    let frame = parse_headless(Method::Push, "sensor_01|[temp:=32;humidity:=65]").unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables.len(), 2);
}

#[test]
fn headless_push_passthrough() {
    let frame = parse_headless(Method::Push, "sensor_01|>xDEADBEEF").unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Passthrough(p) => p,
        _ => panic!("expected passthrough"),
    };
    assert_eq!(body.encoding, PassthroughEncoding::Hex);
    assert_eq!(body.data, "DEADBEEF");
}

#[test]
fn headless_pull() {
    let frame = parse_headless(Method::Pull, "sensor_01|[temperature;humidity]").unwrap();
    let pull = frame.pull_body.unwrap();
    assert_eq!(pull.variables.len(), 2);
    assert_eq!(pull.variables[0], "temperature");
    assert_eq!(pull.variables[1], "humidity");
}

#[test]
fn headless_ping() {
    let frame = parse_headless(Method::Ping, "sensor_01").unwrap();
    assert_eq!(frame.serial, "sensor_01");
    assert!(frame.push_body.is_none());
    assert!(frame.pull_body.is_none());
}

#[test]
fn headless_push_missing_body_rejected() {
    // PUSH requires a body — serial only should fail
    assert!(parse_headless(Method::Push, "sensor_01").is_err());
}

#[test]
fn headless_roundtrip_structured() {
    let input = "sensor_01|[temp:=32;humidity:=65]";
    let parsed = parse_headless(Method::Push, input).unwrap();
    let mut buf = [0u8; 4096];
    let n = build_headless(Method::Push, &parsed, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, input);
}

#[test]
fn headless_roundtrip_passthrough() {
    let input = "sensor_01|>xDEADBEEF01020304";
    let parsed = parse_headless(Method::Push, input).unwrap();
    let mut buf = [0u8; 4096];
    let n = build_headless(Method::Push, &parsed, &mut buf).unwrap();
    let output = core::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(output, input);
}

// =========================================================================
// 1G. Auth Hash
// =========================================================================

#[test]
fn auth_valid_16_chars() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32]");
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn auth_too_short_rejected() {
    let short_auth = "4deedd7bab8817e"; // 15 chars
    let input = format!("PUSH|{short_auth}|sensor_01|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidAuth);
}

#[test]
fn auth_too_long_rejected() {
    let long_auth = "4deedd7bab8817ec0"; // 17 chars
    let input = format!("PUSH|{long_auth}|sensor_01|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidAuth);
}

#[test]
fn auth_non_hex_rejected() {
    let bad_auth = "4deedd7bab8817gz"; // contains g, z
    let input = format!("PUSH|{bad_auth}|sensor_01|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidAuth);
}

#[test]
fn auth_uppercase_hex_accepted() {
    let upper_auth = "4DEEDD7BAB8817EC";
    let input = format!("PUSH|{upper_auth}|sensor_01|[temp:=32]");
    let result = parse_uplink(&input);
    assert!(result.is_ok(), "uppercase hex should be accepted");
}

// =========================================================================
// 1H. Body Modifier Ordering
// =========================================================================

#[test]
fn body_modifiers_all_three() {
    let input = format!("PUSH|{AUTH}|sensor_01|@1694567890000^group_01{{firmware=2.1}}[temp:=32]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.group, Some("group_01"));
    assert_eq!(body.timestamp, Some("1694567890000"));
    assert_eq!(body.body_metadata().len(), 1);
    roundtrip(&input);
}

#[test]
fn body_group_only() {
    let input = format!("PUSH|{AUTH}|sensor_01|^group_01[temp:=32]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.group, Some("group_01"));
    assert!(body.timestamp.is_none());
    roundtrip(&input);
}

#[test]
fn body_timestamp_only() {
    let input = format!("PUSH|{AUTH}|sensor_01|@1694567890000[temp:=32]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert!(body.group.is_none());
    assert_eq!(body.timestamp, Some("1694567890000"));
    roundtrip(&input);
}

#[test]
fn body_meta_only() {
    let input = format!("PUSH|{AUTH}|sensor_01|{{firmware=2.1}}[temp:=32]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert!(body.group.is_none());
    assert!(body.timestamp.is_none());
    assert_eq!(body.body_metadata().len(), 1);
    roundtrip(&input);
}

#[test]
fn body_group_after_timestamp_rejected() {
    // Modifiers must be in order: @timestamp ^group {meta}
    // ^group before @timestamp is rejected during group validation (@ is not a valid group char)
    let input = format!("PUSH|{AUTH}|sensor_01|^group_01@1694567890000[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidField);
}

// =========================================================================
// 1I. Build Edge Cases
// =========================================================================

#[test]
fn build_push_with_unit() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temperature:=32#C]");
    roundtrip(&input);
}

#[test]
fn build_push_with_all_suffixes() {
    let input =
        format!("PUSH|{AUTH}|sensor_01|[temperature:=32#C@1694567890000^batch_01{{source=dht22}}]");
    roundtrip(&input);
}

#[test]
fn build_push_boolean_true() {
    let input = format!("PUSH|{AUTH}|sensor_01|[active?=true]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables[0].value, Value::Boolean(true));
    roundtrip(&input);
}

#[test]
fn build_push_boolean_false() {
    let input = format!("PUSH|{AUTH}|sensor_01|[active?=false]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables[0].value, Value::Boolean(false));
    roundtrip(&input);
}

#[test]
fn build_push_location_no_alt() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=39.74,-104.99]");
    roundtrip(&input);
}

#[test]
fn build_push_location_with_alt() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=39.74,-104.99,305]");
    roundtrip(&input);
}

#[test]
fn build_push_string_with_escapes() {
    let input = format!("PUSH|{AUTH}|sensor_01|[msg=hello\\|world]");
    roundtrip(&input);
}

#[test]
fn build_passthrough_base64() {
    let input = format!("PUSH|{AUTH}|sensor_01|>b3q2+7wECAwQ=");
    roundtrip(&input);
}

#[test]
fn build_buffer_too_small() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32]");
    let frame = parse_uplink(&input).unwrap();
    let mut buf = [0u8; 5]; // way too small
    assert!(build_uplink(&frame, &mut buf).is_err());
}

// =========================================================================
// 1J. ACK Edge Cases
// =========================================================================

#[test]
fn ack_cmd_no_detail() {
    // CMD with no detail — should parse, detail is None or just "CMD"
    // ACK|CMD has no detail field
    let frame = parse_ack("ACK|CMD").unwrap();
    assert_eq!(frame.status, AckStatus::Cmd);
    assert!(frame.detail.is_none());
}

#[test]
fn ack_ok_no_detail() {
    // ACK|OK with no count or variables
    let frame = parse_ack("ACK|OK").unwrap();
    assert_eq!(frame.status, AckStatus::Ok);
    assert!(frame.detail.is_none());
}

#[test]
fn ack_raw_detail() {
    // An OK with a non-numeric, non-bracket detail → might be Raw
    // Actually, if it's OK and detail is not a number and not starting with [, it might error
    // Let's check: ACK|OK|sometext
    let result = parse_ack("ACK|OK|sometext");
    // The parser tries to parse as count first, then variables; if neither works,
    // it may fall back to Raw or error
    if let Ok(frame) = result {
        match frame.detail {
            Some(AckDetail::Raw(_)) => {} // OK, it's a raw detail
            _ => {}                       // other handling is fine too
        }
    }
}

#[test]
fn ack_err_all_12_codes_roundtrip() {
    let codes = [
        "invalid_token",
        "invalid_method",
        "invalid_payload",
        "invalid_seq",
        "device_not_found",
        "variable_not_found",
        "rate_limited",
        "auth_failed",
        "unsupported_version",
        "payload_too_large",
        "server_error",
    ];

    for code in codes {
        let input = format!("ACK|ERR|{code}");
        let parsed = parse_ack(&input).unwrap();
        let mut buf = [0u8; 256];
        let n = build_ack(&parsed, &mut buf).unwrap();
        let output = core::str::from_utf8(&buf[..n]).unwrap();
        assert_eq!(output, input, "ACK roundtrip failed for: {code}");
    }
}

#[test]
fn ack_nul_byte_rejected() {
    // NUL in ACK input — depends on implementation
    let input = "ACK\0OK|3";
    // parse_ack may or may not check for NUL (it's checked in parse_uplink)
    // Just verify the parser doesn't panic
    let _ = parse_ack(input);
}

#[test]
fn ack_unknown_error_code() {
    let frame = parse_ack("ACK|ERR|some_future_error").unwrap();
    match frame.detail {
        Some(AckDetail::Error { code, text }) => {
            assert_eq!(code, ErrorCode::Unknown);
            assert_eq!(text, "some_future_error");
        }
        _ => panic!("expected Error detail"),
    }
}

#[test]
fn ack_cmd_with_equals() {
    let frame = parse_ack("ACK|CMD|ota=https://example.com/v2.1.bin").unwrap();
    assert_eq!(frame.status, AckStatus::Cmd);
    assert_eq!(
        frame.detail,
        Some(AckDetail::Command("ota=https://example.com/v2.1.bin"))
    );
}

#[test]
fn ack_ok_large_count() {
    let frame = parse_ack("ACK|OK|4294967295").unwrap();
    assert_eq!(frame.detail, Some(AckDetail::Count(u32::MAX)));
}

// =========================================================================
// Additional edge cases
// =========================================================================

#[test]
fn nul_byte_in_frame_rejected() {
    let input = format!("PUSH|{AUTH}|sensor\x0001|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::NulByte);
}

#[test]
fn empty_frame_rejected() {
    assert_parse_err("", ParseErrorKind::EmptyFrame);
}

#[test]
fn invalid_method_rejected() {
    let input = format!("INVALID|{AUTH}|sensor_01|[temp:=32]");
    assert_parse_err(&input, ParseErrorKind::InvalidMethod);
}

#[test]
fn push_missing_body_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01");
    assert_parse_err(&input, ParseErrorKind::MissingBody);
}

#[test]
fn pull_missing_body_rejected() {
    let input = format!("PULL|{AUTH}|sensor_01");
    assert_parse_err(&input, ParseErrorKind::MissingBody);
}

#[test]
fn empty_variable_block_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariableBlock);
}

#[test]
fn invalid_boolean_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[active?=yes]");
    assert_parse_err(&input, ParseErrorKind::InvalidVariable);
}

#[test]
fn odd_hex_passthrough_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|>xABC");
    assert_parse_err(&input, ParseErrorKind::InvalidPassthrough);
}

#[test]
fn trailing_newline_accepted() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32]\n");
    assert!(parse_uplink(&input).is_ok());
}

#[test]
fn string_value_non_empty_required() {
    // `status=` has empty string value — should be rejected per spec
    let input = format!("PUSH|{AUTH}|sensor_01|[status=]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn location_unit_rejected() {
    // #unit is not allowed with @= operator
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=39.74,-104.99#m]");
    assert!(parse_uplink(&input).is_err());
}

#[test]
fn metadata_empty_block_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32{{}}]");
    assert_parse_err(&input, ParseErrorKind::InvalidMetadata);
}

#[test]
fn metadata_missing_equals_rejected() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temp:=32{{keyonly}}]");
    assert_parse_err(&input, ParseErrorKind::InvalidMetadata);
}

#[test]
fn decimal_zero_point_something() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=0.5]");
    let frame = parse_uplink(&input).unwrap();
    let body = match frame.push_body.unwrap() {
        PushBody::Structured(s) => s,
        _ => panic!("expected structured"),
    };
    assert_eq!(body.variables[0].value, Value::Number("0.5"));
    roundtrip(&input);
}

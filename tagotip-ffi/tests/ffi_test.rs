//! FFI integration tests.
//!
//! Tests the C FFI functions by calling them from Rust.
//! No C compiler needed — same-binary calls.

use std::mem::MaybeUninit;

use tagotip_ffi::*;

const AUTH: &str = "4deedd7bab8817ec";

/// Helper: parse an uplink frame via FFI, returning the result code and the frame.
unsafe fn ffi_parse_uplink_helper(input: &str) -> (i32, TagotipUplinkFrame) {
    let mut frame = MaybeUninit::<TagotipUplinkFrame>::zeroed();
    let rc = unsafe { tagotip_parse_uplink(input.as_ptr(), input.len(), frame.as_mut_ptr()) };
    (rc, unsafe { frame.assume_init() })
}

/// Helper: parse an ACK frame via FFI.
unsafe fn ffi_parse_ack_helper(input: &str) -> (i32, TagotipAckFrame) {
    let mut frame = MaybeUninit::<TagotipAckFrame>::zeroed();
    let rc = unsafe { tagotip_parse_ack(input.as_ptr(), input.len(), frame.as_mut_ptr()) };
    (rc, unsafe { frame.assume_init() })
}

/// Helper: extract a &str from a `TagotipStr`.
unsafe fn str_from_tagotip(s: &TagotipStr) -> &str {
    if s.ptr.is_null() || s.len == 0 {
        ""
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
        std::str::from_utf8(bytes).unwrap()
    }
}

// =========================================================================
// 3A. Parse Uplink via FFI
// =========================================================================

#[test]
fn ffi_parse_uplink_simple_push() {
    let input = format!("PUSH|{AUTH}|sensor_01|[temperature:=32;humidity:=65]");
    let (rc, frame) = unsafe { ffi_parse_uplink_helper(&input) };
    assert_eq!(rc, TAGOTIP_OK);
    assert!(matches!(frame.method, TagotipMethod::Push));
    assert_eq!(frame.has_seq, 0);
    assert_eq!(unsafe { str_from_tagotip(&frame.serial) }, "sensor_01");
    assert!(matches!(
        frame.push_body_tag,
        TagotipPushBodyTag::Structured
    ));
    assert_eq!(frame.variables_len, 2);
    assert_eq!(
        unsafe { str_from_tagotip(&frame.variables[0].name) },
        "temperature"
    );
    assert_eq!(
        unsafe { str_from_tagotip(&frame.variables[1].name) },
        "humidity"
    );
}

#[test]
fn ffi_parse_uplink_with_seq() {
    let input = format!("PUSH|!42|{AUTH}|sensor_01|[temp:=32]");
    let (rc, frame) = unsafe { ffi_parse_uplink_helper(&input) };
    assert_eq!(rc, TAGOTIP_OK);
    assert_eq!(frame.has_seq, 1);
    assert_eq!(frame.seq, 42);
}

#[test]
fn ffi_parse_uplink_typed_values() {
    let input = format!("PUSH|{AUTH}|sensor_01|[n:=32.5;s=hello;b?=true]");
    let (rc, frame) = unsafe { ffi_parse_uplink_helper(&input) };
    assert_eq!(rc, TAGOTIP_OK);
    assert_eq!(frame.variables_len, 3);

    // Number
    assert!(matches!(
        frame.variables[0].operator,
        TagotipOperator::Number
    ));
    assert!(matches!(
        frame.variables[0].value.tag,
        TagotipValueTag::Number
    ));
    assert_eq!(
        unsafe { str_from_tagotip(&frame.variables[0].value.str_val) },
        "32.5"
    );

    // String
    assert!(matches!(
        frame.variables[1].operator,
        TagotipOperator::String
    ));
    assert!(matches!(
        frame.variables[1].value.tag,
        TagotipValueTag::String
    ));
    assert_eq!(
        unsafe { str_from_tagotip(&frame.variables[1].value.str_val) },
        "hello"
    );

    // Boolean
    assert!(matches!(
        frame.variables[2].operator,
        TagotipOperator::Boolean
    ));
    assert!(matches!(
        frame.variables[2].value.tag,
        TagotipValueTag::Boolean
    ));
    assert_eq!(frame.variables[2].value.bool_val, 1);
}

#[test]
fn ffi_parse_uplink_location() {
    let input = format!("PUSH|{AUTH}|sensor_01|[pos@=39.74,-104.99,305]");
    let (rc, frame) = unsafe { ffi_parse_uplink_helper(&input) };
    assert_eq!(rc, TAGOTIP_OK);
    assert!(matches!(
        frame.variables[0].value.tag,
        TagotipValueTag::Location
    ));
    assert_eq!(
        unsafe { str_from_tagotip(&frame.variables[0].value.lat) },
        "39.74"
    );
    assert_eq!(
        unsafe { str_from_tagotip(&frame.variables[0].value.lng) },
        "-104.99"
    );
    assert_eq!(
        unsafe { str_from_tagotip(&frame.variables[0].value.alt) },
        "305"
    );
}

#[test]
fn ffi_parse_uplink_passthrough() {
    let input = format!("PUSH|{AUTH}|sensor_01|>xDEADBEEF");
    let (rc, frame) = unsafe { ffi_parse_uplink_helper(&input) };
    assert_eq!(rc, TAGOTIP_OK);
    assert!(matches!(
        frame.push_body_tag,
        TagotipPushBodyTag::Passthrough
    ));
    assert!(matches!(
        frame.passthrough.encoding,
        TagotipPassthroughEncoding::Hex
    ));
    assert_eq!(
        unsafe { str_from_tagotip(&frame.passthrough.data) },
        "DEADBEEF"
    );
}

#[test]
fn ffi_parse_uplink_pull() {
    let input = format!("PULL|{AUTH}|sensor_01|[temperature;humidity]");
    let (rc, frame) = unsafe { ffi_parse_uplink_helper(&input) };
    assert_eq!(rc, TAGOTIP_OK);
    assert!(matches!(frame.method, TagotipMethod::Pull));
    assert_eq!(frame.has_pull_body, 1);
    assert_eq!(frame.pull_variables_len, 2);
    assert_eq!(
        unsafe { str_from_tagotip(&frame.pull_variables[0]) },
        "temperature"
    );
    assert_eq!(
        unsafe { str_from_tagotip(&frame.pull_variables[1]) },
        "humidity"
    );
}

#[test]
fn ffi_parse_uplink_ping() {
    let input = format!("PING|{AUTH}|sensor_01");
    let (rc, frame) = unsafe { ffi_parse_uplink_helper(&input) };
    assert_eq!(rc, TAGOTIP_OK);
    assert!(matches!(frame.method, TagotipMethod::Ping));
    assert!(matches!(frame.push_body_tag, TagotipPushBodyTag::None));
    assert_eq!(frame.has_pull_body, 0);
}

#[test]
fn ffi_parse_uplink_error() {
    let input = "INVALID|badauth|serial|[temp:=32]";
    let (rc, _) = unsafe { ffi_parse_uplink_helper(input) };
    assert!(rc < 0, "expected negative error code, got {rc}");
    assert_eq!(rc, TAGOTIP_ERR_INVALID_METHOD);
}

// =========================================================================
// 3B. Parse ACK via FFI
// =========================================================================

#[test]
fn ffi_parse_ack_ok_count() {
    let (rc, frame) = unsafe { ffi_parse_ack_helper("ACK|OK|3") };
    assert_eq!(rc, TAGOTIP_OK);
    assert!(matches!(frame.status, TagotipAckStatus::Ok));
    assert!(matches!(frame.detail.tag, TagotipAckDetailTag::Count));
    assert_eq!(frame.detail.count, 3);
}

#[test]
fn ffi_parse_ack_pong() {
    let (rc, frame) = unsafe { ffi_parse_ack_helper("ACK|PONG") };
    assert_eq!(rc, TAGOTIP_OK);
    assert!(matches!(frame.status, TagotipAckStatus::Pong));
    assert!(matches!(frame.detail.tag, TagotipAckDetailTag::None));
}

#[test]
fn ffi_parse_ack_err() {
    let (rc, frame) = unsafe { ffi_parse_ack_helper("ACK|ERR|invalid_token") };
    assert_eq!(rc, TAGOTIP_OK);
    assert!(matches!(frame.status, TagotipAckStatus::Err));
    assert!(matches!(frame.detail.tag, TagotipAckDetailTag::Error));
    assert!(matches!(
        frame.detail.error_code,
        TagotipErrorCode::InvalidToken
    ));
}

#[test]
fn ffi_parse_ack_cmd() {
    let (rc, frame) = unsafe { ffi_parse_ack_helper("ACK|CMD|reboot") };
    assert_eq!(rc, TAGOTIP_OK);
    assert!(matches!(frame.status, TagotipAckStatus::Cmd));
    assert!(matches!(frame.detail.tag, TagotipAckDetailTag::Command));
    assert_eq!(unsafe { str_from_tagotip(&frame.detail.text) }, "reboot");
}

#[test]
fn ffi_parse_ack_with_seq() {
    let (rc, frame) = unsafe { ffi_parse_ack_helper("ACK|!7|OK|5") };
    assert_eq!(rc, TAGOTIP_OK);
    assert_eq!(frame.has_seq, 1);
    assert_eq!(frame.seq, 7);
    assert!(matches!(frame.status, TagotipAckStatus::Ok));
    assert_eq!(frame.detail.count, 5);
}

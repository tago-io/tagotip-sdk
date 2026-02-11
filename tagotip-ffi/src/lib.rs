//! C ABI bridge for tagotip-codec.
//!
//! Exposes parse/build functions through `extern "C"` so that every language
//! binding (Node, Go, Python, Arduino) can call a single shared implementation.

use std::slice;
use std::str;

use tagotip_codec::consts::MAX_VARIABLES;
use tagotip_codec::types::{
    AckDetail, AckFrame, AckStatus, ErrorCode, MAX_TOTAL_META, Method, Operator,
    PassthroughEncoding, PushBody, UplinkFrame, Value,
};
use tagotip_codec::{ParseError, ParseErrorKind};

// ---------------------------------------------------------------------------
// Error codes (negative = error, 0 = success, positive = bytes written)
// ---------------------------------------------------------------------------

pub const TAGOTIP_OK: i32 = 0;
pub const TAGOTIP_ERR_EMPTY_FRAME: i32 = -1;
pub const TAGOTIP_ERR_NUL_BYTE: i32 = -2;
pub const TAGOTIP_ERR_INVALID_METHOD: i32 = -3;
pub const TAGOTIP_ERR_INVALID_SEQ: i32 = -4;
pub const TAGOTIP_ERR_INVALID_AUTH: i32 = -5;
pub const TAGOTIP_ERR_INVALID_SERIAL: i32 = -6;
pub const TAGOTIP_ERR_MISSING_BODY: i32 = -7;
pub const TAGOTIP_ERR_INVALID_MODIFIER: i32 = -8;
pub const TAGOTIP_ERR_INVALID_VARIABLE_BLOCK: i32 = -9;
pub const TAGOTIP_ERR_INVALID_VARIABLE: i32 = -10;
pub const TAGOTIP_ERR_INVALID_PASSTHROUGH: i32 = -11;
pub const TAGOTIP_ERR_INVALID_METADATA: i32 = -12;
pub const TAGOTIP_ERR_INVALID_FIELD: i32 = -13;
pub const TAGOTIP_ERR_INVALID_ACK: i32 = -14;
pub const TAGOTIP_ERR_TOO_MANY_ITEMS: i32 = -15;
pub const TAGOTIP_ERR_FRAME_TOO_LARGE: i32 = -16;
pub const TAGOTIP_ERR_BUFFER_TOO_SMALL: i32 = -17;
pub const TAGOTIP_ERR_INVALID_INPUT: i32 = -18;

// ---------------------------------------------------------------------------
// C-compatible enums
// ---------------------------------------------------------------------------

#[repr(u8)]
pub enum TagotipMethod {
    Push = 0,
    Pull = 1,
    Ping = 2,
}

#[repr(u8)]
pub enum TagotipOperator {
    Number = 0,
    String = 1,
    Boolean = 2,
    Location = 3,
}

#[repr(u8)]
pub enum TagotipValueTag {
    Number = 0,
    String = 1,
    Boolean = 2,
    Location = 3,
}

#[repr(u8)]
pub enum TagotipAckStatus {
    Ok = 0,
    Pong = 1,
    Cmd = 2,
    Err = 3,
}

#[repr(u8)]
pub enum TagotipAckDetailTag {
    None = 0,
    Count = 1,
    Variables = 2,
    Command = 3,
    Error = 4,
    Raw = 5,
}

#[repr(u8)]
pub enum TagotipErrorCode {
    InvalidToken = 0,
    InvalidMethod = 1,
    InvalidPayload = 2,
    InvalidSeq = 3,
    DeviceNotFound = 4,
    VariableNotFound = 5,
    RateLimited = 6,
    AuthFailed = 7,
    UnsupportedVersion = 8,
    PayloadTooLarge = 9,
    ServerError = 10,
    Unknown = 11,
}

#[repr(u8)]
pub enum TagotipPassthroughEncoding {
    Hex = 0,
    Base64 = 1,
}

#[repr(u8)]
pub enum TagotipPushBodyTag {
    None = 0,
    Structured = 1,
    Passthrough = 2,
}

// ---------------------------------------------------------------------------
// C-compatible structs
// ---------------------------------------------------------------------------

/// A borrowed string slice (pointer + length, NOT null-terminated).
#[repr(C)]
pub struct TagotipStr {
    pub ptr: *const u8,
    pub len: usize,
}

impl TagotipStr {
    fn empty() -> Self {
        Self {
            ptr: std::ptr::null(),
            len: 0,
        }
    }

    fn from_str(s: &str) -> Self {
        Self {
            ptr: s.as_ptr(),
            len: s.len(),
        }
    }

    fn from_option(s: Option<&str>) -> Self {
        match s {
            Some(s) => Self::from_str(s),
            None => Self::empty(),
        }
    }
}

#[repr(C)]
pub struct TagotipMetaPair {
    pub key: TagotipStr,
    pub value: TagotipStr,
}

#[repr(C)]
pub struct TagotipValue {
    pub tag: TagotipValueTag,
    /// For Number/String: the string value. For Boolean: len=1, ptr[0]=0|1.
    /// For Location: unused (use lat/lng/alt fields).
    pub str_val: TagotipStr,
    pub bool_val: u8,
    pub lat: TagotipStr,
    pub lng: TagotipStr,
    pub alt: TagotipStr,
}

#[repr(C)]
pub struct TagotipVariable {
    pub name: TagotipStr,
    pub operator: TagotipOperator,
    pub value: TagotipValue,
    pub unit: TagotipStr,
    pub timestamp: TagotipStr,
    pub group: TagotipStr,
    pub meta_start: u16,
    pub meta_len: u16,
}

#[repr(C)]
pub struct TagotipPassthroughBody {
    pub encoding: TagotipPassthroughEncoding,
    pub data: TagotipStr,
}

/// Flat C representation of a parsed uplink frame.
///
/// Variables and metadata are stored in flat arrays. Variable metadata references
/// ranges in the `meta_pool` array via `meta_start`/`meta_len`.
#[repr(C)]
pub struct TagotipUplinkFrame {
    pub method: TagotipMethod,
    pub has_seq: u8,
    pub seq: u32,
    pub auth: TagotipStr,
    pub serial: TagotipStr,

    // Push body
    pub push_body_tag: TagotipPushBodyTag,

    // Structured push body fields
    pub body_group: TagotipStr,
    pub body_timestamp: TagotipStr,
    pub body_meta_start: u16,
    pub body_meta_len: u16,
    pub variables_len: u16,
    pub variables: [TagotipVariable; MAX_VARIABLES],
    pub meta_pool_len: u16,
    pub meta_pool: [TagotipMetaPair; MAX_TOTAL_META],

    // Passthrough push body fields
    pub passthrough: TagotipPassthroughBody,

    // Pull body
    pub has_pull_body: u8,
    pub pull_variables_len: u16,
    pub pull_variables: [TagotipStr; MAX_VARIABLES],
}

#[repr(C)]
pub struct TagotipAckDetail {
    pub tag: TagotipAckDetailTag,
    pub count: u32,
    pub text: TagotipStr,
    pub error_code: TagotipErrorCode,
}

#[repr(C)]
pub struct TagotipAckFrame {
    pub has_seq: u8,
    pub seq: u32,
    pub status: TagotipAckStatus,
    pub detail: TagotipAckDetail,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn parse_error_to_code(e: &ParseError) -> i32 {
    match e.kind {
        ParseErrorKind::EmptyFrame => TAGOTIP_ERR_EMPTY_FRAME,
        ParseErrorKind::NulByte => TAGOTIP_ERR_NUL_BYTE,
        ParseErrorKind::InvalidMethod => TAGOTIP_ERR_INVALID_METHOD,
        ParseErrorKind::InvalidSeq => TAGOTIP_ERR_INVALID_SEQ,
        ParseErrorKind::InvalidAuth => TAGOTIP_ERR_INVALID_AUTH,
        ParseErrorKind::InvalidSerial => TAGOTIP_ERR_INVALID_SERIAL,
        ParseErrorKind::MissingBody => TAGOTIP_ERR_MISSING_BODY,
        ParseErrorKind::InvalidModifier => TAGOTIP_ERR_INVALID_MODIFIER,
        ParseErrorKind::InvalidVariableBlock => TAGOTIP_ERR_INVALID_VARIABLE_BLOCK,
        ParseErrorKind::InvalidVariable => TAGOTIP_ERR_INVALID_VARIABLE,
        ParseErrorKind::InvalidPassthrough => TAGOTIP_ERR_INVALID_PASSTHROUGH,
        ParseErrorKind::InvalidMetadata => TAGOTIP_ERR_INVALID_METADATA,
        ParseErrorKind::InvalidField => TAGOTIP_ERR_INVALID_FIELD,
        ParseErrorKind::InvalidAck => TAGOTIP_ERR_INVALID_ACK,
        ParseErrorKind::TooManyItems => TAGOTIP_ERR_TOO_MANY_ITEMS,
        ParseErrorKind::FrameTooLarge => TAGOTIP_ERR_FRAME_TOO_LARGE,
    }
}

fn convert_method(m: &Method) -> TagotipMethod {
    match m {
        Method::Push => TagotipMethod::Push,
        Method::Pull => TagotipMethod::Pull,
        Method::Ping => TagotipMethod::Ping,
    }
}

fn convert_operator(o: &Operator) -> TagotipOperator {
    match o {
        Operator::Number => TagotipOperator::Number,
        Operator::String => TagotipOperator::String,
        Operator::Boolean => TagotipOperator::Boolean,
        Operator::Location => TagotipOperator::Location,
    }
}

fn convert_value(v: &Value<'_>) -> TagotipValue {
    match v {
        Value::Number(s) => TagotipValue {
            tag: TagotipValueTag::Number,
            str_val: TagotipStr::from_str(s),
            bool_val: 0,
            lat: TagotipStr::empty(),
            lng: TagotipStr::empty(),
            alt: TagotipStr::empty(),
        },
        Value::String(s) => TagotipValue {
            tag: TagotipValueTag::String,
            str_val: TagotipStr::from_str(s),
            bool_val: 0,
            lat: TagotipStr::empty(),
            lng: TagotipStr::empty(),
            alt: TagotipStr::empty(),
        },
        Value::Boolean(b) => TagotipValue {
            tag: TagotipValueTag::Boolean,
            str_val: TagotipStr::empty(),
            bool_val: u8::from(*b),
            lat: TagotipStr::empty(),
            lng: TagotipStr::empty(),
            alt: TagotipStr::empty(),
        },
        Value::Location { lat, lng, alt } => TagotipValue {
            tag: TagotipValueTag::Location,
            str_val: TagotipStr::empty(),
            bool_val: 0,
            lat: TagotipStr::from_str(lat),
            lng: TagotipStr::from_str(lng),
            alt: TagotipStr::from_option(*alt),
        },
    }
}

fn convert_error_code(c: &ErrorCode) -> TagotipErrorCode {
    match c {
        ErrorCode::InvalidToken => TagotipErrorCode::InvalidToken,
        ErrorCode::InvalidMethod => TagotipErrorCode::InvalidMethod,
        ErrorCode::InvalidPayload => TagotipErrorCode::InvalidPayload,
        ErrorCode::InvalidSeq => TagotipErrorCode::InvalidSeq,
        ErrorCode::DeviceNotFound => TagotipErrorCode::DeviceNotFound,
        ErrorCode::VariableNotFound => TagotipErrorCode::VariableNotFound,
        ErrorCode::RateLimited => TagotipErrorCode::RateLimited,
        ErrorCode::AuthFailed => TagotipErrorCode::AuthFailed,
        ErrorCode::UnsupportedVersion => TagotipErrorCode::UnsupportedVersion,
        ErrorCode::PayloadTooLarge => TagotipErrorCode::PayloadTooLarge,
        ErrorCode::ServerError => TagotipErrorCode::ServerError,
        ErrorCode::Unknown => TagotipErrorCode::Unknown,
    }
}

fn convert_ack_status(s: &AckStatus) -> TagotipAckStatus {
    match s {
        AckStatus::Ok => TagotipAckStatus::Ok,
        AckStatus::Pong => TagotipAckStatus::Pong,
        AckStatus::Cmd => TagotipAckStatus::Cmd,
        AckStatus::Err => TagotipAckStatus::Err,
    }
}

// ---------------------------------------------------------------------------
// FFI functions
// ---------------------------------------------------------------------------

/// Parse an uplink frame.
///
/// # Safety
/// - `input_ptr` must point to a valid UTF-8 byte array of `input_len` bytes.
/// - `out` must point to a valid, writeable `TagotipUplinkFrame`.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tagotip_parse_uplink(
    input_ptr: *const u8,
    input_len: usize,
    out: *mut TagotipUplinkFrame,
) -> i32 {
    let input = unsafe {
        let bytes = slice::from_raw_parts(input_ptr, input_len);
        match str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return TAGOTIP_ERR_INVALID_INPUT,
        }
    };

    let frame = match tagotip_codec::parse::parse_uplink(input) {
        Ok(f) => f,
        Err(e) => return parse_error_to_code(&e),
    };

    let out = unsafe { &mut *out };

    out.method = convert_method(&frame.method);
    out.has_seq = u8::from(frame.seq.is_some());
    out.seq = frame.seq.unwrap_or(0);
    out.auth = TagotipStr::from_str(frame.auth);
    out.serial = TagotipStr::from_str(frame.serial);

    // Push body
    match &frame.push_body {
        Some(PushBody::Structured(sb)) => {
            out.push_body_tag = TagotipPushBodyTag::Structured;
            out.body_group = TagotipStr::from_option(sb.group);
            out.body_timestamp = TagotipStr::from_option(sb.timestamp);
            if let Some(r) = sb.body_meta {
                out.body_meta_start = r.start;
                out.body_meta_len = r.len;
            } else {
                out.body_meta_start = 0;
                out.body_meta_len = 0;
            }

            let var_count = sb.variables.len().min(MAX_VARIABLES);
            out.variables_len = var_count as u16;
            for (i, var) in sb.variables.iter().enumerate().take(var_count) {
                out.variables[i] = TagotipVariable {
                    name: TagotipStr::from_str(var.name),
                    operator: convert_operator(&var.operator),
                    value: convert_value(&var.value),
                    unit: TagotipStr::from_option(var.unit),
                    timestamp: TagotipStr::from_option(var.timestamp),
                    group: TagotipStr::from_option(var.group),
                    meta_start: var.meta.map_or(0, |r| r.start),
                    meta_len: var.meta.map_or(0, |r| r.len),
                };
            }

            let meta_count = sb.meta_pool.len().min(MAX_TOTAL_META);
            out.meta_pool_len = meta_count as u16;
            for (i, mp) in sb.meta_pool.iter().enumerate().take(meta_count) {
                out.meta_pool[i] = TagotipMetaPair {
                    key: TagotipStr::from_str(mp.key),
                    value: TagotipStr::from_str(mp.value),
                };
            }
        }
        Some(PushBody::Passthrough(pt)) => {
            out.push_body_tag = TagotipPushBodyTag::Passthrough;
            out.passthrough = TagotipPassthroughBody {
                encoding: match pt.encoding {
                    PassthroughEncoding::Hex => TagotipPassthroughEncoding::Hex,
                    PassthroughEncoding::Base64 => TagotipPassthroughEncoding::Base64,
                },
                data: TagotipStr::from_str(pt.data),
            };
            out.variables_len = 0;
            out.meta_pool_len = 0;
        }
        None => {
            out.push_body_tag = TagotipPushBodyTag::None;
            out.variables_len = 0;
            out.meta_pool_len = 0;
        }
    }

    // Pull body
    if let Some(pb) = &frame.pull_body {
        out.has_pull_body = 1;
        let count = pb.variables.len().min(MAX_VARIABLES);
        out.pull_variables_len = count as u16;
        for (i, name) in pb.variables.iter().enumerate().take(count) {
            out.pull_variables[i] = TagotipStr::from_str(name);
        }
    } else {
        out.has_pull_body = 0;
        out.pull_variables_len = 0;
    }

    TAGOTIP_OK
}

/// Build an uplink frame into a buffer.
///
/// # Safety
/// - `frame` must point to a valid `TagotipUplinkFrame`.
/// - `buf_ptr` must point to a writeable buffer of at least `buf_len` bytes.
///
/// Returns bytes written on success, negative error code on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tagotip_build_uplink(
    frame: *const TagotipUplinkFrame,
    buf_ptr: *mut u8,
    buf_len: usize,
) -> i32 {
    let frame = unsafe { &*frame };
    let buf = unsafe { slice::from_raw_parts_mut(buf_ptr, buf_len) };

    let method = match frame.method {
        TagotipMethod::Push => Method::Push,
        TagotipMethod::Pull => Method::Pull,
        TagotipMethod::Ping => Method::Ping,
    };

    let seq = if frame.has_seq != 0 {
        Some(frame.seq)
    } else {
        None
    };

    let auth = unsafe { tagotip_str_to_str(&frame.auth) };
    let serial = unsafe { tagotip_str_to_str(&frame.serial) };

    // TODO: Build full frame from C struct fields.
    // For now, construct a minimal UplinkFrame and delegate to tagotip_codec::build::build_uplink.
    let rust_frame = UplinkFrame {
        method,
        seq,
        auth,
        serial,
        push_body: None, // TODO: convert push body from C struct
        pull_body: None, // TODO: convert pull body from C struct
    };

    match tagotip_codec::build::build_uplink(&rust_frame, buf) {
        Ok(n) => n as i32,
        Err(_) => TAGOTIP_ERR_BUFFER_TOO_SMALL,
    }
}

/// Parse an ACK (downlink) frame.
///
/// # Safety
/// - `input_ptr` must point to a valid UTF-8 byte array of `input_len` bytes.
/// - `out` must point to a valid, writeable `TagotipAckFrame`.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tagotip_parse_ack(
    input_ptr: *const u8,
    input_len: usize,
    out: *mut TagotipAckFrame,
) -> i32 {
    let input = unsafe {
        let bytes = slice::from_raw_parts(input_ptr, input_len);
        match str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return TAGOTIP_ERR_INVALID_INPUT,
        }
    };

    let frame = match tagotip_codec::parse::parse_ack(input) {
        Ok(f) => f,
        Err(e) => return parse_error_to_code(&e),
    };

    let out = unsafe { &mut *out };

    out.has_seq = u8::from(frame.seq.is_some());
    out.seq = frame.seq.unwrap_or(0);
    out.status = convert_ack_status(&frame.status);

    match &frame.detail {
        Some(AckDetail::Count(n)) => {
            out.detail = TagotipAckDetail {
                tag: TagotipAckDetailTag::Count,
                count: *n,
                text: TagotipStr::empty(),
                error_code: TagotipErrorCode::Unknown,
            };
        }
        Some(AckDetail::Variables(s)) => {
            out.detail = TagotipAckDetail {
                tag: TagotipAckDetailTag::Variables,
                count: 0,
                text: TagotipStr::from_str(s),
                error_code: TagotipErrorCode::Unknown,
            };
        }
        Some(AckDetail::Command(s)) => {
            out.detail = TagotipAckDetail {
                tag: TagotipAckDetailTag::Command,
                count: 0,
                text: TagotipStr::from_str(s),
                error_code: TagotipErrorCode::Unknown,
            };
        }
        Some(AckDetail::Error { code, text }) => {
            out.detail = TagotipAckDetail {
                tag: TagotipAckDetailTag::Error,
                count: 0,
                text: TagotipStr::from_str(text),
                error_code: convert_error_code(code),
            };
        }
        Some(AckDetail::Raw(s)) => {
            out.detail = TagotipAckDetail {
                tag: TagotipAckDetailTag::Raw,
                count: 0,
                text: TagotipStr::from_str(s),
                error_code: TagotipErrorCode::Unknown,
            };
        }
        None => {
            out.detail = TagotipAckDetail {
                tag: TagotipAckDetailTag::None,
                count: 0,
                text: TagotipStr::empty(),
                error_code: TagotipErrorCode::Unknown,
            };
        }
    }

    TAGOTIP_OK
}

/// Build an ACK frame into a buffer.
///
/// # Safety
/// - `frame` must point to a valid `TagotipAckFrame`.
/// - `buf_ptr` must point to a writeable buffer of at least `buf_len` bytes.
///
/// Returns bytes written on success, negative error code on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tagotip_build_ack(
    frame: *const TagotipAckFrame,
    buf_ptr: *mut u8,
    buf_len: usize,
) -> i32 {
    let frame = unsafe { &*frame };
    let buf = unsafe { slice::from_raw_parts_mut(buf_ptr, buf_len) };

    let seq = if frame.has_seq != 0 {
        Some(frame.seq)
    } else {
        None
    };

    let status = match frame.status {
        TagotipAckStatus::Ok => AckStatus::Ok,
        TagotipAckStatus::Pong => AckStatus::Pong,
        TagotipAckStatus::Cmd => AckStatus::Cmd,
        TagotipAckStatus::Err => AckStatus::Err,
    };

    // TODO: convert detail from C struct
    let rust_frame = AckFrame {
        seq,
        status,
        detail: None,
    };

    match tagotip_codec::build::build_ack(&rust_frame, buf) {
        Ok(n) => n as i32,
        Err(_) => TAGOTIP_ERR_BUFFER_TOO_SMALL,
    }
}

/// Helper to convert `TagotipStr` back to &str.
///
/// # Safety
/// - The `TagotipStr` must point to valid UTF-8 data.
unsafe fn tagotip_str_to_str<'a>(s: &TagotipStr) -> &'a str {
    if s.ptr.is_null() || s.len == 0 {
        ""
    } else {
        unsafe {
            let bytes = slice::from_raw_parts(s.ptr, s.len);
            str::from_utf8_unchecked(bytes)
        }
    }
}

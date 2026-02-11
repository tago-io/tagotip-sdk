use crate::consts::{AUTH_TOKEN_LEN, MAX_UPLINK_FIELDS};
use crate::error::{ParseError, ParseErrorKind};
use crate::inline_vec::InlineVec;
use crate::types::Method;
use crate::validate;

/// Split a frame string by `|`, respecting `\|` escape sequences.
/// Returns slices into the original string.
#[must_use]
pub fn split_fields(input: &str) -> InlineVec<&str, MAX_UPLINK_FIELDS> {
    let mut fields = InlineVec::new();
    let bytes = input.as_bytes();
    let mut start = 0;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2; // skip escape sequence
            continue;
        }
        if bytes[i] == b'|' {
            let _ = fields.push(&input[start..i]);
            start = i + 1;
            // If we've filled the vec, put everything remaining in the last slot
            if fields.len() == MAX_UPLINK_FIELDS - 1 {
                let _ = fields.push(&input[start..]);
                return fields;
            }
        }
        i += 1;
    }
    let _ = fields.push(&input[start..]);
    fields
}

/// Parse the method string. Case-sensitive per spec.
pub fn parse_method(s: &str) -> Result<Method, ParseError> {
    match s {
        "PUSH" => Ok(Method::Push),
        "PULL" => Ok(Method::Pull),
        "PING" => Ok(Method::Ping),
        _ => Err(ParseError::new(ParseErrorKind::InvalidMethod, 0)),
    }
}

/// Parse a sequence counter field (e.g., "!42"). Returns the u32 value.
pub fn parse_seq(s: &str, pos: usize) -> Result<u32, ParseError> {
    if !s.starts_with('!') {
        return Err(ParseError::new(ParseErrorKind::InvalidSeq, pos));
    }
    let num_str = &s[1..];
    if num_str.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidSeq, pos));
    }
    // No leading zeros (except "0" itself)
    if num_str.len() > 1 && num_str.as_bytes()[0] == b'0' {
        return Err(ParseError::new(ParseErrorKind::InvalidSeq, pos));
    }
    parse_u32(num_str).ok_or_else(|| ParseError::new(ParseErrorKind::InvalidSeq, pos))
}

/// Validate an auth token: "at" + 32 hex chars.
pub fn validate_auth(s: &str, pos: usize) -> Result<(), ParseError> {
    if s.len() != AUTH_TOKEN_LEN {
        return Err(ParseError::new(ParseErrorKind::InvalidAuth, pos));
    }
    if !s.starts_with("at") {
        return Err(ParseError::new(ParseErrorKind::InvalidAuth, pos));
    }
    for &b in &s.as_bytes()[2..] {
        if !b.is_ascii_hexdigit() {
            return Err(ParseError::new(ParseErrorKind::InvalidAuth, pos));
        }
    }
    Ok(())
}

/// Extract the serial from a field, unescaping if needed, and validate it.
/// Returns a reference to the original string (serial chars don't need unescaping
/// since SERIALCHAR doesn't include any escapable characters).
pub fn extract_serial(s: &str, pos: usize) -> Result<&str, ParseError> {
    // Serial chars (a-zA-Z, 0-9, -, _) don't include any escapable chars,
    // so the raw field IS the serial. Just validate it.
    validate::validate_serial(s, pos)?;
    Ok(s)
}

/// Parse a decimal string to u32 (`no_std`).
fn parse_u32(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut result: u32 = 0;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        result = result.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(result)
}

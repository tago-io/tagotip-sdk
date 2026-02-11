pub mod ack;
pub mod body;
pub mod frame;
pub mod variable;

use crate::consts::MAX_FRAME_SIZE;
use crate::error::{ParseError, ParseErrorKind};
use crate::types::{AckFrame, HeadlessFrame, Method, UplinkFrame};

use self::body::{parse_pull_body, parse_push_body};
use self::frame::{extract_serial, parse_method, parse_seq, split_fields, validate_auth};

/// Parse a complete uplink frame (PUSH, PULL, or PING).
///
/// The input should NOT include a trailing `\n`.
pub fn parse_uplink(input: &str) -> Result<UplinkFrame<'_>, ParseError> {
    // NUL byte check
    if input.as_bytes().contains(&0) {
        return Err(ParseError::new(ParseErrorKind::NulByte, 0));
    }

    // Frame size check
    if input.len() > MAX_FRAME_SIZE {
        return Err(ParseError::new(ParseErrorKind::FrameTooLarge, 0));
    }

    // Strip trailing \n if present (TCP transport)
    let input = input.strip_suffix('\n').unwrap_or(input);

    let fields = split_fields(input);

    if fields.is_empty() || fields[0].is_empty() {
        return Err(ParseError::new(ParseErrorKind::EmptyFrame, 0));
    }

    let method = parse_method(fields[0])?;

    // Determine if field[1] is a sequence counter
    let (seq, auth_idx) = if fields.len() > 1 && fields[1].starts_with('!') {
        let seq_val = parse_seq(fields[1], fields[0].len() + 1)?;
        (Some(seq_val), 2)
    } else {
        (None, 1)
    };

    // Compute positions for error reporting
    let auth_pos: usize = fields[..auth_idx].iter().map(|f| f.len() + 1).sum();

    if fields.len() <= auth_idx {
        return Err(ParseError::new(ParseErrorKind::InvalidAuth, auth_pos));
    }
    let auth = fields[auth_idx];
    validate_auth(auth, auth_pos)?;

    let serial_idx = auth_idx + 1;
    let serial_pos = auth_pos + auth.len() + 1;

    if fields.len() <= serial_idx {
        return Err(ParseError::new(ParseErrorKind::InvalidSerial, serial_pos));
    }
    let serial = extract_serial(fields[serial_idx], serial_pos)?;

    let body_idx = serial_idx + 1;
    let body_pos = serial_pos + serial.len() + 1;

    match method {
        Method::Push => {
            if fields.len() <= body_idx {
                return Err(ParseError::new(ParseErrorKind::MissingBody, body_pos));
            }
            // Body may span multiple fields if it contains unescaped pipes
            // (which shouldn't happen in valid frames, but handle it like the reference)
            // Actually, split_fields puts the rest into the last field, so fields[body_idx] is the full body
            let body_str = fields[body_idx];
            let push_body = parse_push_body(body_str, body_pos)?;
            Ok(UplinkFrame {
                method,
                seq,
                auth,
                serial,
                push_body: Some(push_body),
                pull_body: None,
            })
        }
        Method::Pull => {
            if fields.len() <= body_idx {
                return Err(ParseError::new(ParseErrorKind::MissingBody, body_pos));
            }
            let body_str = fields[body_idx];
            let pull_body = parse_pull_body(body_str, body_pos)?;
            Ok(UplinkFrame {
                method,
                seq,
                auth,
                serial,
                push_body: None,
                pull_body: Some(pull_body),
            })
        }
        Method::Ping => Ok(UplinkFrame {
            method,
            seq,
            auth,
            serial,
            push_body: None,
            pull_body: None,
        }),
    }
}

/// Parse an ACK (downlink) frame.
pub fn parse_ack(input: &str) -> Result<AckFrame<'_>, ParseError> {
    // Strip trailing \n if present
    let input = input.strip_suffix('\n').unwrap_or(input);
    ack::parse_ack(input)
}

/// Parse a headless inner frame (for TagoTiP/S).
/// The method comes from the envelope flags byte.
///
/// Headless format:
/// - PUSH: `SERIAL|BODY`
/// - PULL: `SERIAL|[var1;var2;...]`
/// - PING: `SERIAL`
pub fn parse_headless(method: Method, input: &str) -> Result<HeadlessFrame<'_>, ParseError> {
    match method {
        Method::Push => {
            // Split by first unescaped `|`
            let (serial_str, body_str) = split_first_pipe(input)
                .ok_or_else(|| ParseError::new(ParseErrorKind::MissingBody, 0))?;

            let serial = extract_serial(serial_str, 0)?;
            let body_pos = serial_str.len() + 1;
            let push_body = parse_push_body(body_str, body_pos)?;

            Ok(HeadlessFrame {
                serial,
                push_body: Some(push_body),
                pull_body: None,
            })
        }
        Method::Pull => {
            let (serial_str, body_str) = split_first_pipe(input)
                .ok_or_else(|| ParseError::new(ParseErrorKind::MissingBody, 0))?;

            let serial = extract_serial(serial_str, 0)?;
            let body_pos = serial_str.len() + 1;
            let pull_body = parse_pull_body(body_str, body_pos)?;

            Ok(HeadlessFrame {
                serial,
                push_body: None,
                pull_body: Some(pull_body),
            })
        }
        Method::Ping => {
            let serial = extract_serial(input, 0)?;
            Ok(HeadlessFrame {
                serial,
                push_body: None,
                pull_body: None,
            })
        }
    }
}

/// Split on the first unescaped `|`.
fn split_first_pipe(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'|' {
            return Some((&s[..i], &s[i + 1..]));
        }
        i += 1;
    }
    None
}

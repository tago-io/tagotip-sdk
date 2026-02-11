use crate::error::{ParseError, ParseErrorKind};
use crate::types::{AckDetail, AckFrame, AckStatus, ErrorCode};

use super::frame::{parse_seq, split_fields};

/// Parse an ACK (downlink) frame.
///
/// Formats:
/// - `ACK|STATUS`
/// - `ACK|STATUS|DETAIL`
/// - `ACK|!N|STATUS`
/// - `ACK|!N|STATUS|DETAIL`
pub fn parse_ack(input: &str) -> Result<AckFrame<'_>, ParseError> {
    let fields = split_fields(input);

    if fields.is_empty() || fields[0] != "ACK" {
        return Err(ParseError::new(ParseErrorKind::InvalidAck, 0));
    }

    let field_count = fields.len();

    if field_count < 2 {
        return Err(ParseError::new(ParseErrorKind::InvalidAck, 0));
    }

    // Determine if field[1] is a sequence counter
    let (seq, status_idx) = if fields[1].starts_with('!') {
        let seq = parse_seq(fields[1], 4)?; // 4 = "ACK|" length
        (Some(seq), 2)
    } else {
        (None, 1)
    };

    if field_count <= status_idx {
        return Err(ParseError::new(ParseErrorKind::InvalidAck, 0));
    }

    let status = parse_ack_status(fields[status_idx])?;

    let detail = if field_count > status_idx + 1 {
        let detail_str = fields[status_idx + 1];
        Some(parse_ack_detail(detail_str, status)?)
    } else {
        None
    };

    Ok(AckFrame {
        seq,
        status,
        detail,
    })
}

/// Parse an ACK status string.
fn parse_ack_status(s: &str) -> Result<AckStatus, ParseError> {
    match s {
        "OK" => Ok(AckStatus::Ok),
        "PONG" => Ok(AckStatus::Pong),
        "CMD" => Ok(AckStatus::Cmd),
        "ERR" => Ok(AckStatus::Err),
        _ => Err(ParseError::new(ParseErrorKind::InvalidAck, 0)),
    }
}

/// Parse the DETAIL field of an ACK frame.
fn parse_ack_detail(s: &str, status: AckStatus) -> Result<AckDetail<'_>, ParseError> {
    match status {
        AckStatus::Ok => {
            // Could be a count (digits) or variables (bracket-wrapped)
            if s.starts_with('[') {
                Ok(AckDetail::Variables(s))
            } else {
                // Try to parse as count
                if let Some(count) = parse_u32_str(s) {
                    Ok(AckDetail::Count(count))
                } else {
                    Ok(AckDetail::Raw(s))
                }
            }
        }
        AckStatus::Pong => {
            // PONG shouldn't have detail, but if present, return raw
            Ok(AckDetail::Raw(s))
        }
        AckStatus::Cmd => Ok(AckDetail::Command(s)),
        AckStatus::Err => {
            let code = match s {
                "invalid_token" => ErrorCode::InvalidToken,
                "invalid_method" => ErrorCode::InvalidMethod,
                "invalid_payload" => ErrorCode::InvalidPayload,
                "invalid_seq" => ErrorCode::InvalidSeq,
                "device_not_found" => ErrorCode::DeviceNotFound,
                "variable_not_found" => ErrorCode::VariableNotFound,
                "rate_limited" => ErrorCode::RateLimited,
                "auth_failed" => ErrorCode::AuthFailed,
                "unsupported_version" => ErrorCode::UnsupportedVersion,
                "payload_too_large" => ErrorCode::PayloadTooLarge,
                "server_error" => ErrorCode::ServerError,
                _ => ErrorCode::Unknown,
            };
            Ok(AckDetail::Error { code, text: s })
        }
    }
}

/// Parse a decimal string to u32.
fn parse_u32_str(s: &str) -> Option<u32> {
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

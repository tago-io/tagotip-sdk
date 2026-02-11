use tagotip_codec::parse::parse_ack;
use tagotip_codec::types::*;

#[test]
fn ack_ok_count() {
    let frame = parse_ack("ACK|OK|3").unwrap();
    assert_eq!(frame.status, AckStatus::Ok);
    assert!(frame.seq.is_none());
    assert_eq!(frame.detail, Some(AckDetail::Count(3)));
}

#[test]
fn ack_ok_zero_count() {
    let frame = parse_ack("ACK|OK|0").unwrap();
    assert_eq!(frame.detail, Some(AckDetail::Count(0)));
}

#[test]
fn ack_ok_variables() {
    let frame = parse_ack("ACK|OK|[temperature:=32#F@1694567890000]").unwrap();
    assert_eq!(frame.status, AckStatus::Ok);
    match frame.detail {
        Some(AckDetail::Variables(v)) => {
            assert_eq!(v, "[temperature:=32#F@1694567890000]");
        }
        _ => panic!("expected Variables detail"),
    }
}

#[test]
fn ack_pong() {
    let frame = parse_ack("ACK|PONG").unwrap();
    assert_eq!(frame.status, AckStatus::Pong);
    assert!(frame.detail.is_none());
}

#[test]
fn ack_cmd() {
    let frame = parse_ack("ACK|CMD|reboot").unwrap();
    assert_eq!(frame.status, AckStatus::Cmd);
    assert_eq!(frame.detail, Some(AckDetail::Command("reboot")));
}

#[test]
fn ack_cmd_with_value() {
    let frame = parse_ack("ACK|CMD|ota=https://example.com/v2.1.bin").unwrap();
    assert_eq!(frame.status, AckStatus::Cmd);
    assert_eq!(
        frame.detail,
        Some(AckDetail::Command("ota=https://example.com/v2.1.bin"))
    );
}

#[test]
fn ack_err_invalid_token() {
    let frame = parse_ack("ACK|ERR|invalid_token").unwrap();
    assert_eq!(frame.status, AckStatus::Err);
    match frame.detail {
        Some(AckDetail::Error { code, text }) => {
            assert_eq!(code, ErrorCode::InvalidToken);
            assert_eq!(text, "invalid_token");
        }
        _ => panic!("expected Error detail"),
    }
}

#[test]
fn ack_err_invalid_payload() {
    let frame = parse_ack("ACK|ERR|invalid_payload").unwrap();
    match frame.detail {
        Some(AckDetail::Error { code, .. }) => {
            assert_eq!(code, ErrorCode::InvalidPayload);
        }
        _ => panic!("expected Error detail"),
    }
}

#[test]
fn ack_err_all_error_codes() {
    let cases = [
        ("invalid_token", ErrorCode::InvalidToken),
        ("invalid_method", ErrorCode::InvalidMethod),
        ("invalid_payload", ErrorCode::InvalidPayload),
        ("invalid_seq", ErrorCode::InvalidSeq),
        ("device_not_found", ErrorCode::DeviceNotFound),
        ("variable_not_found", ErrorCode::VariableNotFound),
        ("rate_limited", ErrorCode::RateLimited),
        ("auth_failed", ErrorCode::AuthFailed),
        ("unsupported_version", ErrorCode::UnsupportedVersion),
        ("payload_too_large", ErrorCode::PayloadTooLarge),
        ("server_error", ErrorCode::ServerError),
        ("some_unknown_error", ErrorCode::Unknown),
    ];

    for (text, expected_code) in cases {
        let input = format!("ACK|ERR|{text}");
        let frame = parse_ack(&input).unwrap();
        match frame.detail {
            Some(AckDetail::Error { code, .. }) => {
                assert_eq!(code, expected_code, "failed for: {text}");
            }
            _ => panic!("expected Error detail for: {text}"),
        }
    }
}

// --- With sequence counter ---

#[test]
fn ack_with_seq_ok() {
    let frame = parse_ack("ACK|!1|OK|2").unwrap();
    assert_eq!(frame.seq, Some(1));
    assert_eq!(frame.status, AckStatus::Ok);
    assert_eq!(frame.detail, Some(AckDetail::Count(2)));
}

#[test]
fn ack_with_seq_pong() {
    let frame = parse_ack("ACK|!3|PONG").unwrap();
    assert_eq!(frame.seq, Some(3));
    assert_eq!(frame.status, AckStatus::Pong);
    assert!(frame.detail.is_none());
}

#[test]
fn ack_with_seq_err() {
    let frame = parse_ack("ACK|!5|ERR|invalid_token").unwrap();
    assert_eq!(frame.seq, Some(5));
    assert_eq!(frame.status, AckStatus::Err);
}

#[test]
fn ack_with_seq_variables() {
    let frame =
        parse_ack("ACK|!2|OK|[temperature:=32#F@1694567890000;humidity:=65#%@1694567890000]")
            .unwrap();
    assert_eq!(frame.seq, Some(2));
    assert_eq!(frame.status, AckStatus::Ok);
    match frame.detail {
        Some(AckDetail::Variables(v)) => {
            assert!(v.starts_with('['));
        }
        _ => panic!("expected Variables detail"),
    }
}

// --- Error cases ---

#[test]
fn ack_empty_rejected() {
    assert!(parse_ack("ACK").is_err());
}

#[test]
fn ack_invalid_status_rejected() {
    assert!(parse_ack("ACK|UNKNOWN").is_err());
}

#[test]
fn ack_trailing_newline() {
    let frame = parse_ack("ACK|OK|3\n").unwrap();
    assert_eq!(frame.detail, Some(AckDetail::Count(3)));
}

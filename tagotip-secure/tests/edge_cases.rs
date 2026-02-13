use tagotip_codec::types::{HeadlessFrame, Method};
use tagotip_secure::error::CryptoErrorKind;
use tagotip_secure::{
    CipherSuite, EnvelopeMethod, Flags, derive_auth_hash, is_envelope, open_envelope,
    parse_envelope_header, seal_raw, seal_uplink,
};

const TOKEN: &str = "ate2bd319014b24e0a8aca9f00aea4c0d0";
const KEY_16: [u8; 16] = [
    0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee, 0x12, 0xab, 0x56, 0xcd, 0x78, 0xef, 0x90, 0x12,
];

// ---------------------------------------------------------------------------
// Decryption failures
// ---------------------------------------------------------------------------

#[test]
fn test_wrong_key() {
    let auth_hash = derive_auth_hash(TOKEN);
    let frame = HeadlessFrame {
        serial: "sensor-01",
        push_body: None,
        pull_body: None,
    };

    let envelope = seal_uplink(
        Method::Ping,
        &frame,
        1,
        auth_hash,
        &KEY_16,
        CipherSuite::Aes128Ccm,
    )
    .unwrap();

    let wrong_key = [0u8; 16];
    let result = open_envelope(&envelope, &wrong_key);
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::DecryptionFailed);
}

#[test]
fn test_tampered_header() {
    let auth_hash = derive_auth_hash(TOKEN);
    let frame = HeadlessFrame {
        serial: "sensor-01",
        push_body: None,
        pull_body: None,
    };

    let mut envelope = seal_uplink(
        Method::Ping,
        &frame,
        1,
        auth_hash,
        &KEY_16,
        CipherSuite::Aes128Ccm,
    )
    .unwrap();

    // Tamper with the counter field (bytes 1-4)
    envelope[2] ^= 0xFF;

    let result = open_envelope(&envelope, &KEY_16);
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::DecryptionFailed);
}

#[test]
fn test_tampered_ciphertext() {
    let auth_hash = derive_auth_hash(TOKEN);
    let frame = HeadlessFrame {
        serial: "sensor-01",
        push_body: None,
        pull_body: None,
    };

    let mut envelope = seal_uplink(
        Method::Ping,
        &frame,
        1,
        auth_hash,
        &KEY_16,
        CipherSuite::Aes128Ccm,
    )
    .unwrap();

    // Tamper with ciphertext
    let ct_start = 21;
    envelope[ct_start] ^= 0xFF;

    let result = open_envelope(&envelope, &KEY_16);
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::DecryptionFailed);
}

#[test]
fn test_tampered_auth_tag() {
    let auth_hash = derive_auth_hash(TOKEN);
    let frame = HeadlessFrame {
        serial: "sensor-01",
        push_body: None,
        pull_body: None,
    };

    let mut envelope = seal_uplink(
        Method::Ping,
        &frame,
        1,
        auth_hash,
        &KEY_16,
        CipherSuite::Aes128Ccm,
    )
    .unwrap();

    // Tamper with the last byte (part of auth tag)
    let last = envelope.len() - 1;
    envelope[last] ^= 0xFF;

    let result = open_envelope(&envelope, &KEY_16);
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::DecryptionFailed);
}

// ---------------------------------------------------------------------------
// Truncated envelopes
// ---------------------------------------------------------------------------

#[test]
fn test_empty_envelope() {
    let result = parse_envelope_header(&[]);
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::EnvelopeTooShort);
}

#[test]
fn test_truncated_header() {
    let data = [0u8; 20]; // 1 byte short of header
    let result = parse_envelope_header(&data);
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::EnvelopeTooShort);
}

#[test]
fn test_header_only_no_ciphertext() {
    let auth_hash = derive_auth_hash(TOKEN);
    let device_hash = tagotip_secure::derive_device_hash("sensor-01");

    let header = tagotip_secure::EnvelopeHeader {
        flags: 0x00,
        counter: 1,
        auth_hash,
        device_hash,
    };
    let envelope = header.to_bytes();

    let result = open_envelope(&envelope, &KEY_16);
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::EnvelopeTooShort);
}

// ---------------------------------------------------------------------------
// Reserved flags value
// ---------------------------------------------------------------------------

#[test]
fn test_reserved_flags_value_encode() {
    // 0x41 = cipher 2 (AES-256-CCM), version 0, method 1 (PULL)
    let result = Flags::encode(CipherSuite::Aes256Ccm, 0, EnvelopeMethod::Pull);
    assert_eq!(
        result.unwrap_err().kind,
        CryptoErrorKind::ReservedFlagsValue
    );
}

#[test]
fn test_reserved_flags_value_decode() {
    let result = Flags::decode(0x41);
    assert_eq!(
        result.unwrap_err().kind,
        CryptoErrorKind::ReservedFlagsValue
    );
}

#[test]
fn test_reserved_flags_in_envelope() {
    let mut envelope = [0u8; 30];
    envelope[0] = 0x41; // Reserved flags value
    let result = parse_envelope_header(&envelope);
    assert_eq!(
        result.unwrap_err().kind,
        CryptoErrorKind::ReservedFlagsValue
    );
}

// ---------------------------------------------------------------------------
// Invalid key sizes
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_key_size_too_short() {
    let auth_hash = derive_auth_hash(TOKEN);
    let device_hash = tagotip_secure::derive_device_hash("sensor-01");
    let short_key = [0u8; 8];

    let result = seal_raw(
        b"test",
        EnvelopeMethod::Push,
        1,
        auth_hash,
        device_hash,
        &short_key,
        CipherSuite::Aes128Ccm,
    );
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::InvalidKeySize);
}

#[test]
fn test_invalid_key_size_too_long() {
    let auth_hash = derive_auth_hash(TOKEN);
    let device_hash = tagotip_secure::derive_device_hash("sensor-01");
    let long_key = [0u8; 32]; // 32 bytes for a 16-byte cipher

    let result = seal_raw(
        b"test",
        EnvelopeMethod::Push,
        1,
        auth_hash,
        device_hash,
        &long_key,
        CipherSuite::Aes128Ccm,
    );
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::InvalidKeySize);
}

// ---------------------------------------------------------------------------
// Unsupported version
// ---------------------------------------------------------------------------

#[test]
fn test_unsupported_version_decode() {
    // Version 1 is not currently supported
    // cipher=0 (bits 7-5 = 000), version=1 (bits 4-3 = 01), method=0 (bits 2-0 = 000)
    // = 0b0000_1000 = 0x08
    let result = open_envelope(
        &{
            let mut env = [0u8; 30];
            env[0] = 0x08; // version 1
            env
        },
        &KEY_16,
    );
    assert_eq!(
        result.unwrap_err().kind,
        CryptoErrorKind::UnsupportedVersion
    );
}

// ---------------------------------------------------------------------------
// Unsupported cipher
// ---------------------------------------------------------------------------

#[test]
fn test_unsupported_cipher_decode() {
    // cipher=5 (bits 7-5 = 101), version=0, method=0
    // = 0b1010_0000 = 0xA0
    let result = Flags::decode(0xA0);
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::UnsupportedCipher);
}

// ---------------------------------------------------------------------------
// Invalid method
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_method_decode() {
    // cipher=0, version=0, method=5 (bits 2-0 = 101)
    // = 0b0000_0101 = 0x05
    let result = Flags::decode(0x05);
    assert_eq!(result.unwrap_err().kind, CryptoErrorKind::InvalidMethod);
}

// ---------------------------------------------------------------------------
// Disambiguation
// ---------------------------------------------------------------------------

#[test]
fn test_is_envelope_various() {
    assert!(is_envelope(&[0x00])); // AES-128-CCM PUSH
    assert!(is_envelope(&[0x80])); // ChaCha20 PUSH
    assert!(is_envelope(&[0x03])); // AES-128-CCM ACK
    assert!(!is_envelope(&[0x41])); // Reserved / plaintext ACK
    assert!(!is_envelope(b"ACK|OK|3")); // Plaintext ACK
    assert!(!is_envelope(&[])); // Empty
}

// ---------------------------------------------------------------------------
// Flags encode/decode round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_flags_round_trip() {
    let suites = [
        (CipherSuite::Aes128Ccm, 0),
        (CipherSuite::Aes128Gcm, 1),
        (CipherSuite::Aes256Gcm, 3),
        (CipherSuite::ChaCha20Poly1305, 4),
    ];
    let methods = [
        EnvelopeMethod::Push,
        EnvelopeMethod::Pull,
        EnvelopeMethod::Ping,
        EnvelopeMethod::Ack,
    ];

    for &(suite, _) in &suites {
        for &method in &methods {
            let result = Flags::encode(suite, 0, method);
            match result {
                Ok(byte) => {
                    let (decoded_suite, decoded_version, decoded_method) =
                        Flags::decode(byte).unwrap();
                    assert_eq!(decoded_suite, suite);
                    assert_eq!(decoded_version, 0);
                    assert_eq!(decoded_method, method);
                }
                Err(e) => {
                    // Only the reserved 0x41 case should fail
                    assert_eq!(e.kind, CryptoErrorKind::ReservedFlagsValue);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CipherSuite properties
// ---------------------------------------------------------------------------

#[test]
fn test_cipher_suite_properties() {
    assert_eq!(CipherSuite::Aes128Ccm.key_size(), 16);
    assert_eq!(CipherSuite::Aes128Ccm.tag_size(), 8);
    assert_eq!(CipherSuite::Aes128Ccm.nonce_size(), 13);

    assert_eq!(CipherSuite::Aes128Gcm.key_size(), 16);
    assert_eq!(CipherSuite::Aes128Gcm.tag_size(), 16);
    assert_eq!(CipherSuite::Aes128Gcm.nonce_size(), 12);

    assert_eq!(CipherSuite::Aes256Ccm.key_size(), 32);
    assert_eq!(CipherSuite::Aes256Ccm.tag_size(), 8);
    assert_eq!(CipherSuite::Aes256Ccm.nonce_size(), 13);

    assert_eq!(CipherSuite::Aes256Gcm.key_size(), 32);
    assert_eq!(CipherSuite::Aes256Gcm.tag_size(), 16);
    assert_eq!(CipherSuite::Aes256Gcm.nonce_size(), 12);

    assert_eq!(CipherSuite::ChaCha20Poly1305.key_size(), 32);
    assert_eq!(CipherSuite::ChaCha20Poly1305.tag_size(), 16);
    assert_eq!(CipherSuite::ChaCha20Poly1305.nonce_size(), 12);
}

#[test]
fn test_cipher_suite_from_id() {
    assert_eq!(CipherSuite::from_id(0).unwrap(), CipherSuite::Aes128Ccm);
    assert_eq!(CipherSuite::from_id(1).unwrap(), CipherSuite::Aes128Gcm);
    assert_eq!(CipherSuite::from_id(2).unwrap(), CipherSuite::Aes256Ccm);
    assert_eq!(CipherSuite::from_id(3).unwrap(), CipherSuite::Aes256Gcm);
    assert_eq!(
        CipherSuite::from_id(4).unwrap(),
        CipherSuite::ChaCha20Poly1305
    );
    assert!(CipherSuite::from_id(5).is_err());
    assert!(CipherSuite::from_id(7).is_err());
}

// ---------------------------------------------------------------------------
// EnvelopeMethod properties
// ---------------------------------------------------------------------------

#[test]
fn test_envelope_method_conversions() {
    assert_eq!(
        EnvelopeMethod::from(tagotip_codec::Method::Push),
        EnvelopeMethod::Push
    );
    assert_eq!(
        EnvelopeMethod::from(tagotip_codec::Method::Pull),
        EnvelopeMethod::Pull
    );
    assert_eq!(
        EnvelopeMethod::from(tagotip_codec::Method::Ping),
        EnvelopeMethod::Ping
    );

    assert_eq!(
        EnvelopeMethod::Push.to_codec_method(),
        Some(tagotip_codec::Method::Push)
    );
    assert_eq!(EnvelopeMethod::Ack.to_codec_method(), None);
}

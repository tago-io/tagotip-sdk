/// Byte-for-byte validation against TagoTiP/S spec section 11.1.
///
/// Test vector: Encrypted Push -- AES-128-CCM
///
/// Inputs:
///   Token:           ate2bd319014b24e0a8aca9f00aea4c0d0
///   Serial:          sensor-01
///   Encryption Key:  fe 09 da 81 bc 44 00 ee 12 ab 56 cd 78 ef 90 12
///   Counter:         42
///   Method:          PUSH
///   Cipher Suite:    0 (AES-128-CCM)
///
/// Headless inner frame (20 bytes):
///   ASCII:  sensor-01|[temp:=32]
///   Hex:    73 65 6e 73 6f 72 2d 30 31 7c 5b 74 65 6d 70 3a 3d 33 32 5d
use tagotip_codec::types::{
  HeadlessFrame, Method, Operator, PushBody, StructuredBody, Value, Variable,
};
use tagotip_codec::inline_vec::InlineVec;
use tagotip_secure::{
  CipherSuite, derive_auth_hash, derive_device_hash, is_envelope, open_envelope,
  parse_envelope_header, seal_uplink,
};

const TOKEN: &str = "ate2bd319014b24e0a8aca9f00aea4c0d0";
const SERIAL: &str = "sensor-01";
const ENCRYPTION_KEY: [u8; 16] = [
  0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee, 0x12, 0xab, 0x56, 0xcd, 0x78, 0xef, 0x90,
  0x12,
];
const COUNTER: u32 = 42;

const EXPECTED_AUTH_HASH: [u8; 8] = [0x4d, 0xee, 0xdd, 0x7b, 0xab, 0x88, 0x17, 0xec];
const EXPECTED_DEVICE_HASH: [u8; 8] = [0xab, 0x77, 0x88, 0xd2, 0x2e, 0xb7, 0x37, 0x2f];
const EXPECTED_FLAGS: u8 = 0x00;

const EXPECTED_NONCE: [u8; 13] = [
  0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0x77, 0x88, 0xd2, 0x00, 0x00, 0x00, 0x2a,
];

const EXPECTED_AAD: [u8; 21] = [
  0x00, 0x00, 0x00, 0x00, 0x2a, 0x4d, 0xee, 0xdd, 0x7b, 0xab, 0x88, 0x17, 0xec, 0xab, 0x77,
  0x88, 0xd2, 0x2e, 0xb7, 0x37, 0x2f,
];

const EXPECTED_CIPHERTEXT: [u8; 20] = [
  0xc8, 0xc5, 0xaa, 0x56, 0xd7, 0x55, 0x58, 0x2b, 0xac, 0xea, 0x13, 0xbb, 0x57, 0x24, 0x93,
  0xbb, 0x8c, 0xb1, 0x08, 0x03,
];

const EXPECTED_AUTH_TAG: [u8; 8] = [0xcf, 0x82, 0x6f, 0xdb, 0x83, 0x3b, 0x79, 0xc6];

#[rustfmt::skip]
const EXPECTED_ENVELOPE: [u8; 49] = [
  0x00, 0x00, 0x00, 0x00, 0x2a, 0x4d, 0xee, 0xdd, 0x7b, 0xab, 0x88, 0x17, 0xec, 0xab, 0x77, 0x88,
  0xd2, 0x2e, 0xb7, 0x37, 0x2f, 0xc8, 0xc5, 0xaa, 0x56, 0xd7, 0x55, 0x58, 0x2b, 0xac, 0xea, 0x13,
  0xbb, 0x57, 0x24, 0x93, 0xbb, 0x8c, 0xb1, 0x08, 0x03, 0xcf, 0x82, 0x6f, 0xdb, 0x83, 0x3b, 0x79,
  0xc6,
];

const EXPECTED_INNER_FRAME: &[u8] = b"sensor-01|[temp:=32]";

#[test]
fn test_auth_hash_derivation() {
  let hash = derive_auth_hash(TOKEN);
  assert_eq!(hash, EXPECTED_AUTH_HASH);
}

#[test]
fn test_device_hash_derivation() {
  let hash = derive_device_hash(SERIAL);
  assert_eq!(hash, EXPECTED_DEVICE_HASH);
}

#[test]
fn test_nonce_construction() {
  let nonce = tagotip_secure::nonce::construct_nonce(
    CipherSuite::Aes128Ccm,
    EXPECTED_FLAGS,
    &EXPECTED_DEVICE_HASH,
    COUNTER,
  );
  assert_eq!(nonce.as_slice(), &EXPECTED_NONCE);
}

#[test]
fn test_header_serialization() {
  let header = tagotip_secure::EnvelopeHeader {
    flags: EXPECTED_FLAGS,
    counter: COUNTER,
    auth_hash: EXPECTED_AUTH_HASH,
    device_hash: EXPECTED_DEVICE_HASH,
  };
  assert_eq!(header.to_bytes(), EXPECTED_AAD);
}

#[test]
fn test_inner_frame_bytes() {
  let mut variables = InlineVec::new();
  let _ = variables.push(Variable {
    name: "temp",
    operator: Operator::Number,
    value: Value::Number("32"),
    unit: None,
    timestamp: None,
    group: None,
    meta: None,
  });

  let frame = HeadlessFrame {
    serial: SERIAL,
    push_body: Some(PushBody::Structured(StructuredBody {
      group: None,
      timestamp: None,
      body_meta: None,
      variables,
      meta_pool: InlineVec::new(),
    })),
    pull_body: None,
  };

  let mut buf = [0u8; 256];
  let n = tagotip_codec::build::build_headless(Method::Push, &frame, &mut buf).unwrap();
  assert_eq!(&buf[..n], EXPECTED_INNER_FRAME);
}

#[test]
fn test_seal_produces_spec_envelope() {
  let auth_hash = derive_auth_hash(TOKEN);

  let mut variables = InlineVec::new();
  let _ = variables.push(Variable {
    name: "temp",
    operator: Operator::Number,
    value: Value::Number("32"),
    unit: None,
    timestamp: None,
    group: None,
    meta: None,
  });

  let frame = HeadlessFrame {
    serial: SERIAL,
    push_body: Some(PushBody::Structured(StructuredBody {
      group: None,
      timestamp: None,
      body_meta: None,
      variables,
      meta_pool: InlineVec::new(),
    })),
    pull_body: None,
  };

  let envelope =
    seal_uplink(Method::Push, &frame, COUNTER, auth_hash, &ENCRYPTION_KEY, CipherSuite::Aes128Ccm)
      .unwrap();

  // Verify total size
  assert_eq!(envelope.len(), 49, "envelope should be exactly 49 bytes");

  // Verify header (AAD) bytes
  assert_eq!(&envelope[..21], &EXPECTED_AAD, "header (AAD) mismatch");

  // Verify ciphertext bytes
  assert_eq!(&envelope[21..41], &EXPECTED_CIPHERTEXT, "ciphertext mismatch");

  // Verify auth tag bytes
  assert_eq!(&envelope[41..49], &EXPECTED_AUTH_TAG, "auth tag mismatch");

  // Verify complete envelope byte-for-byte
  assert_eq!(envelope.as_slice(), &EXPECTED_ENVELOPE, "full envelope mismatch");
}

#[test]
fn test_open_spec_envelope() {
  let (header, method, plaintext) = open_envelope(&EXPECTED_ENVELOPE, &ENCRYPTION_KEY).unwrap();

  assert_eq!(header.flags, EXPECTED_FLAGS);
  assert_eq!(header.counter, COUNTER);
  assert_eq!(header.auth_hash, EXPECTED_AUTH_HASH);
  assert_eq!(header.device_hash, EXPECTED_DEVICE_HASH);
  assert_eq!(method, tagotip_secure::EnvelopeMethod::Push);
  assert_eq!(plaintext, EXPECTED_INNER_FRAME);
}

#[test]
fn test_parse_header_spec_envelope() {
  let header = parse_envelope_header(&EXPECTED_ENVELOPE).unwrap();
  assert_eq!(header.flags, EXPECTED_FLAGS);
  assert_eq!(header.counter, COUNTER);
  assert_eq!(header.auth_hash, EXPECTED_AUTH_HASH);
  assert_eq!(header.device_hash, EXPECTED_DEVICE_HASH);
}

#[test]
fn test_is_envelope_spec() {
  assert!(is_envelope(&EXPECTED_ENVELOPE));
  assert!(!is_envelope(b"ACK|OK|3")); // Starts with 'A' = 0x41
}

#[test]
fn test_round_trip_with_parse_headless() {
  let (_, method, plaintext) = open_envelope(&EXPECTED_ENVELOPE, &ENCRYPTION_KEY).unwrap();
  let codec_method = method.to_codec_method().unwrap();
  let inner_str = core::str::from_utf8(&plaintext).unwrap();
  let frame = tagotip_codec::parse::parse_headless(codec_method, inner_str).unwrap();

  assert_eq!(frame.serial, SERIAL);
  let push_body = frame.push_body.unwrap();
  if let PushBody::Structured(structured) = push_body {
    assert_eq!(structured.variables.len(), 1);
    let var = &structured.variables.as_slice()[0];
    assert_eq!(var.name, "temp");
    assert_eq!(var.operator, Operator::Number);
    assert_eq!(var.value, Value::Number("32"));
  } else {
    panic!("expected structured push body");
  }
}

use tagotip_codec::inline_vec::InlineVec;
use tagotip_codec::types::{
  AckDetail, AckFrame, AckStatus, HeadlessFrame, Method, Operator, PullBody, PushBody,
  StructuredBody, Value, Variable,
};
use tagotip_secure::{
  CipherSuite, EnvelopeMethod, derive_auth_hash, derive_device_hash, open_envelope,
  seal_downlink, seal_uplink,
};

const TOKEN: &str = "ate2bd319014b24e0a8aca9f00aea4c0d0";
const SERIAL: &str = "sensor-01";
const KEY_16: [u8; 16] = [
  0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee, 0x12, 0xab, 0x56, 0xcd, 0x78, 0xef, 0x90,
  0x12,
];
#[cfg(any(
  feature = "aes-256-ccm",
  feature = "aes-256-gcm",
  feature = "chacha20-poly1305"
))]
const KEY_32: [u8; 32] = [
  0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee, 0x12, 0xab, 0x56, 0xcd, 0x78, 0xef, 0x90,
  0x12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
  0x0f, 0x10,
];

fn make_push_frame() -> HeadlessFrame<'static> {
  let mut variables = InlineVec::new();
  let _ = variables.push(Variable {
    name: "temperature",
    operator: Operator::Number,
    value: Value::Number("32.5"),
    unit: Some("C"),
    timestamp: None,
    group: None,
    meta: None,
  });
  let _ = variables.push(Variable {
    name: "humidity",
    operator: Operator::Number,
    value: Value::Number("65"),
    unit: Some("%"),
    timestamp: None,
    group: None,
    meta: None,
  });

  HeadlessFrame {
    serial: SERIAL,
    push_body: Some(PushBody::Structured(StructuredBody {
      group: None,
      timestamp: None,
      body_meta: None,
      variables,
      meta_pool: InlineVec::new(),
    })),
    pull_body: None,
  }
}

fn make_pull_frame() -> HeadlessFrame<'static> {
  let mut variables = InlineVec::new();
  let _ = variables.push("temperature");
  let _ = variables.push("humidity");

  HeadlessFrame {
    serial: SERIAL,
    push_body: None,
    pull_body: Some(PullBody { variables }),
  }
}

fn make_ping_frame() -> HeadlessFrame<'static> {
  HeadlessFrame {
    serial: SERIAL,
    push_body: None,
    pull_body: None,
  }
}

/// Helper to test round-trip for uplink with a given cipher suite.
fn test_uplink_round_trip(method: Method, frame: &HeadlessFrame<'_>, suite: CipherSuite, key: &[u8]) {
  let auth_hash = derive_auth_hash(TOKEN);
  let counter = 100;

  let envelope = seal_uplink(method, frame, counter, auth_hash, key, suite).unwrap();
  let (header, env_method, plaintext) = open_envelope(&envelope, key).unwrap();

  assert_eq!(header.counter, counter);
  assert_eq!(header.auth_hash, auth_hash);
  assert_eq!(env_method, EnvelopeMethod::from(method));

  // Parse the inner frame back
  let codec_method = env_method.to_codec_method().unwrap();
  let inner_str = core::str::from_utf8(&plaintext).unwrap();
  let parsed = tagotip_codec::parse::parse_headless(codec_method, inner_str).unwrap();
  assert_eq!(parsed.serial, frame.serial);
}

// ---------------------------------------------------------------------------
// AES-128-CCM (default)
// ---------------------------------------------------------------------------

#[test]
fn test_aes128_ccm_push() {
  let frame = make_push_frame();
  test_uplink_round_trip(Method::Push, &frame, CipherSuite::Aes128Ccm, &KEY_16);
}

#[test]
fn test_aes128_ccm_pull() {
  let frame = make_pull_frame();
  test_uplink_round_trip(Method::Pull, &frame, CipherSuite::Aes128Ccm, &KEY_16);
}

#[test]
fn test_aes128_ccm_ping() {
  let frame = make_ping_frame();
  test_uplink_round_trip(Method::Ping, &frame, CipherSuite::Aes128Ccm, &KEY_16);
}

#[test]
fn test_aes128_ccm_ack_ok() {
  let auth_hash = derive_auth_hash(TOKEN);
  let device_hash = derive_device_hash(SERIAL);

  let ack = AckFrame {
    seq: None,
    status: AckStatus::Ok,
    detail: Some(AckDetail::Count(5)),
  };

  let envelope = seal_downlink(&ack, 1, auth_hash, device_hash, &KEY_16, CipherSuite::Aes128Ccm).unwrap();
  let (_, method, plaintext) = open_envelope(&envelope, &KEY_16).unwrap();

  assert_eq!(method, EnvelopeMethod::Ack);
  let inner_str = core::str::from_utf8(&plaintext).unwrap();
  let parsed = tagotip_codec::parse::parse_ack_inner(inner_str).unwrap();
  assert_eq!(parsed.status, AckStatus::Ok);
  assert_eq!(parsed.detail, Some(AckDetail::Count(5)));
}

#[test]
fn test_aes128_ccm_ack_pong() {
  let auth_hash = derive_auth_hash(TOKEN);
  let device_hash = derive_device_hash(SERIAL);

  let ack = AckFrame {
    seq: None,
    status: AckStatus::Pong,
    detail: None,
  };

  let envelope = seal_downlink(&ack, 2, auth_hash, device_hash, &KEY_16, CipherSuite::Aes128Ccm).unwrap();
  let (_, method, plaintext) = open_envelope(&envelope, &KEY_16).unwrap();

  assert_eq!(method, EnvelopeMethod::Ack);
  let inner_str = core::str::from_utf8(&plaintext).unwrap();
  let parsed = tagotip_codec::parse::parse_ack_inner(inner_str).unwrap();
  assert_eq!(parsed.status, AckStatus::Pong);
  assert_eq!(parsed.detail, None);
}

#[test]
fn test_aes128_ccm_ack_cmd() {
  let auth_hash = derive_auth_hash(TOKEN);
  let device_hash = derive_device_hash(SERIAL);

  let ack = AckFrame {
    seq: None,
    status: AckStatus::Cmd,
    detail: Some(AckDetail::Command("ota=https://example.com/v2.1.bin")),
  };

  let envelope = seal_downlink(&ack, 3, auth_hash, device_hash, &KEY_16, CipherSuite::Aes128Ccm).unwrap();
  let (_, method, plaintext) = open_envelope(&envelope, &KEY_16).unwrap();

  assert_eq!(method, EnvelopeMethod::Ack);
  let inner_str = core::str::from_utf8(&plaintext).unwrap();
  let parsed = tagotip_codec::parse::parse_ack_inner(inner_str).unwrap();
  assert_eq!(parsed.status, AckStatus::Cmd);
  assert_eq!(parsed.detail, Some(AckDetail::Command("ota=https://example.com/v2.1.bin")));
}

#[test]
fn test_aes128_ccm_ack_err() {
  let auth_hash = derive_auth_hash(TOKEN);
  let device_hash = derive_device_hash(SERIAL);

  let ack = AckFrame {
    seq: None,
    status: AckStatus::Err,
    detail: Some(AckDetail::Error {
      code: tagotip_codec::types::ErrorCode::InvalidToken,
      text: "invalid_token",
    }),
  };

  let envelope = seal_downlink(&ack, 4, auth_hash, device_hash, &KEY_16, CipherSuite::Aes128Ccm).unwrap();
  let (_, method, plaintext) = open_envelope(&envelope, &KEY_16).unwrap();

  assert_eq!(method, EnvelopeMethod::Ack);
  let inner_str = core::str::from_utf8(&plaintext).unwrap();
  let parsed = tagotip_codec::parse::parse_ack_inner(inner_str).unwrap();
  assert_eq!(parsed.status, AckStatus::Err);
}

// ---------------------------------------------------------------------------
// AES-128-GCM
// ---------------------------------------------------------------------------

#[cfg(feature = "aes-128-gcm")]
#[test]
fn test_aes128_gcm_push() {
  let frame = make_push_frame();
  test_uplink_round_trip(Method::Push, &frame, CipherSuite::Aes128Gcm, &KEY_16);
}

#[cfg(feature = "aes-128-gcm")]
#[test]
fn test_aes128_gcm_ack() {
  let auth_hash = derive_auth_hash(TOKEN);
  let device_hash = derive_device_hash(SERIAL);

  let ack = AckFrame {
    seq: None,
    status: AckStatus::Ok,
    detail: Some(AckDetail::Count(1)),
  };

  let envelope = seal_downlink(&ack, 1, auth_hash, device_hash, &KEY_16, CipherSuite::Aes128Gcm).unwrap();
  let (_, method, plaintext) = open_envelope(&envelope, &KEY_16).unwrap();
  assert_eq!(method, EnvelopeMethod::Ack);
  let inner_str = core::str::from_utf8(&plaintext).unwrap();
  assert_eq!(inner_str, "OK|1");
}

// ---------------------------------------------------------------------------
// AES-256-CCM
// ---------------------------------------------------------------------------

#[cfg(feature = "aes-256-ccm")]
#[test]
fn test_aes256_ccm_push() {
  let frame = make_push_frame();
  test_uplink_round_trip(Method::Push, &frame, CipherSuite::Aes256Ccm, &KEY_32);
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

#[cfg(feature = "aes-256-gcm")]
#[test]
fn test_aes256_gcm_push() {
  let frame = make_push_frame();
  test_uplink_round_trip(Method::Push, &frame, CipherSuite::Aes256Gcm, &KEY_32);
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305
// ---------------------------------------------------------------------------

#[cfg(feature = "chacha20-poly1305")]
#[test]
fn test_chacha20_poly1305_push() {
  let frame = make_push_frame();
  test_uplink_round_trip(Method::Push, &frame, CipherSuite::ChaCha20Poly1305, &KEY_32);
}

#[cfg(feature = "chacha20-poly1305")]
#[test]
fn test_chacha20_poly1305_ack() {
  let auth_hash = derive_auth_hash(TOKEN);
  let device_hash = derive_device_hash(SERIAL);

  let ack = AckFrame {
    seq: None,
    status: AckStatus::Pong,
    detail: None,
  };

  let envelope =
    seal_downlink(&ack, 1, auth_hash, device_hash, &KEY_32, CipherSuite::ChaCha20Poly1305)
      .unwrap();
  let (_, method, plaintext) = open_envelope(&envelope, &KEY_32).unwrap();
  assert_eq!(method, EnvelopeMethod::Ack);
  let inner_str = core::str::from_utf8(&plaintext).unwrap();
  assert_eq!(inner_str, "PONG");
}

// ---------------------------------------------------------------------------
// Envelope size verification
// ---------------------------------------------------------------------------

#[test]
fn test_envelope_overhead_ccm() {
  let frame = make_ping_frame();
  let auth_hash = derive_auth_hash(TOKEN);

  let envelope = seal_uplink(Method::Ping, &frame, 1, auth_hash, &KEY_16, CipherSuite::Aes128Ccm).unwrap();
  // PING inner frame = "sensor-01" = 9 bytes
  // Envelope = 21 (header) + 9 (ciphertext) + 8 (CCM tag) = 38 bytes
  assert_eq!(envelope.len(), 21 + 9 + 8);
}

#[cfg(feature = "aes-128-gcm")]
#[test]
fn test_envelope_overhead_gcm() {
  let frame = make_ping_frame();
  let auth_hash = derive_auth_hash(TOKEN);

  let envelope = seal_uplink(Method::Ping, &frame, 1, auth_hash, &KEY_16, CipherSuite::Aes128Gcm).unwrap();
  // PING inner frame = "sensor-01" = 9 bytes
  // Envelope = 21 (header) + 9 (ciphertext) + 16 (GCM tag) = 46 bytes
  assert_eq!(envelope.len(), 21 + 9 + 16);
}

use alloc::vec::Vec;

use tagotip_codec::{AckFrame, HeadlessFrame, Method, build};

use crate::cipher::{aead_decrypt, aead_encrypt};
use crate::consts::{HEADER_SIZE, MAX_INNER_FRAME_SIZE, RESERVED_FLAGS_VALUE};
use crate::error::CryptoError;
use crate::hash::derive_device_hash;
use crate::nonce::construct_nonce;
use crate::types::{CipherSuite, EnvelopeHeader, EnvelopeMethod, Flags};

/// Check if a message is a TagoTiP/S envelope or a plaintext fallback.
///
/// Returns `true` if the first byte is NOT `0x41` (ASCII `A`).
/// An empty message returns `false`.
#[must_use]
pub fn is_envelope(data: &[u8]) -> bool {
    match data.first() {
        Some(&b) => b != RESERVED_FLAGS_VALUE,
        None => false,
    }
}

/// Parse just the 21-byte envelope header for server-side routing (key lookup before decryption).
pub fn parse_envelope_header(envelope: &[u8]) -> Result<EnvelopeHeader, CryptoError> {
    if envelope.len() < HEADER_SIZE {
        return Err(CryptoError::envelope_too_short());
    }
    let header = EnvelopeHeader::from_bytes(envelope)?;
    // Validate the flags byte
    Flags::decode(header.flags)?;
    Ok(header)
}

/// Encrypt a `HeadlessFrame` into a TagoTiP/S uplink envelope.
pub fn seal_uplink(
    method: Method,
    frame: &HeadlessFrame<'_>,
    counter: u32,
    auth_hash: [u8; 8],
    encryption_key: &[u8],
    cipher_suite: CipherSuite,
) -> Result<Vec<u8>, CryptoError> {
    // Build the headless inner frame into bytes.
    let mut buf = [0u8; MAX_INNER_FRAME_SIZE];
    let n = build::build_headless(method, frame, &mut buf)
        .map_err(|_| CryptoError::new(crate::error::CryptoErrorKind::InnerFrameTooLarge))?;
    let inner_frame = &buf[..n];

    // Derive device hash from the serial in the frame.
    let device_hash = derive_device_hash(frame.serial);
    let envelope_method = EnvelopeMethod::from(method);

    seal_raw(
        inner_frame,
        envelope_method,
        counter,
        auth_hash,
        device_hash,
        encryption_key,
        cipher_suite,
    )
}

/// Encrypt an `AckFrame` into a TagoTiP/S downlink envelope.
pub fn seal_downlink(
    ack: &AckFrame<'_>,
    counter: u32,
    auth_hash: [u8; 8],
    device_hash: [u8; 8],
    encryption_key: &[u8],
    cipher_suite: CipherSuite,
) -> Result<Vec<u8>, CryptoError> {
    // Build the ACK inner frame (STATUS[|DETAIL], no ACK| prefix).
    let mut buf = [0u8; MAX_INNER_FRAME_SIZE];
    let n = tagotip_codec::build::build_ack_inner(ack, &mut buf)
        .map_err(|_| CryptoError::new(crate::error::CryptoErrorKind::InnerFrameTooLarge))?;
    let inner_frame = &buf[..n];

    seal_raw(
        inner_frame,
        EnvelopeMethod::Ack,
        counter,
        auth_hash,
        device_hash,
        encryption_key,
        cipher_suite,
    )
}

/// Encrypt raw inner frame bytes into a TagoTiP/S envelope.
pub fn seal_raw(
    inner_frame: &[u8],
    method: EnvelopeMethod,
    counter: u32,
    auth_hash: [u8; 8],
    device_hash: [u8; 8],
    encryption_key: &[u8],
    cipher_suite: CipherSuite,
) -> Result<Vec<u8>, CryptoError> {
    if inner_frame.len() > MAX_INNER_FRAME_SIZE {
        return Err(CryptoError::inner_frame_too_large());
    }

    if encryption_key.len() != cipher_suite.key_size() {
        return Err(CryptoError::invalid_key_size());
    }

    let flags = Flags::encode(cipher_suite, 0, method)?;

    let header = EnvelopeHeader {
        flags,
        counter,
        auth_hash,
        device_hash,
    };
    let aad = header.to_bytes();

    let nonce = construct_nonce(cipher_suite, flags, &device_hash, counter);

    let ciphertext_with_tag =
        aead_encrypt(cipher_suite, encryption_key, &nonce, &aad, inner_frame)?;

    // Check envelope size limit.
    let envelope_size = HEADER_SIZE + ciphertext_with_tag.len();
    let max_envelope_size = MAX_INNER_FRAME_SIZE + HEADER_SIZE + cipher_suite.tag_size();
    if envelope_size > max_envelope_size {
        return Err(CryptoError::envelope_too_large());
    }

    let mut envelope = Vec::with_capacity(envelope_size);
    envelope.extend_from_slice(&aad);
    envelope.extend_from_slice(&ciphertext_with_tag);

    Ok(envelope)
}

/// Decrypt a TagoTiP/S envelope.
///
/// Returns `(header, method, inner_frame_bytes)`.
/// The caller uses the method to know how to parse the inner frame:
///   - Push/Pull/Ping -> `parse_headless(method, str)`
///   - Ack -> `parse_ack_inner(str)`
pub fn open_envelope(
    envelope: &[u8],
    encryption_key: &[u8],
) -> Result<(EnvelopeHeader, EnvelopeMethod, Vec<u8>), CryptoError> {
    let header = parse_envelope_header(envelope)?;
    let (cipher, version, method) = Flags::decode(header.flags)?;

    if version != 0 {
        return Err(CryptoError::unsupported_version());
    }

    if encryption_key.len() != cipher.key_size() {
        return Err(CryptoError::invalid_key_size());
    }

    let ciphertext_with_tag = &envelope[HEADER_SIZE..];
    if ciphertext_with_tag.len() < cipher.tag_size() {
        return Err(CryptoError::envelope_too_short());
    }

    let aad = &envelope[..HEADER_SIZE];
    let nonce = construct_nonce(cipher, header.flags, &header.device_hash, header.counter);

    let plaintext = aead_decrypt(cipher, encryption_key, &nonce, aad, ciphertext_with_tag)?;

    Ok((header, method, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::derive_auth_hash;
    use tagotip_codec::types::{AckDetail, AckStatus};

    #[test]
    fn test_is_envelope() {
        assert!(is_envelope(&[0x00, 0x01, 0x02])); // Starts with 0x00
        assert!(!is_envelope(&[0x41, 0x43, 0x4B])); // Starts with 'A' (ACK)
        assert!(!is_envelope(&[])); // Empty
    }

    #[test]
    #[cfg(feature = "aes-128-ccm")]
    fn test_seal_open_uplink_push() {
        let auth_hash = derive_auth_hash("ate2bd319014b24e0a8aca9f00aea4c0d0");
        let key: [u8; 16] = [
            0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee, 0x12, 0xab, 0x56, 0xcd, 0x78, 0xef,
            0x90, 0x12,
        ];

        let frame = HeadlessFrame {
            serial: "sensor-01",
            push_body: None,
            pull_body: None,
        };

        let envelope = seal_uplink(
            Method::Ping,
            &frame,
            42,
            auth_hash,
            &key,
            CipherSuite::Aes128Ccm,
        )
        .unwrap();

        let (header, method, plaintext) = open_envelope(&envelope, &key).unwrap();
        assert_eq!(method, EnvelopeMethod::Ping);
        assert_eq!(header.counter, 42);
        assert_eq!(header.auth_hash, auth_hash);

        let inner_str = core::str::from_utf8(&plaintext).unwrap();
        assert_eq!(inner_str, "sensor-01");
    }

    #[test]
    #[cfg(feature = "aes-128-ccm")]
    fn test_seal_open_downlink_ack() {
        let auth_hash = derive_auth_hash("ate2bd319014b24e0a8aca9f00aea4c0d0");
        let device_hash = crate::hash::derive_device_hash("sensor-01");
        let key: [u8; 16] = [
            0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee, 0x12, 0xab, 0x56, 0xcd, 0x78, 0xef,
            0x90, 0x12,
        ];

        let ack = AckFrame {
            seq: None,
            status: AckStatus::Ok,
            detail: Some(AckDetail::Count(3)),
        };

        let envelope = seal_downlink(
            &ack,
            1,
            auth_hash,
            device_hash,
            &key,
            CipherSuite::Aes128Ccm,
        )
        .unwrap();

        let (header, method, plaintext) = open_envelope(&envelope, &key).unwrap();
        assert_eq!(method, EnvelopeMethod::Ack);
        assert_eq!(header.counter, 1);

        let inner_str = core::str::from_utf8(&plaintext).unwrap();
        assert_eq!(inner_str, "OK|3");
    }

    #[test]
    #[cfg(feature = "aes-128-ccm")]
    fn test_wrong_key_fails() {
        let auth_hash = derive_auth_hash("ate2bd319014b24e0a8aca9f00aea4c0d0");
        let key: [u8; 16] = [
            0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee, 0x12, 0xab, 0x56, 0xcd, 0x78, 0xef,
            0x90, 0x12,
        ];
        let wrong_key: [u8; 16] = [0x00; 16];

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
            &key,
            CipherSuite::Aes128Ccm,
        )
        .unwrap();

        let result = open_envelope(&envelope, &wrong_key);
        assert_eq!(
            result.unwrap_err().kind,
            crate::error::CryptoErrorKind::DecryptionFailed
        );
    }
}

use alloc::string::String;
use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::consts::AUTH_HASH_SIZE;

/// Derive the Authorization Hash from an authorization token.
///
/// The token format is `at` + 32 hex chars. The `at` prefix is stripped,
/// and SHA-256 is computed over the remaining hex string (UTF-8 encoded).
/// Returns the first 8 bytes of the digest.
#[must_use]
pub fn derive_auth_hash(token: &str) -> [u8; AUTH_HASH_SIZE] {
    let hex_part = token.strip_prefix("at").unwrap_or(token);
    let digest = Sha256::digest(hex_part.as_bytes());
    let mut hash = [0u8; AUTH_HASH_SIZE];
    hash.copy_from_slice(&digest[..AUTH_HASH_SIZE]);
    hash
}

/// Derive the Device Hash from a device serial number.
///
/// Computes SHA-256 of the serial (UTF-8 encoded) and returns the first 8 bytes.
#[must_use]
pub fn derive_device_hash(serial: &str) -> [u8; AUTH_HASH_SIZE] {
    let digest = Sha256::digest(serial.as_bytes());
    let mut hash = [0u8; AUTH_HASH_SIZE];
    hash.copy_from_slice(&digest[..AUTH_HASH_SIZE]);
    hash
}

/// Derive an encryption key from an authorization token and device serial
/// using HMAC-SHA256.
///
/// The `at` prefix is stripped from the token; the remaining hex string
/// (UTF-8 encoded) is used as the HMAC key. The serial (UTF-8 encoded)
/// is used as the HMAC message. Returns the full 32-byte HMAC-SHA256
/// output; callers should slice to the cipher suite's key size
/// (e.g., `&result[..16]` for AES-128).
#[must_use]
pub fn derive_key(token: &str, serial: &str) -> [u8; 32] {
    let hex_part = token.strip_prefix("at").unwrap_or(token);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(hex_part.as_bytes()).expect("HMAC accepts any key length");
    mac.update(serial.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Decode a hex string into bytes.
///
/// Returns `None` if the string has odd length or contains non-hex characters.
#[must_use]
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.as_bytes();
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.chunks_exact(2) {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Encode bytes as a lowercase hex string.
#[must_use]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_auth_hash_spec_vector() {
        // From spec section 11.1
        let token = "ate2bd319014b24e0a8aca9f00aea4c0d0";
        let hash = derive_auth_hash(token);
        assert_eq!(hash, [0x4d, 0xee, 0xdd, 0x7b, 0xab, 0x88, 0x17, 0xec]);
    }

    #[test]
    fn test_derive_device_hash_spec_vector() {
        // From spec section 11.1
        let hash = derive_device_hash("sensor-01");
        assert_eq!(hash, [0xab, 0x77, 0x88, 0xd2, 0x2e, 0xb7, 0x37, 0x2f]);
    }

    #[test]
    fn test_derive_key_spec_vector() {
        let token = "ate2bd319014b24e0a8aca9f00aea4c0d0";
        let serial = "sensor-01";
        let key = derive_key(token, serial);
        #[rustfmt::skip]
        let expected: [u8; 32] = [
            0xe5, 0x05, 0xf0, 0x3c, 0xc9, 0xe9, 0x3f, 0xdb,
            0xcc, 0x38, 0x28, 0x44, 0xcc, 0xa3, 0xe1, 0x7f,
            0xdf, 0x0b, 0xb3, 0x13, 0x18, 0x58, 0x53, 0x95,
            0xce, 0xaa, 0xa3, 0x9a, 0x5d, 0x14, 0x19, 0x64,
        ];
        assert_eq!(key, expected);
    }

    #[test]
    fn test_derive_key_without_prefix() {
        let key_with = derive_key("ate2bd319014b24e0a8aca9f00aea4c0d0", "sensor-01");
        let key_without = derive_key("e2bd319014b24e0a8aca9f00aea4c0d0", "sensor-01");
        assert_eq!(key_with, key_without);
    }

    #[test]
    fn test_hex_to_bytes_round_trip() {
        let original = &[0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee];
        let hex = bytes_to_hex(original);
        assert_eq!(hex, "fe09da81bc4400ee");
        let decoded = hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded.as_slice(), original);
    }

    #[test]
    fn test_hex_to_bytes_rejects_odd_length() {
        assert!(hex_to_bytes("abc").is_none());
    }

    #[test]
    fn test_hex_to_bytes_rejects_non_hex() {
        assert!(hex_to_bytes("zz00").is_none());
    }

    #[test]
    fn test_hex_to_bytes_empty() {
        assert_eq!(hex_to_bytes("").unwrap(), alloc::vec![]);
    }

    #[test]
    fn test_hex_to_bytes_uppercase() {
        let result = hex_to_bytes("AABB").unwrap();
        assert_eq!(result, alloc::vec![0xaa, 0xbb]);
    }

    #[test]
    fn test_derive_auth_hash_without_prefix() {
        // Should also work if token is passed without "at" prefix
        let hash = derive_auth_hash("e2bd319014b24e0a8aca9f00aea4c0d0");
        assert_eq!(hash, [0x4d, 0xee, 0xdd, 0x7b, 0xab, 0x88, 0x17, 0xec]);
    }
}

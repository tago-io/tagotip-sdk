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
    fn test_derive_auth_hash_without_prefix() {
        // Should also work if token is passed without "at" prefix
        let hash = derive_auth_hash("e2bd319014b24e0a8aca9f00aea4c0d0");
        assert_eq!(hash, [0x4d, 0xee, 0xdd, 0x7b, 0xab, 0x88, 0x17, 0xec]);
    }
}

use alloc::vec::Vec;

use crate::types::CipherSuite;

/// Construct the AEAD nonce from envelope fields.
///
/// CCM (13 bytes): `[Flags:1] [0x00 x4] [DeviceHash[:4]:4] [Counter:4]`
/// GCM/ChaCha (12 bytes): `[Flags:1] [0x00 x3] [DeviceHash[:4]:4] [Counter:4]`
#[must_use]
pub fn construct_nonce(
  suite: CipherSuite,
  flags: u8,
  device_hash: &[u8; 8],
  counter: u32,
) -> Vec<u8> {
  let nonce_size = suite.nonce_size();
  let mut nonce = alloc::vec![0u8; nonce_size];

  nonce[0] = flags;
  // Zero-padding is already set by the vec! initialization.
  // Device hash first 4 bytes start at offset (nonce_size - 8).
  let dh_offset = nonce_size - 8;
  nonce[dh_offset..dh_offset + 4].copy_from_slice(&device_hash[..4]);
  // Counter as big-endian u32 in the last 4 bytes.
  nonce[nonce_size - 4..].copy_from_slice(&counter.to_be_bytes());

  nonce
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_nonce_ccm_spec_vector() {
    // From spec section 11.1
    let device_hash: [u8; 8] = [0xab, 0x77, 0x88, 0xd2, 0x2e, 0xb7, 0x37, 0x2f];
    let nonce = construct_nonce(CipherSuite::Aes128Ccm, 0x00, &device_hash, 42);
    assert_eq!(nonce.len(), 13);
    assert_eq!(
      nonce.as_slice(),
      &[0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0x77, 0x88, 0xd2, 0x00, 0x00, 0x00, 0x2a]
    );
  }

  #[test]
  fn test_nonce_gcm() {
    let device_hash: [u8; 8] = [0xab, 0x77, 0x88, 0xd2, 0x2e, 0xb7, 0x37, 0x2f];
    let nonce = construct_nonce(CipherSuite::Aes128Gcm, 0x08, &device_hash, 1);
    assert_eq!(nonce.len(), 12);
    // [flags:1] [00 00 00] [dev_hash[:4]:4] [counter:4]
    assert_eq!(
      nonce.as_slice(),
      &[0x08, 0x00, 0x00, 0x00, 0xab, 0x77, 0x88, 0xd2, 0x00, 0x00, 0x00, 0x01]
    );
  }

  #[test]
  fn test_nonce_chacha20() {
    let device_hash: [u8; 8] = [0xab, 0x77, 0x88, 0xd2, 0x2e, 0xb7, 0x37, 0x2f];
    let nonce = construct_nonce(CipherSuite::ChaCha20Poly1305, 0x80, &device_hash, 1);
    assert_eq!(nonce.len(), 12);
    assert_eq!(
      nonce.as_slice(),
      &[0x80, 0x00, 0x00, 0x00, 0xab, 0x77, 0x88, 0xd2, 0x00, 0x00, 0x00, 0x01]
    );
  }
}

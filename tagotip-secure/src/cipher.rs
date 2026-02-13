use alloc::vec::Vec;

use crate::error::CryptoError;
use crate::types::CipherSuite;

/// Encrypt plaintext using the specified AEAD cipher suite.
///
/// Returns ciphertext + authentication tag concatenated.
pub fn aead_encrypt(
  suite: CipherSuite,
  key: &[u8],
  nonce: &[u8],
  aad: &[u8],
  plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  if key.len() != suite.key_size() {
    return Err(CryptoError::invalid_key_size());
  }
  match suite {
    CipherSuite::Aes128Ccm => encrypt_aes128_ccm(key, nonce, aad, plaintext),
    CipherSuite::Aes128Gcm => encrypt_aes128_gcm(key, nonce, aad, plaintext),
    CipherSuite::Aes256Ccm => encrypt_aes256_ccm(key, nonce, aad, plaintext),
    CipherSuite::Aes256Gcm => encrypt_aes256_gcm(key, nonce, aad, plaintext),
    CipherSuite::ChaCha20Poly1305 => encrypt_chacha20_poly1305(key, nonce, aad, plaintext),
  }
}

/// Decrypt ciphertext + auth tag using the specified AEAD cipher suite.
///
/// Returns the decrypted plaintext.
pub fn aead_decrypt(
  suite: CipherSuite,
  key: &[u8],
  nonce: &[u8],
  aad: &[u8],
  ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  if key.len() != suite.key_size() {
    return Err(CryptoError::invalid_key_size());
  }
  match suite {
    CipherSuite::Aes128Ccm => decrypt_aes128_ccm(key, nonce, aad, ciphertext_with_tag),
    CipherSuite::Aes128Gcm => decrypt_aes128_gcm(key, nonce, aad, ciphertext_with_tag),
    CipherSuite::Aes256Ccm => decrypt_aes256_ccm(key, nonce, aad, ciphertext_with_tag),
    CipherSuite::Aes256Gcm => decrypt_aes256_gcm(key, nonce, aad, ciphertext_with_tag),
    CipherSuite::ChaCha20Poly1305 => decrypt_chacha20_poly1305(key, nonce, aad, ciphertext_with_tag),
  }
}

// ---------------------------------------------------------------------------
// AES-128-CCM
// ---------------------------------------------------------------------------

#[cfg(feature = "aes-128-ccm")]
fn encrypt_aes128_ccm(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
  use aes::Aes128;
  use ccm::aead::{Aead, KeyInit, Payload};
  use ccm::consts::{U13, U8};
  use ccm::Ccm;

  type Aes128Ccm = Ccm<Aes128, U8, U13>;

  let cipher =
    Aes128Ccm::new_from_slice(key).map_err(|_| CryptoError::invalid_key_size())?;
  let nonce = ccm::aead::generic_array::GenericArray::from_slice(nonce);
  let payload = Payload { msg: plaintext, aad };
  cipher
    .encrypt(nonce, payload)
    .map_err(|_| CryptoError::decryption_failed())
}

#[cfg(not(feature = "aes-128-ccm"))]
fn encrypt_aes128_ccm(_key: &[u8], _nonce: &[u8], _aad: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
  Err(CryptoError::cipher_not_enabled())
}

#[cfg(feature = "aes-128-ccm")]
fn decrypt_aes128_ccm(
  key: &[u8],
  nonce: &[u8],
  aad: &[u8],
  ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  use aes::Aes128;
  use ccm::aead::{Aead, KeyInit, Payload};
  use ccm::consts::{U13, U8};
  use ccm::Ccm;

  type Aes128Ccm = Ccm<Aes128, U8, U13>;

  let cipher =
    Aes128Ccm::new_from_slice(key).map_err(|_| CryptoError::invalid_key_size())?;
  let nonce = ccm::aead::generic_array::GenericArray::from_slice(nonce);
  let payload = Payload {
    msg: ciphertext_with_tag,
    aad,
  };
  cipher
    .decrypt(nonce, payload)
    .map_err(|_| CryptoError::decryption_failed())
}

#[cfg(not(feature = "aes-128-ccm"))]
fn decrypt_aes128_ccm(
  _key: &[u8],
  _nonce: &[u8],
  _aad: &[u8],
  _ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  Err(CryptoError::cipher_not_enabled())
}

// ---------------------------------------------------------------------------
// AES-128-GCM
// ---------------------------------------------------------------------------

#[cfg(feature = "aes-128-gcm")]
fn encrypt_aes128_gcm(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
  use aes_gcm::aead::{Aead, KeyInit, Payload};
  use aes_gcm::Aes128Gcm;

  let cipher =
    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::invalid_key_size())?;
  let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce);
  let payload = Payload { msg: plaintext, aad };
  cipher
    .encrypt(nonce, payload)
    .map_err(|_| CryptoError::decryption_failed())
}

#[cfg(not(feature = "aes-128-gcm"))]
fn encrypt_aes128_gcm(_key: &[u8], _nonce: &[u8], _aad: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
  Err(CryptoError::cipher_not_enabled())
}

#[cfg(feature = "aes-128-gcm")]
fn decrypt_aes128_gcm(
  key: &[u8],
  nonce: &[u8],
  aad: &[u8],
  ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  use aes_gcm::aead::{Aead, KeyInit, Payload};
  use aes_gcm::Aes128Gcm;

  let cipher =
    Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::invalid_key_size())?;
  let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce);
  let payload = Payload {
    msg: ciphertext_with_tag,
    aad,
  };
  cipher
    .decrypt(nonce, payload)
    .map_err(|_| CryptoError::decryption_failed())
}

#[cfg(not(feature = "aes-128-gcm"))]
fn decrypt_aes128_gcm(
  _key: &[u8],
  _nonce: &[u8],
  _aad: &[u8],
  _ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  Err(CryptoError::cipher_not_enabled())
}

// ---------------------------------------------------------------------------
// AES-256-CCM
// ---------------------------------------------------------------------------

#[cfg(feature = "aes-256-ccm")]
fn encrypt_aes256_ccm(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
  use aes::Aes256;
  use ccm::aead::{Aead, KeyInit, Payload};
  use ccm::consts::{U13, U8};
  use ccm::Ccm;

  type Aes256Ccm = Ccm<Aes256, U8, U13>;

  let cipher =
    Aes256Ccm::new_from_slice(key).map_err(|_| CryptoError::invalid_key_size())?;
  let nonce = ccm::aead::generic_array::GenericArray::from_slice(nonce);
  let payload = Payload { msg: plaintext, aad };
  cipher
    .encrypt(nonce, payload)
    .map_err(|_| CryptoError::decryption_failed())
}

#[cfg(not(feature = "aes-256-ccm"))]
fn encrypt_aes256_ccm(_key: &[u8], _nonce: &[u8], _aad: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
  Err(CryptoError::cipher_not_enabled())
}

#[cfg(feature = "aes-256-ccm")]
fn decrypt_aes256_ccm(
  key: &[u8],
  nonce: &[u8],
  aad: &[u8],
  ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  use aes::Aes256;
  use ccm::aead::{Aead, KeyInit, Payload};
  use ccm::consts::{U13, U8};
  use ccm::Ccm;

  type Aes256Ccm = Ccm<Aes256, U8, U13>;

  let cipher =
    Aes256Ccm::new_from_slice(key).map_err(|_| CryptoError::invalid_key_size())?;
  let nonce = ccm::aead::generic_array::GenericArray::from_slice(nonce);
  let payload = Payload {
    msg: ciphertext_with_tag,
    aad,
  };
  cipher
    .decrypt(nonce, payload)
    .map_err(|_| CryptoError::decryption_failed())
}

#[cfg(not(feature = "aes-256-ccm"))]
fn decrypt_aes256_ccm(
  _key: &[u8],
  _nonce: &[u8],
  _aad: &[u8],
  _ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  Err(CryptoError::cipher_not_enabled())
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

#[cfg(feature = "aes-256-gcm")]
fn encrypt_aes256_gcm(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
  use aes_gcm::aead::{Aead, KeyInit, Payload};
  use aes_gcm::Aes256Gcm;

  let cipher =
    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::invalid_key_size())?;
  let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce);
  let payload = Payload { msg: plaintext, aad };
  cipher
    .encrypt(nonce, payload)
    .map_err(|_| CryptoError::decryption_failed())
}

#[cfg(not(feature = "aes-256-gcm"))]
fn encrypt_aes256_gcm(_key: &[u8], _nonce: &[u8], _aad: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
  Err(CryptoError::cipher_not_enabled())
}

#[cfg(feature = "aes-256-gcm")]
fn decrypt_aes256_gcm(
  key: &[u8],
  nonce: &[u8],
  aad: &[u8],
  ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  use aes_gcm::aead::{Aead, KeyInit, Payload};
  use aes_gcm::Aes256Gcm;

  let cipher =
    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::invalid_key_size())?;
  let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce);
  let payload = Payload {
    msg: ciphertext_with_tag,
    aad,
  };
  cipher
    .decrypt(nonce, payload)
    .map_err(|_| CryptoError::decryption_failed())
}

#[cfg(not(feature = "aes-256-gcm"))]
fn decrypt_aes256_gcm(
  _key: &[u8],
  _nonce: &[u8],
  _aad: &[u8],
  _ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  Err(CryptoError::cipher_not_enabled())
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305
// ---------------------------------------------------------------------------

#[cfg(feature = "chacha20-poly1305")]
fn encrypt_chacha20_poly1305(
  key: &[u8],
  nonce: &[u8],
  aad: &[u8],
  plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  use chacha20poly1305::aead::{Aead, KeyInit, Payload};
  use chacha20poly1305::ChaCha20Poly1305;

  let cipher =
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::invalid_key_size())?;
  let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(nonce);
  let payload = Payload { msg: plaintext, aad };
  cipher
    .encrypt(nonce, payload)
    .map_err(|_| CryptoError::decryption_failed())
}

#[cfg(not(feature = "chacha20-poly1305"))]
fn encrypt_chacha20_poly1305(
  _key: &[u8],
  _nonce: &[u8],
  _aad: &[u8],
  _plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  Err(CryptoError::cipher_not_enabled())
}

#[cfg(feature = "chacha20-poly1305")]
fn decrypt_chacha20_poly1305(
  key: &[u8],
  nonce: &[u8],
  aad: &[u8],
  ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  use chacha20poly1305::aead::{Aead, KeyInit, Payload};
  use chacha20poly1305::ChaCha20Poly1305;

  let cipher =
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::invalid_key_size())?;
  let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(nonce);
  let payload = Payload {
    msg: ciphertext_with_tag,
    aad,
  };
  cipher
    .decrypt(nonce, payload)
    .map_err(|_| CryptoError::decryption_failed())
}

#[cfg(not(feature = "chacha20-poly1305"))]
fn decrypt_chacha20_poly1305(
  _key: &[u8],
  _nonce: &[u8],
  _aad: &[u8],
  _ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
  Err(CryptoError::cipher_not_enabled())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  #[cfg(feature = "aes-128-ccm")]
  fn test_aes128_ccm_round_trip() {
    let key = [0x01u8; 16];
    let nonce = [0x00u8; 13];
    let aad = b"header data";
    let plaintext = b"hello world";

    let encrypted = aead_encrypt(CipherSuite::Aes128Ccm, &key, &nonce, aad, plaintext).unwrap();
    assert_eq!(encrypted.len(), plaintext.len() + 8); // 8-byte tag

    let decrypted = aead_decrypt(CipherSuite::Aes128Ccm, &key, &nonce, aad, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
  }

  #[test]
  fn test_invalid_key_size() {
    let key = [0x01u8; 8]; // Wrong size
    let nonce = [0x00u8; 13];
    let result = aead_encrypt(CipherSuite::Aes128Ccm, &key, &nonce, b"", b"test");
    assert_eq!(result.unwrap_err().kind, crate::error::CryptoErrorKind::InvalidKeySize);
  }
}

use crate::consts::{
    AES_128_KEY_SIZE, AES_256_KEY_SIZE, AUTH_HASH_SIZE, CCM_NONCE_SIZE, CCM_TAG_SIZE, COUNTER_SIZE,
    DEVICE_HASH_SIZE, FLAGS_CIPHER_MASK, FLAGS_CIPHER_SHIFT, FLAGS_METHOD_MASK, FLAGS_SIZE,
    FLAGS_VERSION_MASK, FLAGS_VERSION_SHIFT, GCM_NONCE_SIZE, GCM_TAG_SIZE, HEADER_SIZE,
    RESERVED_FLAGS_VALUE,
};
use crate::error::CryptoError;
use tagotip_codec::Method;

/// AEAD cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// Suite 0: AES-128-CCM (16B key, 8B tag, 13B nonce).
    Aes128Ccm = 0,
    /// Suite 1: AES-128-GCM (16B key, 16B tag, 12B nonce).
    Aes128Gcm = 1,
    /// Suite 2: AES-256-CCM (32B key, 8B tag, 13B nonce).
    Aes256Ccm = 2,
    /// Suite 3: AES-256-GCM (32B key, 16B tag, 12B nonce).
    Aes256Gcm = 3,
    /// Suite 4: ChaCha20-Poly1305 (32B key, 16B tag, 12B nonce).
    ChaCha20Poly1305 = 4,
}

impl CipherSuite {
    /// Create from cipher suite ID. Returns error for unknown IDs.
    pub fn from_id(id: u8) -> Result<Self, CryptoError> {
        match id {
            0 => Ok(Self::Aes128Ccm),
            1 => Ok(Self::Aes128Gcm),
            2 => Ok(Self::Aes256Ccm),
            3 => Ok(Self::Aes256Gcm),
            4 => Ok(Self::ChaCha20Poly1305),
            _ => Err(CryptoError::unsupported_cipher()),
        }
    }

    /// Cipher suite ID (0-4).
    #[must_use]
    pub fn id(self) -> u8 {
        self as u8
    }

    /// Required encryption key size in bytes.
    #[must_use]
    pub fn key_size(self) -> usize {
        match self {
            Self::Aes128Ccm | Self::Aes128Gcm => AES_128_KEY_SIZE,
            Self::Aes256Ccm | Self::Aes256Gcm | Self::ChaCha20Poly1305 => AES_256_KEY_SIZE,
        }
    }

    /// Authentication tag size in bytes.
    #[must_use]
    pub fn tag_size(self) -> usize {
        match self {
            Self::Aes128Ccm | Self::Aes256Ccm => CCM_TAG_SIZE,
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305 => GCM_TAG_SIZE,
        }
    }

    /// Nonce size in bytes.
    #[must_use]
    pub fn nonce_size(self) -> usize {
        match self {
            Self::Aes128Ccm | Self::Aes256Ccm => CCM_NONCE_SIZE,
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305 => GCM_NONCE_SIZE,
        }
    }

    /// Check if the feature flag for this cipher suite is enabled.
    #[must_use]
    pub fn is_enabled(self) -> bool {
        match self {
            Self::Aes128Ccm => cfg!(feature = "aes-128-ccm"),
            Self::Aes128Gcm => cfg!(feature = "aes-128-gcm"),
            Self::Aes256Ccm => cfg!(feature = "aes-256-ccm"),
            Self::Aes256Gcm => cfg!(feature = "aes-256-gcm"),
            Self::ChaCha20Poly1305 => cfg!(feature = "chacha20-poly1305"),
        }
    }
}

/// Envelope method (extends tagotip-codec's Method with Ack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeMethod {
    /// PUSH (0) — send data to server.
    Push = 0,
    /// PULL (1) — retrieve data from server.
    Pull = 1,
    /// PING (2) — keepalive.
    Ping = 2,
    /// ACK (3) — downlink response.
    Ack = 3,
}

impl EnvelopeMethod {
    /// Create from method ID. Returns error for unknown IDs.
    pub fn from_id(id: u8) -> Result<Self, CryptoError> {
        match id {
            0 => Ok(Self::Push),
            1 => Ok(Self::Pull),
            2 => Ok(Self::Ping),
            3 => Ok(Self::Ack),
            _ => Err(CryptoError::invalid_method()),
        }
    }

    /// Method ID (0-3).
    #[must_use]
    pub fn id(self) -> u8 {
        self as u8
    }

    /// Convert to tagotip-codec Method. Fails for Ack.
    #[must_use]
    pub fn to_codec_method(self) -> Option<Method> {
        match self {
            Self::Push => Some(Method::Push),
            Self::Pull => Some(Method::Pull),
            Self::Ping => Some(Method::Ping),
            Self::Ack => None,
        }
    }
}

impl From<Method> for EnvelopeMethod {
    fn from(m: Method) -> Self {
        match m {
            Method::Push => Self::Push,
            Method::Pull => Self::Pull,
            Method::Ping => Self::Ping,
        }
    }
}

/// Flags byte encoder/decoder.
pub struct Flags;

impl Flags {
    /// Encode cipher suite, version, and method into a Flags byte.
    /// Returns error if the resulting byte is the reserved value 0x41.
    pub fn encode(
        cipher: CipherSuite,
        version: u8,
        method: EnvelopeMethod,
    ) -> Result<u8, CryptoError> {
        if version > 3 {
            return Err(CryptoError::unsupported_version());
        }
        let byte =
            (cipher.id() << FLAGS_CIPHER_SHIFT) | (version << FLAGS_VERSION_SHIFT) | method.id();
        if byte == RESERVED_FLAGS_VALUE {
            return Err(CryptoError::reserved_flags_value());
        }
        Ok(byte)
    }

    /// Decode a Flags byte into (cipher suite, version, method).
    pub fn decode(byte: u8) -> Result<(CipherSuite, u8, EnvelopeMethod), CryptoError> {
        if byte == RESERVED_FLAGS_VALUE {
            return Err(CryptoError::reserved_flags_value());
        }
        let cipher_id = (byte & FLAGS_CIPHER_MASK) >> FLAGS_CIPHER_SHIFT;
        let version = (byte & FLAGS_VERSION_MASK) >> FLAGS_VERSION_SHIFT;
        let method_id = byte & FLAGS_METHOD_MASK;

        let cipher = CipherSuite::from_id(cipher_id)?;
        let method = EnvelopeMethod::from_id(method_id)?;

        Ok((cipher, version, method))
    }
}

/// Parsed envelope header (first 21 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeHeader {
    /// Raw flags byte.
    pub flags: u8,
    /// Sequence counter (big-endian u32).
    pub counter: u32,
    /// Authorization Hash (first 8 bytes of SHA-256 of token without "at" prefix).
    pub auth_hash: [u8; AUTH_HASH_SIZE],
    /// Device Hash (first 8 bytes of SHA-256 of serial).
    pub device_hash: [u8; DEVICE_HASH_SIZE],
}

impl EnvelopeHeader {
    /// Serialize the header to a 21-byte array (used as AAD).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        let mut pos = 0;
        out[pos] = self.flags;
        pos += FLAGS_SIZE;
        out[pos..pos + COUNTER_SIZE].copy_from_slice(&self.counter.to_be_bytes());
        pos += COUNTER_SIZE;
        out[pos..pos + AUTH_HASH_SIZE].copy_from_slice(&self.auth_hash);
        pos += AUTH_HASH_SIZE;
        out[pos..pos + DEVICE_HASH_SIZE].copy_from_slice(&self.device_hash);
        out
    }

    /// Parse a header from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < HEADER_SIZE {
            return Err(CryptoError::envelope_too_short());
        }
        let flags = data[0];
        let counter = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let mut auth_hash = [0u8; AUTH_HASH_SIZE];
        auth_hash.copy_from_slice(&data[5..13]);
        let mut device_hash = [0u8; DEVICE_HASH_SIZE];
        device_hash.copy_from_slice(&data[13..21]);
        Ok(Self {
            flags,
            counter,
            auth_hash,
            device_hash,
        })
    }
}

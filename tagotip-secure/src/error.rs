use core::fmt;

/// Specific kind of crypto error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoErrorKind {
    /// Envelope is too short to contain a valid header.
    EnvelopeTooShort,
    /// Cipher suite ID is not recognized.
    UnsupportedCipher,
    /// Protocol version is not supported.
    UnsupportedVersion,
    /// Method ID is not recognized.
    InvalidMethod,
    /// The required cipher suite feature is not enabled at compile time.
    CipherNotEnabled,
    /// AEAD decryption failed (wrong key, tampered data, or AAD mismatch).
    DecryptionFailed,
    /// Encryption key size does not match the cipher suite requirement.
    InvalidKeySize,
    /// Inner frame exceeds maximum allowed size.
    InnerFrameTooLarge,
    /// Assembled envelope exceeds maximum allowed size.
    EnvelopeTooLarge,
    /// Output buffer is too small.
    BufferTooSmall,
    /// The Flags byte value 0x41 is reserved for disambiguation.
    ReservedFlagsValue,
}

/// Error returned by crypto envelope operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError {
    pub kind: CryptoErrorKind,
}

impl CryptoError {
    #[must_use]
    pub fn new(kind: CryptoErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub fn envelope_too_short() -> Self {
        Self::new(CryptoErrorKind::EnvelopeTooShort)
    }

    #[must_use]
    pub fn unsupported_cipher() -> Self {
        Self::new(CryptoErrorKind::UnsupportedCipher)
    }

    #[must_use]
    pub fn unsupported_version() -> Self {
        Self::new(CryptoErrorKind::UnsupportedVersion)
    }

    #[must_use]
    pub fn invalid_method() -> Self {
        Self::new(CryptoErrorKind::InvalidMethod)
    }

    #[must_use]
    pub fn cipher_not_enabled() -> Self {
        Self::new(CryptoErrorKind::CipherNotEnabled)
    }

    #[must_use]
    pub fn decryption_failed() -> Self {
        Self::new(CryptoErrorKind::DecryptionFailed)
    }

    #[must_use]
    pub fn invalid_key_size() -> Self {
        Self::new(CryptoErrorKind::InvalidKeySize)
    }

    #[must_use]
    pub fn inner_frame_too_large() -> Self {
        Self::new(CryptoErrorKind::InnerFrameTooLarge)
    }

    #[must_use]
    pub fn envelope_too_large() -> Self {
        Self::new(CryptoErrorKind::EnvelopeTooLarge)
    }

    #[must_use]
    pub fn buffer_too_small() -> Self {
        Self::new(CryptoErrorKind::BufferTooSmall)
    }

    #[must_use]
    pub fn reserved_flags_value() -> Self {
        Self::new(CryptoErrorKind::ReservedFlagsValue)
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self.kind {
            CryptoErrorKind::EnvelopeTooShort => "envelope too short",
            CryptoErrorKind::UnsupportedCipher => "unsupported cipher suite",
            CryptoErrorKind::UnsupportedVersion => "unsupported version",
            CryptoErrorKind::InvalidMethod => "invalid method",
            CryptoErrorKind::CipherNotEnabled => "cipher suite not enabled (missing feature flag)",
            CryptoErrorKind::DecryptionFailed => "AEAD decryption failed",
            CryptoErrorKind::InvalidKeySize => "invalid encryption key size",
            CryptoErrorKind::InnerFrameTooLarge => "inner frame exceeds maximum size",
            CryptoErrorKind::EnvelopeTooLarge => "envelope exceeds maximum size",
            CryptoErrorKind::BufferTooSmall => "output buffer too small",
            CryptoErrorKind::ReservedFlagsValue => "flags byte 0x41 is reserved",
        };
        f.write_str(desc)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

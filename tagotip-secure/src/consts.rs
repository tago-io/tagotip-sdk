/// Size of the envelope header (Flags + Counter + Auth Hash + Device Hash).
pub const HEADER_SIZE: usize = 21;

/// Size of the Flags field.
pub const FLAGS_SIZE: usize = 1;

/// Size of the Counter field.
pub const COUNTER_SIZE: usize = 4;

/// Size of the Authorization Hash.
pub const AUTH_HASH_SIZE: usize = 8;

/// Size of the Device Hash.
pub const DEVICE_HASH_SIZE: usize = 8;

/// CCM authentication tag size (8 bytes).
pub const CCM_TAG_SIZE: usize = 8;

/// GCM / ChaCha20-Poly1305 authentication tag size (16 bytes).
pub const GCM_TAG_SIZE: usize = 16;

/// CCM nonce size (13 bytes, L=2).
pub const CCM_NONCE_SIZE: usize = 13;

/// GCM / ChaCha20-Poly1305 nonce size (12 bytes).
pub const GCM_NONCE_SIZE: usize = 12;

/// AES-128 key size.
pub const AES_128_KEY_SIZE: usize = 16;

/// AES-256 / `ChaCha20` key size.
pub const AES_256_KEY_SIZE: usize = 32;

/// Maximum plaintext inner frame size (same as `MAX_FRAME_SIZE`).
pub const MAX_INNER_FRAME_SIZE: usize = 16_384;

/// Reserved Flags byte value (0x41 = ASCII 'A') for disambiguation.
pub const RESERVED_FLAGS_VALUE: u8 = 0x41;

/// Flags byte bitmask for cipher suite (bits 7-5).
pub const FLAGS_CIPHER_MASK: u8 = 0b1110_0000;

/// Flags byte shift for cipher suite.
pub const FLAGS_CIPHER_SHIFT: u8 = 5;

/// Flags byte bitmask for version (bits 4-3).
pub const FLAGS_VERSION_MASK: u8 = 0b0001_1000;

/// Flags byte shift for version.
pub const FLAGS_VERSION_SHIFT: u8 = 3;

/// Flags byte bitmask for method (bits 2-0).
pub const FLAGS_METHOD_MASK: u8 = 0b0000_0111;

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod cipher;
pub mod consts;
pub mod envelope;
pub mod error;
pub mod hash;
pub mod nonce;
pub mod types;

pub use error::{CryptoError, CryptoErrorKind};
pub use types::{CipherSuite, EnvelopeHeader, EnvelopeMethod, Flags};

pub use envelope::{is_envelope, open_envelope, parse_envelope_header, seal_downlink, seal_raw, seal_uplink};
pub use hash::{derive_auth_hash, derive_device_hash};

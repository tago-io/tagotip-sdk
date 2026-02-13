# tagotip-secure

A `no_std` Rust AEAD crypto envelope for the [TagoTiP/S protocol](https://github.com/tago-io/tagotip-sdk/tree/main/protocol) — encrypt and authenticate TagoTiP frames with pluggable cipher suites.

## Features

- **`no_std` by default** — works on bare-metal and embedded targets
- **Multiple cipher suites** — AES-128/256-CCM, AES-128/256-GCM, ChaCha20-Poly1305
- **Alloc-only** — requires `alloc` but not `std`
- **Spec-compliant** — 21-byte envelope header with flags, counter, auth hash, and device hash

## Usage

```rust
use tagotip_secure::{seal_uplink, open_envelope, CipherSuite};
use tagotip_secure::hash::derive_auth_hash;
use tagotip_codec::{Method, HeadlessFrame};

// Shared key (16 bytes for AES-128-CCM)
let key: [u8; 16] = [0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee,
                      0x12, 0xab, 0x56, 0xcd, 0x78, 0xef, 0x90, 0x12];
let auth_hash = derive_auth_hash("ate2bd319014b24e0a8aca9f00aea4c0d0");

let frame = HeadlessFrame {
    serial: "sensor-01",
    push_body: None,
    pull_body: None,
};

// Seal (encrypt) an uplink frame
let envelope = seal_uplink(
    Method::Ping, &frame, 42, auth_hash, &key, CipherSuite::Aes128Ccm,
).unwrap();

// Open (decrypt) the envelope
let (header, method, plaintext) = open_envelope(&envelope, &key).unwrap();
assert_eq!(method, tagotip_secure::EnvelopeMethod::Ping);
assert_eq!(header.counter, 42);
```

## Feature flags

| Flag                  | Description                                             |
|-----------------------|---------------------------------------------------------|
| `aes-128-ccm`        | AES-128-CCM cipher suite (enabled by default)           |
| `aes-128-gcm`        | AES-128-GCM cipher suite                                |
| `aes-256-ccm`        | AES-256-CCM cipher suite                                |
| `aes-256-gcm`        | AES-256-GCM cipher suite                                |
| `chacha20-poly1305`  | ChaCha20-Poly1305 cipher suite                          |
| `full`               | Enables all cipher suites                               |
| `std`                | Enables `std` support (not required for core functionality) |

## License

Apache-2.0 — see [LICENSE](../LICENSE) for details.

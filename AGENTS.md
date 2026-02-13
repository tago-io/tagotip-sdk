# AGENTS.md — TagoTiP SDK Libraries

## Repository Structure

```
tagotip-sdk/
  protocol/           Git submodule — TagoTiP protocol spec (source of truth)
  tagotip-codec/      Rust no_std codec (parser + builder)
  tagotip-secure/     Rust TagoTiP/S crypto envelope (AEAD encryption)
  tagotip-ffi/        Rust crate exposing tagotip-codec via C ABI
  tagotip-node/       TypeScript SDK (@tagoio/tagotip)
  tagotip-go/         Go SDK
  tagotip-python/     Python SDK
  tagotip-arduino/    Arduino/C library
```

## FFI Architecture

All language bindings use `tagotip-codec` (Rust) as the single implementation. No language re-implements parsing or building logic.

- **Node**: Uses napi-rs to call tagotip-codec directly from Rust (no C FFI needed).
- **Go/Python/Arduino**: Use `tagotip-ffi` (C ABI) to call tagotip-codec.

```
tagotip-codec
      |
      +---> tagotip-secure (AEAD envelope layer for TagoTiP/S)
      |
      +---> tagotip-node (napi-rs — calls Rust directly)
      |
      +---> tagotip-ffi (cdylib + staticlib)
                  |
                  +---> Go (cgo links to .so/.a)
                  +---> Python (cffi loads .so/.dylib)
                  +---> Arduino (links .a statically)
```

The C header `tagotip-ffi/tagotip.h` declares all public types and functions for Go/Python/Arduino. The Node package has its own Rust crate in `tagotip-node/native/lib.rs` using napi-rs.

## Protocol Source of Truth

- `protocol/TagoTiP.md` is the canonical spec for the plaintext protocol.
- `protocol/TagoTiPs.md` is the canonical spec for the TagoTiP/S crypto envelope.

All type definitions, constants, and behaviors must match the spec. When in doubt, read the spec.

## Core Types

These types exist across all language bindings:

- **Method**: `Push`, `Pull`, `Ping`
- **Operator**: `Number` (`:=`), `String` (`=`), `Boolean` (`?=`), `Location` (`@=`)
- **Value**: `Number(str)`, `String(str)`, `Boolean(bool)`, `Location{lat,lng,alt?}`
- **Variable**: `name`, `operator`, `value`, `unit?`, `timestamp?`, `group?`, `meta?`
- **MetaPair**: `key`, `value`
- **UplinkFrame**: `method`, `seq?`, `auth`, `serial`, `push_body?`, `pull_body?`
- **AckFrame**: `seq?`, `status`, `detail?`
- **AckStatus**: `Ok`, `Pong`, `Cmd`, `Err`
- **AckDetail**: `Count(u32)`, `Variables(str)`, `Command(str)`, `Error{code,text}`, `Raw(str)`

## Constants

```
MAX_VARIABLES       = 100
MAX_META_PAIRS      = 32
MAX_TOTAL_META      = 512
MAX_VARNAME_LEN     = 100
MAX_SERIAL_LEN      = 100
MAX_GROUP_LEN       = 100
MAX_META_KEY_LEN    = 100
MAX_UNIT_LEN        = 25
MAX_FRAME_SIZE      = 16384
AUTH_HASH_LEN       = 16
```

## Build & Test Commands

A root `justfile` provides all build/test/lint recipes. Install [just](https://github.com/casey/just) and run:

```bash
just              # list all recipes
just check        # cargo check --workspace
just build        # build everything (Rust + Node + FFI)
just test         # run all tests (Rust, Node, Go, Python, Arduino)
just lint         # cargo clippy --workspace --all-targets
just fmt          # cargo fmt --all
just fmt-check    # check formatting (CI)
just clean        # clean all build artifacts
```

Per-language recipes are also available:

```bash
just rust-test       # cargo test --workspace
just crypto-test     # test tagotip-secure (default = AES-128-CCM)
just crypto-test-all # test tagotip-secure with all cipher suites
just crypto-clippy   # clippy on tagotip-secure with all features
just node-test       # npm test in tagotip-node
just go-test         # go test in tagotip-go
just python-test     # pytest in tagotip-python
just arduino-test    # compile & run C test in tagotip-arduino
just ffi-build       # cargo build -p tagotip-ffi
```

## tagotip-secure (TagoTiP/S)

The `tagotip-secure` crate implements the TagoTiP/S secure crypto envelope per `protocol/TagoTiPs.md`.

- **Dependencies**: `tagotip-codec` (path), `sha2`, `aes`, `ccm`, `aes-gcm`, `chacha20poly1305`
- **Feature flags**: `aes-128-ccm` (default), `aes-128-gcm`, `aes-256-ccm`, `aes-256-gcm`, `chacha20-poly1305`, `full` (all suites), `std`
- **`no_std`** with `alloc` (returns `Vec<u8>` for encrypted output)

### Key types

- **`CipherSuite`**: `Aes128Ccm` (0), `Aes128Gcm` (1), `Aes256Ccm` (2), `Aes256Gcm` (3), `ChaCha20Poly1305` (4)
- **`EnvelopeMethod`**: `Push` (0), `Pull` (1), `Ping` (2), `Ack` (3)
- **`EnvelopeHeader`**: `flags`, `counter`, `auth_hash`, `device_hash` (21 bytes)
- **`CryptoError`** / **`CryptoErrorKind`**: Error types for all envelope operations

### Public API

```rust
// Hash derivation
derive_auth_hash(token: &str) -> [u8; 8]
derive_device_hash(serial: &str) -> [u8; 8]

// Uplink (client -> server)
seal_uplink(method, frame, counter, auth_hash, key, suite) -> Result<Vec<u8>>

// Downlink (server -> client)
seal_downlink(ack, counter, auth_hash, device_hash, key, suite) -> Result<Vec<u8>>

// Server routing (pre-decryption)
parse_envelope_header(envelope) -> Result<EnvelopeHeader>

// Decryption (both sides)
open_envelope(envelope, key) -> Result<(EnvelopeHeader, EnvelopeMethod, Vec<u8>)>

// Low-level / disambiguation
seal_raw(inner_frame, method, counter, auth_hash, device_hash, key, suite) -> Result<Vec<u8>>
is_envelope(data) -> bool
```

### Codec additions for TagoTiP/S

The following functions were added to `tagotip-codec` for ACK inner frames (no `ACK|` prefix):

- `build_ack_inner(frame, buf) -> Result<usize>` — builds `STATUS[|DETAIL]`
- `parse_ack_inner(input) -> Result<AckFrame>` — parses `STATUS[|DETAIL]`

## tagotip-arduino/tagotips (TagoTiP/S Pure C)

The `tagotips.h` / `tagotips.c` files provide a **standalone pure C** implementation of the TagoTiP/S crypto envelope for Arduino and embedded targets.

- **Zero dependencies**: self-contained SHA-256, AES-128, and AES-128-CCM
- **Zero heap allocation**: all operations use stack buffers
- **Client-only scope**: seal uplink frames, open downlink envelopes
- **AES-128-CCM only**: the mandatory cipher suite (suite 0) per spec
- All crypto primitives are `static` functions inside `tagotips.c`

### Public API

```c
tagotips_derive_auth_hash(token, out)       // SHA-256 truncated to 8 bytes
tagotips_derive_device_hash(serial, out)     // SHA-256 truncated to 8 bytes
tagotips_seal(inner, len, method, counter, auth_hash, device_hash, key, out, out_len)
tagotips_open(envelope, len, key, header, method, inner, inner_len)
tagotips_parse_header(envelope, len, header) // no decryption
tagotips_is_envelope(data, len)              // disambiguation (0x41 check)
```

### Test

```bash
just arduino-crypto-test
```

## Versioning

- `tagotip-codec` and `tagotip-secure` must always share the same version number (managed via `workspace.package.version` in the root `Cargo.toml`).

## README Convention

All README.md files must include the TagoIO logo header at the top, before the title:

```html
<br/>
<p align="center">
  <img src="https://assets.tago.io/tagoio/tagoio.png" width="250px" alt="TagoIO"></img>
</p>
```

## Coding Conventions

- **Rust**: Edition 2024, `no_std` for codec and crypto, `#![forbid(unsafe_op_in_unsafe_fn)]`
- **TypeScript**: Strict mode, ES2022, Bundler module resolution, `.ts` import extensions, `tsdown` bundler, napi-rs for native addon
- **Go**: Standard `go fmt`, modules
- **Python**: Python 3.10+, dataclasses, type hints
- **C/Arduino**: C99, `#ifndef` guard macros

## FFI Function Signatures

All FFI functions follow the pattern:
- Parse: `tagotip_parse_*(input_ptr, input_len, out_ptr) -> i32` (0 = success, negative = error)
- Build: `tagotip_build_*(frame_ptr, buf_ptr, buf_len) -> i32` (positive = bytes written, negative = error)

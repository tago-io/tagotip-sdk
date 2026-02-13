<br/>
<p align="center">
  <img src="https://assets.tago.io/tagoio/tagoio.png" width="250px" alt="TagoIO"></img>
</p>

# TagoTiP SDK Libraries

Multi-language SDK for the [TagoTiP protocol](protocol/TagoTiP.md) — a compact, text-based IoT transport protocol by [TagoIO](https://tago.io). Includes support for [TagoTiP/S](protocol/TagoTiPs.md), an AEAD crypto envelope for encrypted communication on constrained links (LoRa, Sigfox, NB-IoT, raw UDP).

## Architecture

The Rust `tagotip-codec` crate is the reference implementation. Language SDKs reimplement the codec natively for zero C dependencies, while the FFI bridge serves embedded/Arduino targets. All SDKs support TagoTiP/S encryption.

```
tagotip-codec (Rust, no_std)        tagotip-secure (Rust, AEAD crypto)
      |                                     |
      +---> tagotip-node                    +---> tagotip-python (PyO3 bindings)
      |     (pure TypeScript + TagoTiP/S)   |
      +---> tagotip-go                      +---> tagotip-node (Node.js crypto)
      |     (pure Go + TagoTiP/S)           |
      v                                     +---> tagotip-go (Go crypto)
tagotip-ffi (Rust crate, C ABI)
      |
      +---> tagotip-arduino (C — static linking + standalone TagoTiP/S)
```

## Packages

| Package | Language | Path | Description |
|---------|----------|------|-------------|
| `tagotip-codec` | Rust | [`tagotip-codec/`](tagotip-codec/) | `no_std` reference codec (parser + builder) |
| `tagotip-secure` | Rust | [`tagotip-secure/`](tagotip-secure/) | `no_std` AEAD crypto envelope (multiple cipher suites) |
| `tagotip-ffi` | Rust/C | [`tagotip-ffi/`](tagotip-ffi/) | C ABI bridge exposing codec functions |
| `@tagoio/tagotip` | TypeScript | [`tagotip-node/`](tagotip-node/) | Node.js SDK (pure TypeScript + TagoTiP/S) |
| `tagotip` | Go | [`tagotip-go/`](tagotip-go/) | Go SDK (pure Go + TagoTiP/S) |
| `tagotip` | Python | [`tagotip-python/`](tagotip-python/) | Python SDK (PyO3 bindings + TagoTiP/S) |
| `TagoTiP` | C/Arduino | [`tagotip-arduino/`](tagotip-arduino/) | Arduino library (FFI codec + standalone TagoTiP/S) |

## Protocol

The protocol specification lives in the `protocol/` submodule:

- [**TagoTiP.md**](protocol/TagoTiP.md) — Core protocol spec (Draft v1.0, Revision B)
- [**TagoTiPs.md**](protocol/TagoTiPs.md) — Secure envelope spec (Draft v1.0, Revision C)

### Frame Format

```
METHOD | AUTH_HASH | SERIAL | [BODY]
```

**Methods**: `PUSH` (send data), `PULL` (request data), `PING` (keepalive), `ACK` (server response)

**Variable operators**:

| Operator | Type | Example |
|----------|------|---------|
| `:=` | Number | `temperature:=25.3#C` |
| `=` | String | `status=running` |
| `?=` | Boolean | `active?=true` |
| `@=` | Location | `position@=39.74,-104.99,305` |

### Example

```
PUSH|4deedd7bab8817ec|sensor-01|[temperature:=32.5#C@1694567890000^reading{source=dht22}]
```

### TagoTiP/S Secure Envelope

Binary envelope (21-byte header + ciphertext + auth tag) providing authenticated encryption without TLS:

```
[Flags: 1B] [Counter: 4B] [Auth Hash: 8B] [Device Hash: 8B] [Ciphertext + Tag]
```

**Supported cipher suites**:

| Cipher | Key | Tag | Overhead |
|--------|-----|-----|----------|
| AES-128-CCM (mandatory) | 16 B | 8 B | 29 B |
| AES-128-GCM | 16 B | 16 B | 37 B |
| AES-256-CCM | 32 B | 8 B | 29 B |
| AES-256-GCM | 32 B | 16 B | 37 B |
| ChaCha20-Poly1305 | 32 B | 16 B | 37 B |

## Building

Requires [just](https://github.com/casey/just) as a task runner.

```bash
# Run all tests across every language
just test

# Format and lint (Rust)
just fmt
just lint

# Build everything
just build
```

### Per-language commands

```bash
# Rust
just rust-test              # cargo test --workspace
just crypto-test            # tagotip-secure (AES-128-CCM)
just crypto-test-all        # tagotip-secure (all cipher suites)

# Node.js
just node-build             # npm install && npm run build
just node-test              # npm test

# Go
just go-test                # go test ./...

# Python
just python-test            # uv run pytest tests/

# Arduino/C
just arduino-test           # Compile and run C tests
just arduino-crypto-test    # TagoTiP/S C tests
```

### Prerequisites

| Tool | Version |
|------|---------|
| Rust | 1.85+ |
| Node.js | 22+ |
| Go | 1.22+ |
| Python | 3.10+ (with [uv](https://github.com/astral-sh/uv)) |
| just | latest |
| C compiler | Any (for Arduino tests) |

## License

Apache-2.0

<br/>
<p align="center">
  <img src="https://assets.tago.io/tagoio/tagoio.png" width="250px" alt="TagoIO"></img>
</p>

# TagoTiP SDK Libraries

Multi-language SDK bindings for the [TagoTiP protocol](protocol/TagoTiP.md) — a compact, text-based IoT transport protocol by [TagoIO](https://tago.io).

## Architecture

All language SDKs share a single Rust implementation (`tagotip-codec`). This guarantees identical parsing and building behavior across every language.

```
tagotip-codec (Rust, no_std)
      |
      +---> tagotip-node      (TypeScript — napi-rs native addon, calls Rust directly)
      |
      v
tagotip-ffi (Rust crate, C ABI)
      |
      +---> tagotip-arduino   (C — static linking)
      +---> tagotip-go        (Go — cgo)
      +---> tagotip-python    (Python — cffi)
```

## Packages

| Package | Language | Path | Description |
|---------|----------|------|-------------|
| `tagotip-codec` | Rust | `tagotip-codec/` | `no_std` codec (parser + builder) |
| `tagotip-ffi` | Rust/C | `tagotip-ffi/` | C ABI bridge exposing codec functions |
| `@tagoio/tagotip` | TypeScript | `tagotip-node/` | Node.js SDK |
| `tagotip` | Go | `tagotip-go/` | Go SDK |
| `tagotip` | Python | `tagotip-python/` | Python SDK |
| `TagoTiP` | C/Arduino | `tagotip-arduino/` | Arduino library |

## Protocol

The protocol specification lives in the `protocol/` submodule. See [`protocol/TagoTiP.md`](protocol/TagoTiP.md) for the full spec.

### Example Frame

```
PUSH|at0123456789abcdef0123456789abcdef|my-device|[temperature:=25.3#C;humidity:=60#%]
```

## Building

```bash
# Rust codec tests
cargo test --manifest-path tagotip-codec/Cargo.toml

# FFI crate
cargo build --manifest-path tagotip-ffi/Cargo.toml

# Node
cd tagotip-node && npm install && npm run build

# Go
cd tagotip-go && go build ./...

# Python
cd tagotip-python && python -c "from tagotip import types"
```

## License

Apache-2.0

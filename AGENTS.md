# AGENTS.md — TagoTiP SDK Libraries

## Repository Structure

```
tagotip-sdk/
  protocol/           Git submodule — TagoTiP protocol spec (source of truth)
  tagotip-codec/      Rust no_std codec (parser + builder)
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

`protocol/TagoTiP.md` is the canonical spec. All type definitions, constants, and behaviors must match the spec. When in doubt, read the spec.

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
just rust-test    # cargo test --workspace
just node-test    # npm test in tagotip-node
just go-test      # go test in tagotip-go
just python-test  # pytest in tagotip-python
just arduino-test # compile & run C test in tagotip-arduino
just ffi-build    # cargo build -p tagotip-ffi
```

## Coding Conventions

- **Rust**: Edition 2024, `no_std` for codec, `#![forbid(unsafe_op_in_unsafe_fn)]`
- **TypeScript**: Strict mode, ES2022, Bundler module resolution, `.ts` import extensions, `tsdown` bundler, napi-rs for native addon
- **Go**: Standard `go fmt`, modules
- **Python**: Python 3.10+, dataclasses, type hints
- **C/Arduino**: C99, `#ifndef` guard macros

## FFI Function Signatures

All FFI functions follow the pattern:
- Parse: `tagotip_parse_*(input_ptr, input_len, out_ptr) -> i32` (0 = success, negative = error)
- Build: `tagotip_build_*(frame_ptr, buf_ptr, buf_len) -> i32` (positive = bytes written, negative = error)

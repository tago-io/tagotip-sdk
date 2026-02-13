# TagoTiP SDK Libraries — Task Runner

# List all recipes
default:
    @just --list

# ─── Workspace-wide ──────────────────────────────────────────

# Type-check all Rust crates
check:
    cargo check --workspace

# Build everything (Rust + Node native + FFI)
build: rust-build node-build

# Run all tests across all languages
test: rust-test node-test go-test python-test arduino-test

# Lint all Rust code with clippy
lint: rust-clippy

# Format all Rust code
fmt: rust-fmt

# Check formatting (CI)
fmt-check:
    cargo fmt --all -- --check

# Clean all build artifacts
clean:
    cargo clean
    rm -rf tagotip-node/dist tagotip-node/node_modules/.cache
    rm -f tagotip-arduino/test_parse

# ─── Rust ────────────────────────────────────────────────────

# Build all Rust crates
rust-build:
    cargo build --workspace

# Run all Rust tests
rust-test:
    cargo test --workspace

# Format Rust code
rust-fmt:
    cargo fmt --all

# Run clippy on all Rust crates
rust-clippy:
    cargo clippy --workspace --all-targets

# ─── Node ────────────────────────────────────────────────────

# Build Node SDK (native addon + TypeScript)
node-build:
    cd tagotip-node && npm install && npm run build

# Run Node tests
node-test:
    cd tagotip-node && npm test

# ─── Go ──────────────────────────────────────────────────────

# Run Go tests
go-test:
    cd tagotip-go && go test ./...

# ─── Python ──────────────────────────────────────────────────

# Run Python tests
python-test:
    cd tagotip-python && python -m pytest tests/

# ─── Arduino ─────────────────────────────────────────────────

# Build and run Arduino/C test
arduino-test:
    cd tagotip-arduino && cc -o test_parse tests/test_parse.c -I src && ./test_parse

# Build and run Arduino/C crypto test
arduino-crypto-test:
    cd tagotip-arduino && cc -std=c99 -Wall -Wextra -Werror -o test_crypto tests/test_crypto.c src/tagotips.c -I src && ./test_crypto

# ─── Secure ─────────────────────────────────────────────────

# Run tagotip-secure tests (default features = AES-128-CCM)
crypto-test:
    cargo test -p tagotip-secure

# Run tagotip-secure tests with all cipher suites
crypto-test-all:
    cargo test -p tagotip-secure --all-features

# Run clippy on tagotip-secure with all cipher suites
crypto-clippy:
    cargo clippy -p tagotip-secure --all-features -- -D warnings

# ─── FFI ─────────────────────────────────────────────────────

# Build the FFI shared/static library
ffi-build:
    cargo build -p tagotip-ffi

# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Please use [GitHub's private security advisory feature](https://github.com/tago-io/tagotip-sdk/security/advisories/new) to report vulnerabilities. This keeps the report confidential while allowing us to collaborate on a fix before public disclosure.

Alternatively, email **security@tago.io**.

We will acknowledge receipt within 48 hours and aim to provide an initial assessment within 5 business days.

## Scope

This policy applies to all packages in this repository:

- `tagotip-codec` (Rust)
- `tagotip-secure` (Rust, cryptographic operations)
- `tagotip-ffi` (Rust/C FFI bridge)
- `@tagoio/tagotip` (Node.js)
- `tagotip` (Go)
- `tagotip` (Python)
- `TagoTiP` (Arduino/C)

Cryptographic issues in `tagotip-secure` and language-specific crypto implementations are especially critical and will be prioritized.

## Disclosure

We follow coordinated disclosure. We will work with you to understand and address the issue before any public disclosure.

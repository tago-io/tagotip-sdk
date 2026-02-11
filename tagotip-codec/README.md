# tagotip-codec

A `no_std` Rust codec for the [TagoTiP protocol](https://github.com/tago-io/tagotip-sdk/tree/main/protocol) — parse and build uplink/downlink frames with zero heap allocation.

## Features

- **`no_std` by default** — works on bare-metal and embedded targets
- **Zero-copy parsing** — parsed types borrow directly from the input string
- **Frame builder** — serialize frames into a caller-provided `&mut [u8]` buffer
- **Full protocol coverage** — PUSH (structured + passthrough), PULL, PING, and ACK frames
- Optional `std` feature for environments with an allocator

## Usage

```rust
use tagotip_codec::parse::parse_uplink;
use tagotip_codec::build::build_uplink;
use tagotip_codec::types::*;

// Parse an uplink frame
let input = "PUSH|ate2bd319014b24e0a8aca9f00aea4c0d0|sensor_01|[temperature:=32;humidity:=65]";
let frame = parse_uplink(input).unwrap();

assert_eq!(frame.method, Method::Push);
assert_eq!(frame.serial, "sensor_01");

if let Some(PushBody::Structured(body)) = &frame.push_body {
    for var in body.variables.iter() {
        // var.name, var.operator, var.value, etc.
    }
}

// Build (serialize) a frame back into bytes
let mut buf = [0u8; 512];
let n = build_uplink(&frame, &mut buf).unwrap();
let output = core::str::from_utf8(&buf[..n]).unwrap();
assert_eq!(output, input);
```

## Feature flags

| Flag  | Description |
|-------|-------------|
| `std` | Enables `std` support (not required for core functionality) |

## License

Apache-2.0 — see [LICENSE](../LICENSE) for details.

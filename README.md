# ClientHello

Zero-copy TLS ClientHello parser. Works with both TLS record and raw handshake input.

`clienthello` parses TLS ClientHello messages without external parser dependencies, extracting SNI, ALPN, cipher suites, supported versions, key shares, and other extensions from raw bytes.

## Features

- **Dual Input Formats**: Parse standard TLS records (`0x16` prefix) or raw handshake messages (`0x01` prefix, QUIC CRYPTO).
- **Zero-Copy**: Borrows directly from the input buffer wherever possible.
- **GREASE Filtering**: Automatically detects and filters RFC 8701 GREASE values from cipher suites, versions, groups, and key shares.
- **Structured Extensions**: SNI, ALPN, Supported Versions, Supported Groups, Signature Algorithms, Key Share, PSK Exchange Modes, and Renegotiation Info are parsed into typed variants.
- **`no_std` + `alloc`**: Works in `no_std` environments with an allocator.

## Usage Examples

Check the `examples` directory for runnable code:

- **Record Layer**: [`examples/parse_record.rs`](examples/parse_record.rs) - Parse a full TLS record and print all fields.
- **QUIC SNI**: [`examples/quic_sni.rs`](examples/quic_sni.rs) - Extract SNI from a raw handshake message.

## Installation

```toml
[dependencies]
clienthello = { version = "0.1", features = ["full"] }
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `std` | Enables standard library support. |
| `full` | Enables all features above. |

## License

Released under the MIT License © 2026 [Canmi](https://github.com/canmi21)

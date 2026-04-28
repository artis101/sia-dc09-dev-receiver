# SIA DC-09 Dev Receiver

A small developer receiver for testing SIA DC-09 alarm reporting integrations.

This tool listens for SIA DC-09 TCP frames, validates basic frame structure, logs parsed event details, optionally decrypts AES-CBC payloads, and replies with configurable `ACK`, `NAK`, or `DUH` responses. It is intended for developers building or debugging SIA DC-09 senders, receivers, gateways, or alarm-response integrations.

It is not a production alarm receiver and should not be used as one.

## Features

- Listens for SIA DC-09 messages over TCP.
- Validates frame length and CRC.
- Parses common header fields, account data, event payloads, NULL supervision polls, and timestamps.
- Supports plaintext and AES-CBC encrypted payloads with 128/192/256-bit keys.
- Can run in the foreground or as a simple daemon.
- Can force receiver replies to `ACK`, `NAK`, or `DUH` for integration testing.

## Usage

Run with the defaults:

```sh
cargo run --release
```

Listen on a custom port:

```sh
cargo run --release -- --port 1111
```

Use a specific reply mode:

```sh
cargo run --release -- --reply NAK
```

Use a custom AES key:

```sh
cargo run --release -- --key DEADBEEFCAFEBABEDEADBEEFCAFEBABE
```

Show all options:

```sh
cargo run -- --help
```

## Device Build

`scripts/build-armv7-musl.sh` is a convenience script for building an `armv7-unknown-linux-musleabihf` release binary in Docker. This is useful for custom devices, router-class hardware, and other small ARMv7 Linux targets.

```sh
./scripts/build-armv7-musl.sh
```

For local development, use the normal Cargo commands instead:

```sh
cargo build
cargo test
```

Tagged releases can also produce binaries for common Linux, macOS, and Windows targets through GitHub Actions.

```sh
git tag v0.1.0
git push origin v0.1.0
```

## License

This project is licensed under the BSD 2-Clause license. You can use, copy, modify, and distribute it freely, including in commercial projects, as long as the license notice is preserved.

## Intended Audience

This project is for developers working on SIA DC-09 integrations who need a simple receiver they can run locally or on a test device to inspect payloads and verify sender behavior.

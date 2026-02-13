# lakers &emsp; [![CI status]][actions] [![Latest Version]][crates.io] [![API Documentation]][docs.rs]

[CI status]: https://github.com/lake-rs/lakers/actions/workflows/build-and-test.yml/badge.svg
[actions]: https://github.com/lake-rs/lakers/actions/workflows/build-and-test.yml
[Latest Version]: https://img.shields.io/crates/v/lakers.svg
[crates.io]: https://crates.io/crates/lakers
[API Documentation]: https://docs.rs/lakers/badge.svg
[docs.rs]: https://docs.rs/lakers

An implementation of [EDHOC (RFC 9528)](https://datatracker.ietf.org/doc/html/rfc9528) in Rust.

# What is EDHOC?

Ephemeral Diffie-Hellman Over COSE (EDHOC) is a new IETF standard that provides a [very lightweight](https://hal.science/hal-04382397/document) authenticated key exchange, ideal for usage in constrained scenarios, such as in Internet of Things environments.

# EDHOC Features
- lightweight: full authenticated key exchange in as few as 101 bytes
- secure: mutual authentication, forward secrecy, and identity protection
- transport-agnostic: can be used on scenarios with or without IP connectivity; a common way to transport EDHOC is [over reliable CoAP](https://www.rfc-editor.org/rfc/rfc9528.html#coap)
- code re-use: achieved due to re-using technologies common in IoT scenarios, such as COSE, CBOR, and CoAP
- finally, a main use case of EDHOC is to establish an [OSCORE](https://datatracker.ietf.org/doc/rfc8613/) security context


# lakers features

- easy to use, typestated API for Initiator and Responder
- microcontroller-optimized: `no_std`, no heap allocations, zero-dependencies (other than crypto backends)
- configurable crypto backends
- bindings for [C](https://github.com/lake-rs/lakers/releases/) and [Python](https://pypi.org/project/lakers-python/)
- support for EDHOC extensions, including [zero-touch authorization](https://datatracker.ietf.org/doc/draft-ietf-lake-authz/)

It currently supports authentication mode STAT-STAT and Cipher Suite 2 (AES-CCM-16-64-128, SHA-256, 8, P-256, ES256, AES-CCM-16-64-128, SHA-256).

# Getting started

To use `lakers` in your Rust project, add it to your Cargo.toml using `cargo add lakers`.

Here's a quick look at the API for the Initiator role (for the Responder role, and more details, check the examples or the unit tests):
```rust
// perform the handshake
let initiator = EdhocInitiator::new(default_crypto());

let (initiator, message_1) = initiator.prepare_message_1(None, &EADItem::new_empty_array())?; // c_i and ead_1 are set to None

let (initiator, _c_r, id_cred_r, _ead_2) = initiator.parse_message_2(&message_2)?;
let valid_cred_r = credential_check_or_fetch(Some(CRED_R), id_cred_r)?; // CRED_R contains Responder's public key
let initiator = initiator.verify_message_2(I, cred_i, valid_cred_r)?; // I is Initiator's private key

let (mut initiator, message_3, i_prk_out) = initiator.prepare_message_3(CredentialTransfer::ByReference, &EADItem::new_empty_array())?; // no ead_3

// derive a secret to use with OSCORE
let oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0

// update the prk_out key (context taken from draft-ietf-lake-traces)
let context = &[0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8, 0xbc, 0xea];
let prk_out_new = initiator.edhoc_key_update(context);
```

### C API
C-compatible static libraries and headers are available for download in [the releases page](https://github.com/lake-rs/lakers/releases).

### Python API
`lakers-python` is [available on PyPI](https://pypi.org/project/lakers-python/), to install it run `pip install lakers-python`.

### Development
To work on `lakers` itself, follow the instructions below:

1. Make sure you have [Rust](https://www.rust-lang.org/tools/install) installed.

2. Download, compile, and run the tests:
```
git clone git@github.com:lake-rs/lakers.git && cd lakers
cargo build
cargo test
```

`lakers` can be compiled with different configurations depending on the enabled features. To learn what are the available features and how to select them for several configurations of build and test, check [the Github Actions file](./.github/workflows/rust.yml).

## Example: EDHOC over CoAP on native host

In one terminal, run an example CoAP server:
```
cargo run --bin coapserver
```

In another one, run the client:
```
cargo run --bin coapclient
```

In the output you should find the EDHOC handshake messages and the derived OSCORE secret/salt.

The source code for these examples is at `examples/coap/src/bin`.

## Example: EDHOC on nRF52840 device with different crypto backends

To build an example application that works on the [nrf52840dk](https://www.nordicsemi.com/Products/Development-hardware/nrf52840-dk), do as follows:

```bash
# head to the example `no_std` example
cd ./examples/lakers-no_std

# build, flash, and run with the cryptocell310 crypto backend (hardware-accelerated)
cargo run --target="thumbv7em-none-eabihf" --release

# build, flash, and run with the psa crypto backend (software-based)
cargo run --target="thumbv7em-none-eabihf" --no-default-features --features="crypto-psa, ead-none, rtt" --release

```

Note that this requires [probe-rs](https://probe.rs/) to be installed in your system.

## Using logs
Logs can be used in both native and embedded applications. Once configured in an application, both can be controlled via environment variables:

- on native, set `RUST_LOG` to control Rust's built-in `log` facility
- on embedded, set `DEFMT_LOG` to control the [defmt](https://github.com/knurling-rs/defmt) crate

The selection of `log` or `defmt` is handled internally by the [defmt-or-log](https://github.com/t-moe/defmt-or-log) crate.

For example, `examples/lakers-nrf52840` is configured to use `defmt`. To globally enable logs at level `trace`:
```bash
DEFMT_LOG=trace cargo run --bin initiator
```

Different log levels can also be set per crate or module.
Here's how to globally set logs to level `trace`, while restricting `lakers` to level `info`:
```bash
DEFMT_LOG=trace,lakers=info cargo run --bin initiator
```

## Directory structure
This library is structured as a [cargo workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html).
Its main members are:

- `lib`: The main library providing the EDHOC implementation.
- `crypto`: Diferent cryptographic backends (e.g. psa, cryptocell310, rustcrypto).
- `ead`: Implementation of extensions to EDHOC via the External Authorization Data (EAD) field.
- `shared`: Defines shared structs and modules used throughout the workspace members.
- `lakers-c`: Provides a foreign function interface that enables using `lakers` from C code.
- `lakers-python`: API for using `lakers` in Python.
- `examples`: Example applications that demonstrate how to use the library.

# Why the name?

The EDHOC protocol was created by the IETF [LAKE](https://datatracker.ietf.org/wg/lake/about/) (Lightweight Authenticated Key Exchange) Working Group, and one of the maintainers is a basketball fan :)

# License

This software is licensed under the BSD 3-Clause License.

# Contributing

Contributors are very welcome!
Please take a look at the open issues, and pay attention to conventions used in the code-base, such as conventional commit messages and well-formatted Rust code.

Test
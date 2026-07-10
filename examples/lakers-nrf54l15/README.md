# lakers on nRF54L15

Bare-metal (`no_std`) examples of EDHOC running on the nRF54L15, using the chip's
hardware-accelerated CRACEN crypto through the [`embedded-cal`](../../../embedded-cal) backend
(the `lakers-crypto/nrf54l15` dispatch feature).

## Binaries

| Binary              | What it does                                                                              |
| ------------------- | ----------------------------------------------------------------------------------------- |
| `initiator`         | EDHOC Initiator: runs the full handshake (message_1 → message_4) over the raw radio.      |
| `responder`         | EDHOC Responder: waits for message_1 and completes the handshake, looping to serve again. |
| `edhoc`             | Single-chip demo: crypto self-tests + an EDHOC `prepare_message_1` on hardware crypto.    |
| `test_crypto_trait` | Stepped diagnostic that exercises each hardware crypto op in isolation.                   |

The `initiator` and `responder` mirror the [nRF52840 example](../lakers-nrf52840): two separate
boards talk to each other over a raw 2.4 GHz BLE-1Mbit radio link. Each board has its own CRACEN,
so each runs one EDHOC party with its own hardware `Crypto` (a single chip cannot host both, as
there is only one CRACEN).

## Prerequisites

- install `probe-rs`
- two nRF54L15 boards, each connected via its own debug probe

## How to use

From this directory (its `rust-toolchain.toml` pins the stable toolchain and its
`.cargo/config.toml` sets the target + probe-rs runner):

    cargo run --release --bin responder  -- --probe <VID:PID:SERIAL of board A>
    cargo run --release --bin initiator  -- --probe <VID:PID:SERIAL of board B>

Start the responder first so it is listening when the initiator sends message_1. List connected
probes with:

    probe-rs list

Progress is printed over RTT/defmt. On success both sides log
`handshake completed. prk_out = …` with the same key material.

> **Note on the radio driver.** `embassy-nrf` has no BLE radio driver for the nRF54L15, so this
> example includes a small hand-rolled, register-level radio driver in `src/lib.rs` (blocking, no
> async executor). It is programmed for the same on-air format the nRF52840 example uses — but two
> nRF54L15 boards are expected to talk _to each other_, not to an nRF52840. The driver has been
> compiled and register-mapped against `nrf-pac`; validate timing/interop on hardware before
> relying on it. See the earlier flash/RTT notes for this board.

## Interop with the nRF52840 example

The physical layer (2.4 GHz, BLE 1 Mbit, same access address / CRC / whitening) is compatible, so
an nRF54L15 and an nRF52840 _can_ in principle interoperate. Doing so reliably requires the on-air
framing to match bit-for-bit; that cross-target pairing is not the target of this example and is
untested.

# Introduction

This folder contains a bare metal (no_std) example of LAKE Initiator and LAKE Responder for nRF52840-DK.
The Initiator and Responder communicate over a raw BLE radio.

The example is configured to be ran on nRF52840-DK board.

## Prerequisites

- install probe-rs
- `rustup target add thumbv7m-none-eabi`

## How to use

This folder's `.cargo/config.toml` configures the target (`thumbv7m-none-eabi`) and the probe-rs runner so the things should just work:

    cargo run --bin initiator -- --probe 1366:1015:000683965284
    cargo run --bin responder -- --probe 1366:1051:001050286964

Note that if there are two boards connected to your computer, we need to specify which one we want to use.
You can get the name of your probes by running:

    probe-rs list

You can enhance debugging by passing environment variables such as `DEFMT_LOG=trace`."

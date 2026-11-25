#!/bin/bash

set -e

export CARGO_TARGET_DIR=../target/

# This script builds the static library for a cortex-m4 target
# It also generates the header files for the c wrapper
# It takes one argument: the selected crypto backend

feature_crypto=$1
if [[ $feature_crypto != "crypto-nrf52840" && $feature_crypto != "crypto-cryptocell310" && $feature_crypto != "crypto-rustcrypto" ]]; then
    echo "crypto should be one of: crypto-nrf52840, crypto-rustcrypto"
    echo "Example: ./build.sh crypto-nrf52840"
    exit 1
fi

if [[ $feature_crypto == "crypto-nrf52840" || $feature_crypto == "crypto-cryptocell310" ]]; then
    rust_target=thumbv7em-none-eabihf
else # use host architecture
    rust_target=`rustc -vV | sed -n 's|host: ||p'`
fi

# hardcoded for now
feature_ead=ead-authz

# build the static library
cargo build --target="$rust_target" --no-default-features  --features="$feature_crypto, $feature_ead" --release
# example just for testing:
#   cargo build --target=thumbv7em-none-eabihf --no-default-features --features="crypto-nrf52840, ead-authz" --release

# generate the headers
cbindgen --config ../shared/cbindgen.toml --crate lakers-shared --output ../target/include/lakers_shared.h
cbindgen --config ../ead/lakers-ead-authz/cbindgen.toml --crate lakers-ead-authz --output ../target/include/lakers_ead_authz.h
cbindgen --config ./cbindgen.toml --crate lakers-c --output ../target/include/lakers.h

# # zip to a single file
cd ../target
zip -r lakers-c-"$feature_crypto"-"$rust_target".zip include/
zip -u -j lakers-c-"$feature_crypto"-"$rust_target".zip "$rust_target"/release/liblakers_c.a
cd -

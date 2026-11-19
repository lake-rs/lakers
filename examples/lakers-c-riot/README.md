# Lakers C RIOT

Basic example of `lakers` in C for embedded targets, using the RIOT operating system.

Compile and run:
```
make flash term
```

Add `LAKE_CRYPTO=psa` if you want the `crypto-psa-baremetal` configuration.

# Requirements

- `lakers-c` library and headers:
  - either download them from the [releases page on GitHub](https://github.com/lake-rs/lakers/releases)
  - or build yourself following the README in the `lakers-c` crate
- [RIOT](https://github.com/RIOT-OS/RIOT)'s source code must be available in a local folder, which can be set via the `RIOTBASE` variable.

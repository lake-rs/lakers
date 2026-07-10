//! Cryptography dispatch for the lakers crate
//!
//! This crate is used by lakers to decide which cryptographic back-end to use. Its presence
//! avoids the need for all lakers types to be generic over a back-end, which would then be
//! provided by the user at initialization time. On the long run, its type may turn into a
//! default associated type.
#![cfg_attr(not(test), no_std)]

/// Convenience re-export
pub use lakers_shared::Crypto as CryptoTrait;

cfg_if::cfg_if!(
    if #[cfg(feature = "psa")] {
        pub type Crypto = lakers_crypto_psa::Crypto;
        pub const fn default_crypto() -> Crypto {
            lakers_crypto_psa::Crypto
        }
    } else if #[cfg(feature = "rustcrypto")] {
        pub type Crypto = lakers_crypto_rustcrypto::Crypto<rand_core::OsRng>;
        pub const fn default_crypto() -> Crypto {
            lakers_crypto_rustcrypto::Crypto::new(rand_core::OsRng)
        }
    } else if #[cfg(feature = "cryptocell310")] {
        pub type Crypto = lakers_crypto_cryptocell310::Crypto;
        pub const fn default_crypto() -> Crypto {
            lakers_crypto_cryptocell310::Crypto
        }
    } else if #[cfg(feature = "nrf54l15")] {
        pub struct Nrf54l15ExtConfig;
        impl embedded_cal_software_demo::ExtenderConfig for Nrf54l15ExtConfig {
            const IMPLEMENT_SHA2SHORT: bool = true;
            type Base = embedded_cal_nrf54l15::Nrf54l15Cal;
        }
        pub type Crypto = lakers_crypto_embedded_cal::Crypto<
            embedded_cal_software_demo::Extender<Nrf54l15ExtConfig>,
        >;
    } else if #[cfg(feature = "stm32wba55")] {
        pub struct Stm32wba55ExtConfig;
        impl embedded_cal_software_demo::ExtenderConfig for Stm32wba55ExtConfig {
            const IMPLEMENT_SHA2SHORT: bool = true;
            type Base = embedded_cal_stm32wba55::Stm32wba55Cal;
        }
        pub type Crypto = lakers_crypto_embedded_cal::Crypto<
            embedded_cal_software_demo::Extender<Stm32wba55ExtConfig>,
        >;
    }
    else {
        compile_error!("One of the features `psa`, `rustcrypto`, `cryptocell310`, `nrf54l15` or `stm32wba55` must be enabled.");
    }
);

/// See test_implements_crypto
#[allow(dead_code)]
fn test_helper<T: CryptoTrait>() {}

/// Ensure at build time that whichever type as selected for Crypto actually implements the Crypto
/// trait, and that one is actually defined.
#[allow(dead_code)]
fn test_implements_crypto() {
    test_helper::<Crypto>()
}

#[cfg(test)]
mod tests {
    use hexlit::hex;
    use lakers_shared::*;
    use rstest::rstest;

    use super::*;

    // Test vectors from RFC 5869, covering Test Cases 1 and 2
    #[rstest]
    #[case(
        &hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        &hex!("f0f1f2f3f4f5f6f7f8f9"),
        42,
        &hex!("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    )]
    #[case(
        &hex!("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
        &hex!("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        82,
        &hex!("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
    )]
    fn test_hkdf_expand(
        #[case] prk_slice: &[u8],
        #[case] info_slice: &[u8],
        #[case] output_length: usize,
        #[case] expected_okm_slice: &[u8],
    ) {
        let mut crypto = default_crypto();

        let mut prk = [0; SHA256_DIGEST_LEN];
        prk[..prk_slice.len()].copy_from_slice(prk_slice);
        let mut info = [0; MAX_INFO_LEN];
        info[..info_slice.len()].copy_from_slice(info_slice);

        let mut output = Vec::new();
        output.resize(output_length, 0x00);
        crypto.hkdf_expand(&prk, &info[..info_slice.len()], &mut output);
        assert_eq!(output, expected_okm_slice[..]);
    }
}

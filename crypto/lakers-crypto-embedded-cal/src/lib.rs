//! EDHOC crypto backend backed by the [`embedded-cal`](embedded_cal) Cryptographic Abstraction
//! Layer.
//!
//! [`Crypto`] is generic over any [`embedded_cal::Cal`] instance. This lets lakers use
//! hardware-accelerated crypto on microcontrollers that ship an embedded-cal backend (e.g.
//! nRF54L15, STM32WBA55), while falling back to a software `Cal` elsewhere. "Use hardware if
//! available" is expressed by *which concrete `Cal` the caller constructs*, not by cfg flags here.
#![cfg_attr(not(test), no_std)]

use embedded_cal::accessor::HashAlgorithmOf;
use embedded_cal::{Cal, HashAlgorithm, HashProvider};
use lakers_shared::{
    BytesCcmIvLen, BytesCcmKeyLen, BytesHashLen, BytesP256ElemLen, CcmTagLen,
    Crypto as CryptoTrait, EDHOCError, EDHOCSuite, EdhocBuffer, MAX_SUITES_LEN,
};

/// A [`lakers_shared::Crypto`] implementation that forwards to an embedded-cal [`Cal`] instance.
///
/// Construct it with [`Crypto::new`], passing a fully-wired `Cal` (for hardware backends, typically
/// an `embedded_cal_software_demo::Extender` wrapping the hardware `Cal`, so that SHA-256, HMAC and
/// therefore HKDF are available on top of the hardware's raw primitives).
pub struct Crypto<C> {
    cal: C,
}

impl<C> Crypto<C> {
    /// Wraps an embedded-cal [`Cal`](embedded_cal::Cal) instance as a lakers crypto backend.
    pub const fn new(cal: C) -> Self {
        Self { cal }
    }
}

// Hand-written so we do not require `C: Debug`; most `Cal` types do not implement it, but the
// `lakers_shared::Crypto` trait requires the backend to be `Debug`.
impl<C> core::fmt::Debug for Crypto<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("lakers_crypto_embedded_cal::Crypto")
            .field("cal", &core::any::type_name::<C>())
            .finish()
    }
}

impl<C: Cal + rand_core::TryCryptoRng> CryptoTrait for Crypto<C> {
    fn supported_suites(&self) -> EdhocBuffer<MAX_SUITES_LEN> {
        EdhocBuffer::<MAX_SUITES_LEN>::new_from_slice(&[EDHOCSuite::CipherSuite2 as u8])
            .expect("the slice is of a length that always fits")
    }

    fn sha256_digest(&mut self, message: &[u8]) -> BytesHashLen {
        let alg = HashAlgorithmOf::<C>::from_ni_id(1).expect("cal must support sha-256");
        let digest = self.cal.hash().hash(alg, message);
        digest
            .as_ref()
            .try_into()
            .expect("sha-256 output is exactly 32 bytes")
    }

    type HashInProcess<'a>
        = sha2::Sha256
    where
        Self: 'a;

    #[inline]
    fn sha256_start<'a>(&'a mut self) -> Self::HashInProcess<'a> {
        use digest::Digest;
        sha2::Sha256::new()
    }

    fn hkdf_expand(&mut self, _prk: &BytesHashLen, _info: &[u8], _result: &mut [u8]) {
        unimplemented!("hkdf_expand: implemented in a later step")
    }

    fn hkdf_extract(&mut self, _salt: &BytesHashLen, _ikm: &BytesP256ElemLen) -> BytesHashLen {
        unimplemented!("hkdf_extract: implemented in a later step")
    }

    fn aes_ccm_encrypt<const N: usize, Tag: CcmTagLen>(
        &mut self,
        _key: &BytesCcmKeyLen,
        _iv: &BytesCcmIvLen,
        _ad: &[u8],
        _plaintext: &[u8],
    ) -> EdhocBuffer<N> {
        unimplemented!("aes_ccm_encrypt: implemented in a later step")
    }

    fn aes_ccm_decrypt<const N: usize, Tag: CcmTagLen>(
        &mut self,
        _key: &BytesCcmKeyLen,
        _iv: &BytesCcmIvLen,
        _ad: &[u8],
        _ciphertext: &[u8],
    ) -> Result<EdhocBuffer<N>, EDHOCError> {
        unimplemented!("aes_ccm_decrypt: implemented in a later step")
    }

    fn p256_ecdh(
        &mut self,
        _private_key: &BytesP256ElemLen,
        _public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        unimplemented!("p256_ecdh: implemented in a later step")
    }

    fn get_random_byte(&mut self) -> u8 {
        unimplemented!("get_random_byte: implemented in a later step")
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        unimplemented!("p256_generate_key_pair: implemented in a later step")
    }
}

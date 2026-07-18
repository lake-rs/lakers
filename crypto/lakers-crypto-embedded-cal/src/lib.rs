//! EDHOC crypto backend backed by the [`embedded-cal`](embedded_cal) Cryptographic Abstraction
//! Layer.
//!
//! [`Crypto`] is generic over any [`embedded_cal::Cal`] instance. This lets lakers use
//! hardware-accelerated crypto on microcontrollers that ship an embedded-cal backend (e.g.
//! nRF54L15, STM32WBA55), while falling back to a software `Cal` elsewhere. "Use hardware if
//! available" is expressed by *which concrete `Cal` the caller constructs*, not by cfg flags here.
#![cfg_attr(not(test), no_std)]

use embedded_cal::accessor::{
    AeadAlgorithmOf, DhAlgorithmOf, DhSecretKeyOf, HashAlgorithmOf, HmacAlgorithmOf,
};
use embedded_cal::{
    AeadAlgorithm, AeadProvider, Cal, DhAlgorithm, DhProvider, HashAlgorithm, HashProvider,
    HkdfProvider, HmacAlgorithm,
};
use lakers_shared::{
    BytesCcmIvLen, BytesCcmKeyLen, BytesElemLenPSK, BytesHashLen, BytesP256ElemLen, CcmTagLen,
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

    fn hkdf_expand(&mut self, prk: &BytesHashLen, info: &[u8], result: &mut [u8]) {
        let alg = HmacAlgorithmOf::<C>::from_cose_number(5).expect("cal must support hmac-sha-256");
        self.cal
            .hmac()
            .hkdf_expand(alg, prk, info, result)
            .expect("output length fits within 255 * hashlen");
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        let alg = HmacAlgorithmOf::<C>::from_cose_number(5).expect("cal must support hmac-sha-256");
        let prk = self
            .cal
            .hmac()
            .hkdf_extract(alg, Some(salt), ikm)
            .expect("hkdf-extract over a present salt is infallible");
        prk.as_ref()
            .try_into()
            .expect("hmac-sha-256 output is exactly 32 bytes")
    }

    fn hkdf_extract_psk(&mut self, salt: &BytesHashLen, ikm: &BytesElemLenPSK) -> BytesHashLen {
        let alg = HmacAlgorithmOf::<C>::from_cose_number(5).expect("cal must support hmac-sha-256");
        let prk = self
            .cal
            .hmac()
            .hkdf_extract(alg, Some(salt), ikm)
            .expect("hkdf-extract over a present salt is infallible");
        prk.as_ref()
            .try_into()
            .expect("hmac-sha-256 output is exactly 32 bytes")
    }

    fn aes_ccm_encrypt<const N: usize, Tag: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &[u8],
    ) -> EdhocBuffer<N> {
        let alg = aes_ccm_algorithm::<C, Tag>();
        let mut outbuffer =
            EdhocBuffer::<N>::new_from_slice(plaintext).expect("plaintext fits the output buffer");
        let aead = self.cal.aead();
        let key = aead.load_from_keydata(alg, key);

        #[allow(
            deprecated,
            reason = "EdhocBuffer has no non-deprecated mutable-slice accessor"
        )]
        let tag = aead.encrypt_in_place(&key, iv, &mut outbuffer.content[..plaintext.len()], ad);
        outbuffer
            .extend_from_slice(tag.as_ref())
            .expect("tag fits the output buffer");
        outbuffer
    }

    fn aes_ccm_decrypt<const N: usize, Tag: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<EdhocBuffer<N>, EDHOCError> {
        let alg = aes_ccm_algorithm::<C, Tag>();
        let plaintext_len = ciphertext.len() - Tag::LEN;
        let mut buffer = EdhocBuffer::<N>::new_from_slice(&ciphertext[..plaintext_len])
            .expect("ciphertext-without-tag fits the output buffer");
        let tag = &ciphertext[plaintext_len..];
        let aead = self.cal.aead();
        let key = aead.load_from_keydata(alg, key);

        #[allow(
            deprecated,
            reason = "EdhocBuffer has no non-deprecated mutable-slice accessor"
        )]
        aead.decrypt_in_place(&key, iv, &mut buffer.content[..plaintext_len], tag, ad)
            .map_err(|_| EDHOCError::MacVerificationFailed)?;
        Ok(buffer)
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        let alg = DhAlgorithmOf::<C>::from_cose_ecdh(1).expect("cal must support ecdh p-256");
        let dh = self.cal.dh();
        let secret: DhSecretKeyOf<C> = dh
            .import_secretkey_bytes(alg.clone(), private_key)
            .expect("private key is a valid p-256 scalar")
            .into();
        let public = dh
            .import_publickey_bytes(alg, public_key)
            .expect("public key is a valid compact p-256 point");
        let shared = dh
            .shared_secret(&secret, &public)
            .expect("both keys are for p-256");
        let secret_bytes = dh
            .raw_secret_bytes(&shared)
            .as_ref()
            .try_into()
            .expect("p-256 shared secret is exactly 32 bytes");
        secret_bytes
    }

    fn get_random_byte(&mut self) -> u8 {
        let mut byte = [0u8; 1];
        self.cal
            .try_fill_bytes(&mut byte)
            .expect("cal random number generation must not fail");
        byte[0]
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        let alg = DhAlgorithmOf::<C>::from_cose_ecdh(1).expect("cal must support ecdh p-256");
        let dh = self.cal.dh();
        let visible_secret = dh.generate_visible(alg);
        let private_key = dh
            .export_secretkey_bytes(&visible_secret)
            .as_ref()
            .try_into()
            .expect("p-256 scalar is exactly 32 bytes");
        let secret: DhSecretKeyOf<C> = visible_secret.into();
        let public = dh.public_key(&secret);
        let public_key = dh
            .export_publickey_bytes(&public)
            .as_ref()
            .try_into()
            .expect("compact p-256 public key is exactly 32 bytes");
        (private_key, public_key)
    }
}

fn aes_ccm_algorithm<C: Cal, Tag: CcmTagLen>() -> AeadAlgorithmOf<C> {
    // FIXME: update this when embedded-cal implement Tag::LEN = 16
    let cose_number = match Tag::LEN {
        8 => 10,
        other => panic!("aes-ccm with a {other}-byte tag is not supported by embedded-cal"),
    };
    AeadAlgorithmOf::<C>::from_cose_number(cose_number).expect("cal must support aes-ccm-16-64-128")
}

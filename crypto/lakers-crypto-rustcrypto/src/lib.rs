#![no_std]

use lakers_shared::{
    BufferCiphertext3, BufferPlaintext3, BytesCcmIvLen, BytesCcmKeyLen, BytesHashLen,
    BytesMaxBuffer, BytesP256ElemLen, BytesP256ElemLenPSK,
    Crypto as CryptoTrait, EDHOCError, AES_CCM_TAG_LEN, MAX_BUFFER_LEN, EdhocBuffer,
    EDHOCSuite, MAX_SUITES_LEN,
};

use ccm::AeadInPlace;
use ccm::KeyInit;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::point::DecompressPoint;
use sha2::Digest;

type AesCcm16_64_128 = ccm::Ccm<aes::Aes128, ccm::consts::U8, ccm::consts::U13>;

/// A type representing cryptographic operations through various RustCrypto crates (eg. [aes],
/// [ccm], [p256]).
///
/// Its size depends on the implementation of Rng passed in at creation.
pub struct Crypto<Rng: rand_core::RngCore + rand_core::CryptoRng> {
    rng: Rng,
}

impl<Rng: rand_core::RngCore + rand_core::CryptoRng> Crypto<Rng> {
    pub const fn new(rng: Rng) -> Self {
        Self { rng }
    }
}

impl<Rng: rand_core::RngCore + rand_core::CryptoRng> core::fmt::Debug for Crypto<Rng> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("lakers_crypto_rustcrypto::Crypto")
            .field("rng", &core::any::type_name::<Rng>())
            .finish()
    }
}

impl<Rng: rand_core::RngCore + rand_core::CryptoRng> CryptoTrait for Crypto<Rng> {
    fn supported_suites(&self) -> EdhocBuffer<MAX_SUITES_LEN> {
        EdhocBuffer::<MAX_SUITES_LEN>::new_from_slice(&[EDHOCSuite::CipherSuite2 as u8])
            .expect("This should never fail, as the slice is of the correct length")
    }

    fn sha256_digest(&mut self, message: &[u8]) -> BytesHashLen {
        let mut hasher = sha2::Sha256::new();
        hasher.update(message);
        hasher.finalize().into()
    }

    type HashInProcess<'a>
        = sha2::Sha256
    where
        Self: 'a;

    #[inline]
    fn sha256_start<'a>(&'a mut self) -> Self::HashInProcess<'a> {
        sha2::Sha256::new()
    }

    fn hkdf_expand(&mut self, prk: &BytesHashLen, info: &[u8], result: &mut [u8]) {
        let hkdf =
            hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).expect("Static size was checked at extract");
        hkdf.expand(info, result)
            .expect("Static lengths match the algorithm");
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        // While it'd be nice to just pass around an Hkdf, the extract output is not a type generic
        // of this trait (yet?).
        let mut extracted = hkdf::HkdfExtract::<sha2::Sha256>::new(Some(salt));
        extracted.input_ikm(ikm);
        extracted.finalize().0.into()
    }

    fn hkdf_extract_psk(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLenPSK) -> BytesHashLen {
        // While it'd be nice to just pass around an Hkdf, the extract output is not a type generic
        // of this trait (yet?).
        let mut extracted = hkdf::HkdfExtract::<sha2::Sha256>::new(Some(salt));
        extracted.input_ikm(ikm);
        extracted.finalize().0.into()
    }

    fn aes_ccm_encrypt_tag_8<const N: usize>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &[u8],
    ) -> EdhocBuffer<N> {
        let key = AesCcm16_64_128::new(key.into());
        let mut outbuffer = EdhocBuffer::new_from_slice(plaintext).unwrap();
        #[allow(
            deprecated,
            reason = "hax won't allow creating a .as_mut_slice() method"
        )]
        if let Ok(tag) =
            key.encrypt_in_place_detached(iv.into(), ad, &mut outbuffer.content[..plaintext.len()])
        {
            outbuffer.extend_from_slice(&tag).unwrap();
        } else {
            panic!("Preconfigured sizes should not allow encryption to fail")
        }
        outbuffer
    }

    fn aes_ccm_decrypt_tag_8<const N: usize>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<EdhocBuffer<N>, EDHOCError> {
        let key = AesCcm16_64_128::new(key.into());
        let plaintext_len = ciphertext.len() - AES_CCM_TAG_LEN;
        let mut buffer = EdhocBuffer::new_from_slice(&ciphertext[..plaintext_len]).unwrap();
        let tag = &ciphertext[plaintext_len..];
        #[allow(
            deprecated,
            reason = "hax won't allow creating a .as_mut_slice() method"
        )]
        key.decrypt_in_place_detached(
            iv.into(),
            ad,
            &mut buffer.content[..plaintext_len],
            tag.into(),
        )
        .map_err(|_| EDHOCError::MacVerificationFailed)?;
        Ok(buffer)
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        let secret = p256::SecretKey::from_bytes(private_key.as_slice().into())
            .expect("Invalid secret key generated");
        let public = p256::AffinePoint::decompress(
            public_key.into(),
            1.into(), /* Y coordinate choice does not matter for ECDH operation */
        )
        // While this can actually panic so far, the proper fix is in
        // https://github.com/lake-rs/lakers/issues/93 which will justify this to be a
        // panic (because after that, public key validity will be an invariant of the public key
        // type)
        .expect("Public key is not a good point");

        (*p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public).raw_secret_bytes()).into()
    }

    fn get_random_byte(&mut self) -> u8 {
        self.rng.next_u32() as _
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        let secret = p256::SecretKey::random(&mut self.rng);

        let public_key = secret.public_key().as_affine().x();
        let private_key = secret.to_bytes();

        (private_key.into(), public_key.into())
    }
}

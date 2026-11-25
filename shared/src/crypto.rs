//! Cryptographic operations of LAKE, performed through a [`Cal`]

use embedded_cal::accessor::{
    AeadAlgorithmOf, DhAlgorithmOf, DhSecretKeyOf, HashAlgorithmOf, HashProviderOf, HashStateOf,
    HmacAlgorithmOf,
};
pub use embedded_cal::Cal;
use embedded_cal::{
    AeadAlgorithm, AeadProvider, DhAlgorithm, DhProvider, HashAlgorithm, HashProvider,
    HkdfProvider, HmacAlgorithm,
};
pub use rand_core::TryCryptoRng;

use crate::{
    BufferPsk, BytesCcmIvLen, BytesCcmKeyLen, BytesHashLen, BytesP256ElemLen, LAKEError, LAKESuite,
    LakeBuffer, AES_CCM_TAG_LEN, MAX_SUITES_LEN,
};

/// Returns the SUITES_I array, or an error if selected_suite is not supported.
///
/// The SUITES_I list will contain:
/// - the selected suite at the last position
/// - an ordered list of preferred suites in the first positions
pub fn prepare_suites_i(
    supported_suites: &LakeBuffer<MAX_SUITES_LEN>,
    selected_suite: u8,
) -> Result<LakeBuffer<MAX_SUITES_LEN>, LAKEError> {
    // TODO: implement a re-positioning algorithm, considering preferred and selected suites (see Section 5.2.2 of RFC 9528)
    //       for now, we only support a single suite so we just return it
    // NOTE: should we assume that supported_suites == preferred_suites?
    if supported_suites.contains(&(selected_suite)) {
        LakeBuffer::<MAX_SUITES_LEN>::new_from_slice(&[selected_suite.into()])
            .map_err(|_| LAKEError::UnsupportedCipherSuite)
    } else {
        Err(LAKEError::UnsupportedCipherSuite)
    }
}

/// Returns the list of cryptographic suites supported by this crate.
pub fn supported_suites() -> LakeBuffer<MAX_SUITES_LEN> {
    LakeBuffer::<MAX_SUITES_LEN>::new_from_slice(&[LAKESuite::CipherSuite2 as u8])
        .expect("the slice is of a length that always fits")
}

/// Calculates a SHA-256 hash from a slice.
///
/// Use [`Sha256`] when the message is not already available in a single slice.
pub fn sha256_digest(crypto: &mut impl Cal, message: &[u8]) -> BytesHashLen {
    let mut hash = Sha256::new(crypto);
    hash.update(message);
    hash.finalize()
}

/// A SHA-256 hash calculation that is fed incrementally.
#[hax_lib::opaque]
pub struct Sha256<'a, C: Cal> {
    hash: &'a mut HashProviderOf<C>,
    state: HashStateOf<C>,
}

#[hax_lib::attributes]
impl<'a, C: Cal> Sha256<'a, C> {
    #[hax_lib::opaque]
    pub fn new(crypto: &'a mut C) -> Self {
        let alg = HashAlgorithmOf::<C>::from_ni_id(1).expect("cal must support sha-256");
        let hash = crypto.hash();
        let state = hash.init(alg);
        Self { hash, state }
    }

    #[hax_lib::opaque]
    pub fn update(&mut self, data: &[u8]) {
        self.hash.update(&mut self.state, data);
    }

    #[hax_lib::opaque]
    pub fn finalize(self) -> BytesHashLen {
        self.hash
            .finalize(self.state)
            .as_ref()
            .try_into()
            .expect("sha-256 output is exactly 32 bytes")
    }
}

fn hmac_sha256_algorithm<C: Cal>() -> HmacAlgorithmOf<C> {
    HmacAlgorithmOf::<C>::from_cose_number(5).expect("cal must support hmac-sha-256")
}

#[hax_lib::opaque]
pub fn hkdf_expand<C: Cal>(crypto: &mut C, prk: &BytesHashLen, info: &[u8], result: &mut [u8]) {
    crypto
        .hmac()
        .hkdf_expand(hmac_sha256_algorithm::<C>(), prk, info, result)
        .expect("output length fits within 255 * hashlen");
}

#[hax_lib::opaque]
pub fn hkdf_extract<C: Cal>(crypto: &mut C, salt: &BytesHashLen, ikm: &[u8]) -> BytesHashLen {
    crypto
        .hmac()
        .hkdf_extract(hmac_sha256_algorithm::<C>(), Some(salt), ikm)
        .expect("hkdf-extract over a present salt is infallible")
        .as_ref()
        .try_into()
        .expect("hmac-sha-256 output is exactly 32 bytes")
}

fn aes_ccm_16_64_128_algorithm<C: Cal>() -> AeadAlgorithmOf<C> {
    AeadAlgorithmOf::<C>::from_cose_number(10).expect("cal must support aes-ccm-16-64-128")
}

/// Encrypts `plaintext` with AES-CCM-16-64-128, and returns it followed by the authentication tag.
#[hax_lib::opaque]
pub fn aes_ccm_encrypt<C: Cal, const N: usize>(
    crypto: &mut C,
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &[u8],
    plaintext: &[u8],
) -> LakeBuffer<N> {
    let mut outbuffer =
        LakeBuffer::<N>::new_from_slice(plaintext).expect("plaintext fits the output buffer");
    let aead = crypto.aead();
    let key = aead.load_from_keydata(aes_ccm_16_64_128_algorithm::<C>(), key);

    #[allow(
        deprecated,
        reason = "LakeBuffer has no non-deprecated mutable-slice accessor"
    )]
    let tag = aead.encrypt_in_place(&key, iv, &mut outbuffer.content[..plaintext.len()], ad);
    outbuffer
        .extend_from_slice(tag.as_ref())
        .expect("tag fits the output buffer");
    outbuffer
}

/// Decrypts `ciphertext`, which carries the trailing [`AES_CCM_TAG_LEN`] byte authentication tag,
/// with AES-CCM-16-64-128, and verifies that tag.
///
/// Returns an error if `ciphertext` is shorter than the tag, or if the plaintext exceeds the
/// output buffer `N`.
#[hax_lib::opaque]
pub fn aes_ccm_decrypt<C: Cal, const N: usize>(
    crypto: &mut C,
    key: &BytesCcmKeyLen,
    iv: &BytesCcmIvLen,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<LakeBuffer<N>, LAKEError> {
    let plaintext_len = ciphertext
        .len()
        .checked_sub(AES_CCM_TAG_LEN)
        .ok_or(LAKEError::ParsingError)?;
    let (plaintext, tag) = ciphertext.split_at(plaintext_len);
    let mut buffer =
        LakeBuffer::<N>::new_from_slice(plaintext).map_err(|_| LAKEError::ParsingError)?;
    let aead = crypto.aead();
    let key = aead.load_from_keydata(aes_ccm_16_64_128_algorithm::<C>(), key);

    #[allow(
        deprecated,
        reason = "LakeBuffer has no non-deprecated mutable-slice accessor"
    )]
    aead.decrypt_in_place(&key, iv, &mut buffer.content[..plaintext_len], tag, ad)
        .map_err(|_| LAKEError::MacVerificationFailed)?;
    Ok(buffer)
}

fn p256_algorithm<C: Cal>() -> DhAlgorithmOf<C> {
    DhAlgorithmOf::<C>::from_cose_ecdh(1).expect("cal must support ecdh p-256")
}

#[hax_lib::opaque]
pub fn p256_ecdh<C: Cal>(
    crypto: &mut C,
    private_key: &BytesP256ElemLen,
    public_key: &BytesP256ElemLen,
) -> BytesP256ElemLen {
    let dh = crypto.dh();
    let secret: DhSecretKeyOf<C> = dh
        .import_secretkey_bytes(p256_algorithm::<C>(), private_key)
        .expect("private key is a valid p-256 scalar")
        .into();
    let public = dh
        .import_publickey_bytes(p256_algorithm::<C>(), public_key)
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

/// Generates a P-256 key pair, and returns the private key and the x coordinate of the public key.
#[hax_lib::opaque]
pub fn p256_generate_key_pair<C: Cal>(crypto: &mut C) -> (BytesP256ElemLen, BytesP256ElemLen) {
    let dh = crypto.dh();
    let visible_secret = dh.generate_visible(p256_algorithm::<C>());
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

pub fn get_random_byte(crypto: &mut impl TryCryptoRng) -> u8 {
    let mut byte = [0u8; 1];
    crypto
        .try_fill_bytes(&mut byte)
        .expect("cal random number generation must not fail");
    byte[0]
}

/// Interface between the lakers crate and any implementations of the required crypto primitives.
///
/// Sending cryptographic operations through a trait gives the library the flexibility to use
/// hardware acceleration on microcontrollers, implementations that facilitate hacspec/hax
/// verification, or software implementations.
///
/// The crypto trait itself operates on an exclusive reference, which is useful for the hardware
/// implementations that can only perform a single operation at a time.
///
/// Many implementations will have a Default constructor or will be Clone (even Copy); either
/// facilitates storing multiple LAKE exchanges at a time. When neither is an option, the
/// remaining options are to wrap a Crypto implementation into interior mutability using the
/// platform's mutex, or to refactor the main initiator and responder objects into a form where the
/// cryptography implementation can be taken out and stored separately.
pub trait Crypto: core::fmt::Debug {
    /// Returns the list of cryptographic suites supported by the backend implementation.
    fn supported_suites(&self) -> LakeBuffer<MAX_SUITES_LEN>;
    /// Calculate a SHA256 hash from a slice.
    ///
    /// This should only be used when the slice is already at hand or very small; otherwise, use
    /// [`Self::sha256_start()`] and the `digest` interface.
    ///
    /// This is currently not provided due to [hax
    /// constraints](https://github.com/cryspen/hax/issues/1495), but can be provided as:
    ///
    /// ```ignore
    /// let mut hash = self.sha256_start();
    /// use digest::Digest;
    /// hash.update(message);
    /// hash.finalize().into()
    /// ```
    fn sha256_digest(&mut self, message: &[u8]) -> BytesHashLen;
    /// This is [in process of being moved](https://github.com/lake-rs/lakers/issues/437) to something more embedded-cal friendly.
    ///
    /// You can use the type, but don't rely on it being `Default`, for that may panic.
    type HashInProcess<'a>: digest::Digest
        + digest::OutputSizeUser<OutputSize = digest::typenum::U32>
    where
        Self: 'a;
    fn sha256_start<'a>(&'a mut self) -> Self::HashInProcess<'a>;
    fn hkdf_expand(&mut self, prk: &BytesHashLen, info: &[u8], result: &mut [u8]);
    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen;
    fn hkdf_extract_psk(&mut self, salt: &BytesHashLen, ikm: &BufferPsk) -> BytesHashLen;
    fn aes_ccm_encrypt<const N: usize, TagLen: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &[u8],
    ) -> LakeBuffer<N>;
    /// Decrypt `ciphertext`, which carries the trailing `TagLen::LEN`-byte authentication tag, and
    /// verify that tag.
    ///
    /// Returns an error if `ciphertext` is shorter than `TagLen::LEN`, or if the plaintext exceeds
    /// the output buffer `N`.
    fn aes_ccm_decrypt<const N: usize, TagLen: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<LakeBuffer<N>, LAKEError>;
    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen;
    fn get_random_byte(&mut self) -> u8;
    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen);
}

/// Trait for valid CCM tag lengths.
/// Only implemented for sizes we explicitly use (8 and 16 bytes).
pub trait CcmTagLen {
    const LEN: usize;
}
pub struct CcmTagLen8;
impl CcmTagLen for CcmTagLen8 {
    const LEN: usize = 8;
}

pub struct CcmTagLen16;
impl CcmTagLen for CcmTagLen16 {
    const LEN: usize = 16;
}

// Blanket implementation because it is never used ownedly
//
// ("region parameter `'a/#1` out of range when instantiating args=[&'_/#0 mut T/#1]").
// https://github.com/cryspen/hax/issues/1907
#[cfg(not(hax))]
impl<T: Crypto> Crypto for &mut T {
    type HashInProcess<'a>
        = T::HashInProcess<'a>
    where
        Self: 'a;

    fn supported_suites(&self) -> LakeBuffer<MAX_SUITES_LEN> {
        T::supported_suites(self)
    }

    fn sha256_digest(&mut self, message: &[u8]) -> BytesHashLen {
        T::sha256_digest(self, message)
    }

    fn sha256_start<'a>(&'a mut self) -> Self::HashInProcess<'a> {
        T::sha256_start(self)
    }

    fn hkdf_expand(&mut self, prk: &BytesHashLen, info: &[u8], result: &mut [u8]) {
        T::hkdf_expand(self, prk, info, result)
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        T::hkdf_extract(self, salt, ikm)
    }

    fn hkdf_extract_psk(&mut self, salt: &BytesHashLen, ikm: &BufferPsk) -> BytesHashLen {
        T::hkdf_extract_psk(self, salt, ikm)
    }

    fn aes_ccm_encrypt<const N: usize, TagLen: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &[u8],
    ) -> LakeBuffer<N> {
        T::aes_ccm_encrypt::<N, TagLen>(self, key, iv, ad, plaintext)
    }

    fn aes_ccm_decrypt<const N: usize, TagLen: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<LakeBuffer<N>, LAKEError> {
        T::aes_ccm_decrypt::<N, TagLen>(self, key, iv, ad, ciphertext)
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        T::p256_ecdh(self, private_key, public_key)
    }

    fn get_random_byte(&mut self) -> u8 {
        T::get_random_byte(self)
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        T::p256_generate_key_pair(self)
    }
}

pub mod test_helper {
    use super::*;

    pub fn test_aes_ccm_roundtrip<C: Crypto, Tag: CcmTagLen>(crypto: &mut C) {
        let key: BytesCcmKeyLen = [
            0x26, 0x51, 0x1f, 0xb5, 0x1f, 0xcf, 0xa7, 0x5c, 0xb4, 0xb4, 0x4d, 0xa7, 0x5a, 0x6e,
            0x5a, 0x0e,
        ];

        let iv: BytesCcmIvLen = [
            0x5a, 0x8a, 0xa4, 0x85, 0xc3, 0x16, 0xe9, 0x40, 0x3a, 0xff, 0x85, 0x9f, 0xbb,
        ];

        let ad = [
            0xa1, 0x6a, 0x2e, 0x74, 0x1f, 0x1c, 0xd9, 0x71, 0x72, 0x85, 0xb6, 0xd8, 0x82, 0xc1,
            0xfc, 0x53, 0x65, 0x5e, 0x97, 0x73, 0x76, 0x1a, 0xd6, 0x97, 0xa7, 0xee, 0x64, 0x10,
            0x18, 0x4c, 0x79, 0x82,
        ];
        let plaintext = [
            0x87, 0x39, 0xb4, 0xbe, 0xa1, 0xa0, 0x99, 0xfe, 0x54, 0x74, 0x99, 0xcb, 0xc6, 0xd1,
            0xb1, 0x3d, 0x84, 0x9b, 0x80, 0x84, 0xc9, 0xb6, 0xac, 0xc5,
        ];

        let ciphertext = crypto.aes_ccm_encrypt::<64, Tag>(&key, &iv, &ad, &plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + Tag::LEN);

        let decrypted = crypto
            .aes_ccm_decrypt::<64, Tag>(&key, &iv, &ad, ciphertext.as_slice())
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), &plaintext);
    }

    pub fn test_aes_ccm_tag_8<C: Crypto>(crypto: &mut C) {
        type Tag = CcmTagLen8;
        let key: BytesCcmKeyLen = [
            0x36, 0x8f, 0x35, 0xa1, 0xf8, 0x0e, 0xaa, 0xac, 0xd6, 0xbb, 0x13, 0x66, 0x09, 0x38,
            0x97, 0x27,
        ];

        let iv: BytesCcmIvLen = [
            0x84, 0x2a, 0x84, 0x45, 0x84, 0x75, 0x02, 0xea, 0x77, 0x36, 0x3a, 0x16, 0xb6,
        ];

        let ad = [
            0x34, 0x39, 0x6d, 0xfc, 0xfa, 0x6f, 0x74, 0x2a, 0xea, 0x70, 0x40, 0x97, 0x6b, 0xd5,
            0x96, 0x49, 0x7a, 0x7a, 0x6f, 0xa4, 0xfb, 0x85, 0xee, 0x8e, 0x4c, 0xa3, 0x94, 0xd0,
            0x20, 0x95, 0xb7, 0xbf,
        ];
        let plaintext = [
            0x1c, 0xcc, 0xd5, 0x58, 0x25, 0x31, 0x6a, 0x94, 0xc5, 0x97, 0x9e, 0x04, 0x93, 0x10,
            0xd1, 0xd7, 0x17, 0xcd, 0xfb, 0x76, 0x24, 0x28, 0x9d, 0xac,
        ];

        let expected_ct: [u8; 32] = [
            0x1a, 0x58, 0x09, 0x4f, 0x0e, 0x8c, 0x60, 0x35, 0xa5, 0x58, 0x4b, 0xfa, 0x8d, 0x10,
            0x09, 0xc5, 0xf7, 0x8f, 0xd2, 0xca, 0x48, 0x7f, 0xf2, 0x22, 0xf6, 0xd1, 0xd8, 0x97,
            0xd6, 0x05, 0x16, 0x18,
        ];

        let ciphertext = crypto.aes_ccm_encrypt::<64, Tag>(&key, &iv, &ad, &plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + Tag::LEN);
        assert_eq!(
            ciphertext,
            LakeBuffer::new_from_slice(&expected_ct).expect("expected_ct.length() <= 64")
        );

        let decrypted = crypto
            .aes_ccm_decrypt::<64, Tag>(&key, &iv, &ad, ciphertext.as_slice())
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), &plaintext);
    }

    pub fn test_aes_ccm_tag_16<C: Crypto>(crypto: &mut C) {
        type Tag = CcmTagLen16;
        let key: BytesCcmKeyLen = [
            0x41, 0x89, 0x35, 0x1b, 0x5c, 0xae, 0xa3, 0x75, 0xa0, 0x29, 0x9e, 0x81, 0xc6, 0x21,
            0xbf, 0x43,
        ];

        let iv: BytesCcmIvLen = [
            0x48, 0xc0, 0x90, 0x69, 0x30, 0x56, 0x1e, 0x0a, 0xb0, 0xef, 0x4c, 0xd9, 0x72,
        ];

        let ad = [
            0x40, 0xa2, 0x7c, 0x1d, 0x1e, 0x23, 0xea, 0x3d, 0xbe, 0x80, 0x56, 0xb2, 0x77, 0x48,
            0x61, 0xa4, 0xa2, 0x01, 0xcc, 0xe4, 0x9f, 0x19, 0x99, 0x7d, 0x19, 0x20, 0x6d, 0x8c,
            0x8a, 0x34, 0x39, 0x51,
        ];
        let plaintext = [
            0x45, 0x35, 0xd1, 0x2b, 0x43, 0x77, 0x92, 0x8a, 0x7c, 0x0a, 0x61, 0xc9, 0xf8, 0x25,
            0xa4, 0x86, 0x71, 0xea, 0x05, 0x91, 0x07, 0x48, 0xc8, 0xef,
        ];

        let expected_ct: [u8; 40] = [
            0x26, 0xc5, 0x69, 0x61, 0xc0, 0x35, 0xa7, 0xe4, 0x52, 0xcc, 0xe6, 0x1b, 0xc6, 0xee,
            0x22, 0x0d, 0x77, 0xb3, 0xf9, 0x4d, 0x18, 0xfd, 0x10, 0xb6, 0xd8, 0x0e, 0x8b, 0xf8,
            0x0f, 0x4a, 0x46, 0xca, 0xb0, 0x6d, 0x43, 0x13, 0xf0, 0xdb, 0x9b, 0xe9,
        ];

        let ciphertext = crypto.aes_ccm_encrypt::<64, Tag>(&key, &iv, &ad, &plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + Tag::LEN);
        assert_eq!(
            ciphertext,
            LakeBuffer::new_from_slice(&expected_ct).expect("expected_ct.length() < 64")
        );

        let decrypted = crypto
            .aes_ccm_decrypt::<64, Tag>(&key, &iv, &ad, ciphertext.as_slice())
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), &plaintext);
    }
}

#[cfg(test)]
mod tests {
    use embedded_cal_rustcrypto::Standalone;
    use hexlit::hex;
    use rstest::rstest;

    use super::*;
    use crate::{AES_CCM_IV_LEN, AES_CCM_KEY_LEN, MAX_INFO_LEN, SHA256_DIGEST_LEN};

    #[test]
    fn test_aes_ccm_roundtrip() {
        let key: BytesCcmKeyLen = [
            0x26, 0x51, 0x1f, 0xb5, 0x1f, 0xcf, 0xa7, 0x5c, 0xb4, 0xb4, 0x4d, 0xa7, 0x5a, 0x6e,
            0x5a, 0x0e,
        ];

        let iv: BytesCcmIvLen = [
            0x5a, 0x8a, 0xa4, 0x85, 0xc3, 0x16, 0xe9, 0x40, 0x3a, 0xff, 0x85, 0x9f, 0xbb,
        ];

        let ad = [
            0xa1, 0x6a, 0x2e, 0x74, 0x1f, 0x1c, 0xd9, 0x71, 0x72, 0x85, 0xb6, 0xd8, 0x82, 0xc1,
            0xfc, 0x53, 0x65, 0x5e, 0x97, 0x73, 0x76, 0x1a, 0xd6, 0x97, 0xa7, 0xee, 0x64, 0x10,
            0x18, 0x4c, 0x79, 0x82,
        ];
        let plaintext = [
            0x87, 0x39, 0xb4, 0xbe, 0xa1, 0xa0, 0x99, 0xfe, 0x54, 0x74, 0x99, 0xcb, 0xc6, 0xd1,
            0xb1, 0x3d, 0x84, 0x9b, 0x80, 0x84, 0xc9, 0xb6, 0xac, 0xc5,
        ];

        let mut crypto = Standalone::standalone();
        let ciphertext: LakeBuffer<64> = aes_ccm_encrypt(&mut crypto, &key, &iv, &ad, &plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + AES_CCM_TAG_LEN);

        let decrypted: LakeBuffer<64> =
            aes_ccm_decrypt(&mut crypto, &key, &iv, &ad, ciphertext.as_slice())
                .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), &plaintext);
    }

    #[test]
    fn test_aes_ccm_tag_8() {
        let key: BytesCcmKeyLen = [
            0x36, 0x8f, 0x35, 0xa1, 0xf8, 0x0e, 0xaa, 0xac, 0xd6, 0xbb, 0x13, 0x66, 0x09, 0x38,
            0x97, 0x27,
        ];

        let iv: BytesCcmIvLen = [
            0x84, 0x2a, 0x84, 0x45, 0x84, 0x75, 0x02, 0xea, 0x77, 0x36, 0x3a, 0x16, 0xb6,
        ];

        let ad = [
            0x34, 0x39, 0x6d, 0xfc, 0xfa, 0x6f, 0x74, 0x2a, 0xea, 0x70, 0x40, 0x97, 0x6b, 0xd5,
            0x96, 0x49, 0x7a, 0x7a, 0x6f, 0xa4, 0xfb, 0x85, 0xee, 0x8e, 0x4c, 0xa3, 0x94, 0xd0,
            0x20, 0x95, 0xb7, 0xbf,
        ];
        let plaintext = [
            0x1c, 0xcc, 0xd5, 0x58, 0x25, 0x31, 0x6a, 0x94, 0xc5, 0x97, 0x9e, 0x04, 0x93, 0x10,
            0xd1, 0xd7, 0x17, 0xcd, 0xfb, 0x76, 0x24, 0x28, 0x9d, 0xac,
        ];

        let expected_ct: [u8; 32] = [
            0x1a, 0x58, 0x09, 0x4f, 0x0e, 0x8c, 0x60, 0x35, 0xa5, 0x58, 0x4b, 0xfa, 0x8d, 0x10,
            0x09, 0xc5, 0xf7, 0x8f, 0xd2, 0xca, 0x48, 0x7f, 0xf2, 0x22, 0xf6, 0xd1, 0xd8, 0x97,
            0xd6, 0x05, 0x16, 0x18,
        ];

        let mut crypto = Standalone::standalone();
        let ciphertext: LakeBuffer<64> = aes_ccm_encrypt(&mut crypto, &key, &iv, &ad, &plaintext);
        assert_eq!(ciphertext.as_slice(), &expected_ct);

        let decrypted: LakeBuffer<64> =
            aes_ccm_decrypt(&mut crypto, &key, &iv, &ad, ciphertext.as_slice())
                .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), &plaintext);
    }

    #[test]
    fn test_aes_ccm_rejects_bad_ciphertext() {
        let mut crypto = Standalone::standalone();
        let key = [0; AES_CCM_KEY_LEN];
        let iv = [0; AES_CCM_IV_LEN];

        let ciphertext: LakeBuffer<64> = aes_ccm_encrypt(&mut crypto, &key, &iv, &[], b"plaintext");
        assert_eq!(
            aes_ccm_decrypt::<_, 4>(&mut crypto, &key, &iv, &[], ciphertext.as_slice()),
            Err(LAKEError::ParsingError)
        );
        assert_eq!(
            aes_ccm_decrypt::<_, 64>(&mut crypto, &key, &iv, &[], &[0; AES_CCM_TAG_LEN - 1]),
            Err(LAKEError::ParsingError)
        );
        assert_eq!(
            aes_ccm_decrypt::<_, 64>(&mut crypto, &key, &iv, b"other", ciphertext.as_slice()),
            Err(LAKEError::MacVerificationFailed)
        );
    }

    #[test]
    fn test_p256_ecdh_agrees() {
        let mut crypto = Standalone::standalone();
        let (x, g_x) = p256_generate_key_pair(&mut crypto);
        let (y, g_y) = p256_generate_key_pair(&mut crypto);

        assert_eq!(
            p256_ecdh(&mut crypto, &x, &g_y),
            p256_ecdh(&mut crypto, &y, &g_x)
        );
    }

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
        let mut crypto = Standalone::standalone();

        let mut prk = [0; SHA256_DIGEST_LEN];
        prk[..prk_slice.len()].copy_from_slice(prk_slice);
        let mut info = [0; MAX_INFO_LEN];
        info[..info_slice.len()].copy_from_slice(info_slice);

        let mut output = [0; 82];
        let output = &mut output[..output_length];
        hkdf_expand(&mut crypto, &prk, &info[..info_slice.len()], output);
        assert_eq!(output, expected_okm_slice);
    }
}

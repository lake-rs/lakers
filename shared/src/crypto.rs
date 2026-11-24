//! Cryptography trait back-end for the lakers-crypto crate

use super::*;

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

    /// The private key used by [`Crypto::p256_ecdsa_sign`].
    ///
    /// Backends that hold keys in memory use [`BytesP256ElemLen`]; backends that keep keys in
    /// secure storage (PSA key IDs, HSM or TPM handles, ...) use their own key reference.
    type SigningKey;

    fn p256_ecdsa_sign(
        &mut self,
        signing_key: &Self::SigningKey,
        message: &[u8],
    ) -> Result<BytesSignature, LAKEError>;

    fn p256_ecdsa_verify(
        &mut self,
        public_key_x: &BytesP256ElemLen,
        message: &[u8],
        signature: &BytesSignature,
    ) -> Result<bool, LAKEError>;
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

    type SigningKey = T::SigningKey;

    fn p256_ecdsa_sign(
        &mut self,
        signing_key: &Self::SigningKey,
        message: &[u8],
    ) -> Result<BytesSignature, LAKEError> {
        T::p256_ecdsa_sign(self, signing_key, message)
    }

    fn p256_ecdsa_verify(
        &mut self,
        public_key_x: &BytesP256ElemLen,
        message: &[u8],
        signature: &BytesSignature,
    ) -> Result<bool, LAKEError> {
        T::p256_ecdsa_verify(self, public_key_x, message, signature)
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

    pub const RFC6979_PRIVATE_KEY: BytesP256ElemLen = [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6,
        0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f,
        0x67, 0x21,
    ];
    const RFC6979_PUBLIC_KEY_X_Y_ODD: BytesP256ElemLen = [
        0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d,
        0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2,
        0x9f, 0xb6,
    ];
    const RFC6979_MESSAGE: &[u8] = b"sample";
    const RFC6979_SIGNATURE: BytesSignature = [
        0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81,
        0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf,
        0x37, 0x16, 0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6,
        0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f,
        0x84, 0x3a, 0xcd, 0xa8,
    ];

    const CAVP_PUBLIC_KEY_X_Y_EVEN: BytesP256ElemLen = [
        0xe0, 0xfc, 0x6a, 0x6f, 0x50, 0xe1, 0xc5, 0x74, 0x75, 0x67, 0x3e, 0xe5, 0x4e, 0x3a, 0x57,
        0xf9, 0xa4, 0x9f, 0x33, 0x28, 0xe7, 0x43, 0xbf, 0x52, 0xf3, 0x35, 0xe3, 0xee, 0xaa, 0x3d,
        0x28, 0x64,
    ];
    const CAVP_MESSAGE: &[u8] = &[
        0x73, 0xc5, 0xf6, 0xa6, 0x74, 0x56, 0xae, 0x48, 0x20, 0x9b, 0x5f, 0x85, 0xd1, 0xe7, 0xde,
        0x77, 0x58, 0xbf, 0x23, 0x53, 0x00, 0xc6, 0xae, 0x2b, 0xdc, 0xeb, 0x1d, 0xcb, 0x27, 0xa7,
        0x73, 0x0f, 0xb6, 0x8c, 0x95, 0x0b, 0x7f, 0xca, 0xda, 0x0e, 0xcc, 0x46, 0x61, 0xd3, 0x57,
        0x82, 0x30, 0xf2, 0x25, 0xa8, 0x75, 0xe6, 0x9a, 0xaa, 0x17, 0xf1, 0xe7, 0x1c, 0x6b, 0xe5,
        0xc8, 0x31, 0xf2, 0x26, 0x63, 0xba, 0xc6, 0x3d, 0x0c, 0x7a, 0x96, 0x35, 0xed, 0xb0, 0x04,
        0x3f, 0xf8, 0xc6, 0xf2, 0x64, 0x70, 0xf0, 0x2a, 0x7b, 0xc5, 0x65, 0x56, 0xf1, 0x43, 0x7f,
        0x06, 0xdf, 0xa2, 0x7b, 0x48, 0x7a, 0x6c, 0x42, 0x90, 0xd8, 0xba, 0xd3, 0x8d, 0x48, 0x79,
        0xb3, 0x34, 0xe3, 0x41, 0xba, 0x09, 0x2d, 0xde, 0x4e, 0x4a, 0xe6, 0x94, 0xa9, 0xc0, 0x93,
        0x02, 0xe2, 0xdb, 0xf4, 0x43, 0x58, 0x1c, 0x08,
    ];
    const CAVP_SIGNATURE: BytesSignature = [
        0x1d, 0x75, 0x83, 0x0c, 0xd3, 0x6f, 0x4c, 0x9a, 0xa1, 0x81, 0xb2, 0xc4, 0x22, 0x1e, 0x87,
        0xf1, 0x76, 0xb7, 0xf0, 0x5b, 0x7c, 0x87, 0x82, 0x4e, 0x82, 0xe3, 0x96, 0xc8, 0x83, 0x15,
        0xc4, 0x07, 0xcb, 0x2a, 0xcb, 0x01, 0xda, 0xc9, 0x6e, 0xfc, 0x53, 0xa3, 0x2d, 0x4a, 0x0d,
        0x85, 0xd0, 0xc2, 0xe4, 0x89, 0x55, 0x21, 0x47, 0x83, 0xec, 0xf5, 0x0a, 0x4f, 0x04, 0x14,
        0xa3, 0x19, 0xc0, 0x5a,
    ];

    pub fn test_ecdsa_known_answer<C: Crypto>(crypto: &mut C) {
        for (public_key_x, message, signature) in [
            (
                &RFC6979_PUBLIC_KEY_X_Y_ODD,
                RFC6979_MESSAGE,
                &RFC6979_SIGNATURE,
            ),
            (&CAVP_PUBLIC_KEY_X_Y_EVEN, CAVP_MESSAGE, &CAVP_SIGNATURE),
        ] {
            assert!(crypto
                .p256_ecdsa_verify(public_key_x, message, signature)
                .expect("verification should succeed"));
        }
    }

    /// `signing_key` must be [`RFC6979_PRIVATE_KEY`].
    pub fn test_ecdsa_roundtrip<C: Crypto>(crypto: &mut C, signing_key: &C::SigningKey) {
        let signature = crypto
            .p256_ecdsa_sign(signing_key, CAVP_MESSAGE)
            .expect("signing should succeed");

        assert!(crypto
            .p256_ecdsa_verify(&RFC6979_PUBLIC_KEY_X_Y_ODD, CAVP_MESSAGE, &signature)
            .expect("verification should succeed"));
    }

    pub fn test_ecdsa_rejects_bad_signature<C: Crypto>(crypto: &mut C) {
        let mut tampered_r = RFC6979_SIGNATURE;
        tampered_r[0] ^= 0x01;
        let mut tampered_s = RFC6979_SIGNATURE;
        tampered_s[SIGNATURE_LENGTH - 1] ^= 0x01;

        for (public_key_x, message, signature) in [
            (
                &CAVP_PUBLIC_KEY_X_Y_EVEN,
                RFC6979_MESSAGE,
                &RFC6979_SIGNATURE,
            ),
            (
                &RFC6979_PUBLIC_KEY_X_Y_ODD,
                CAVP_MESSAGE,
                &RFC6979_SIGNATURE,
            ),
            (&RFC6979_PUBLIC_KEY_X_Y_ODD, RFC6979_MESSAGE, &tampered_r),
            (&RFC6979_PUBLIC_KEY_X_Y_ODD, RFC6979_MESSAGE, &tampered_s),
            (
                &RFC6979_PUBLIC_KEY_X_Y_ODD,
                RFC6979_MESSAGE,
                &[0; SIGNATURE_LENGTH],
            ),
        ] {
            assert!(!crypto
                .p256_ecdsa_verify(public_key_x, message, signature)
                .expect("verification should succeed"));
        }
    }
}

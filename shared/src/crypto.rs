//! Cryptography trait back-end for the lakers-crypto crate

use super::*;

/// Returns the SUITES_I array, or an error if selected_suite is not supported.
///
/// The SUITES_I list will contain:
/// - the selected suite at the last position
/// - an ordered list of preferred suites in the first positions
pub fn prepare_suites_i(
    supported_suites: &EdhocBuffer<MAX_SUITES_LEN>,
    selected_suite: u8,
) -> Result<EdhocBuffer<MAX_SUITES_LEN>, EDHOCError> {
    // TODO: implement a re-positioning algorithm, considering preferred and selected suites (see Section 5.2.2 of RFC 9528)
    //       for now, we only support a single suite so we just return it
    // NOTE: should we assume that supported_suites == preferred_suites?
    if supported_suites.contains(&(selected_suite)) {
        EdhocBuffer::<MAX_SUITES_LEN>::new_from_slice(&[selected_suite.into()])
            .map_err(|_| EDHOCError::UnsupportedCipherSuite)
    } else {
        Err(EDHOCError::UnsupportedCipherSuite)
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
/// facilitates storing multiple EDHOC exchanges at a time. When neither is an option, the
/// remaining options are to wrap a Crypto implementation into interior mutability using the
/// platform's mutex, or to refactor the main initiator and responder objects into a form where the
/// cryptography implementation can be taken out and stored separately.
pub trait Crypto: core::fmt::Debug {
    /// Returns the list of cryptographic suites supported by the backend implementation.
    fn supported_suites(&self) -> EdhocBuffer<MAX_SUITES_LEN>;
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
    type HashInProcess<'a>: digest::Digest
        + digest::OutputSizeUser<OutputSize = digest::typenum::U32>
    where
        Self: 'a;
    fn sha256_start<'a>(&'a mut self) -> Self::HashInProcess<'a>;
    fn hkdf_expand(&mut self, prk: &BytesHashLen, info: &[u8], result: &mut [u8]);
    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen;
    fn aes_ccm_encrypt<const N: usize, TagLen: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &[u8],
    ) -> EdhocBuffer<N>;
    fn aes_ccm_decrypt<const N: usize, TagLen: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<EdhocBuffer<N>, EDHOCError>;
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
            EdhocBuffer::new_from_slice(&expected_ct).expect("expected_ct.length() <= 64")
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
            EdhocBuffer::new_from_slice(&expected_ct).expect("expected_ct.length() < 64")
        );

        let decrypted = crypto
            .aes_ccm_decrypt::<64, Tag>(&key, &iv, &ad, ciphertext.as_slice())
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), &plaintext);
    }
}

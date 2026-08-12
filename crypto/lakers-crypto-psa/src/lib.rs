#![no_std]

use lakers_shared::{Crypto as CryptoTrait, *};
use psa_crypto::operations::{
    aead, asym_signature, hash::hash_compute, key_agreement, key_management, other::generate_random,
};
use psa_crypto::types::algorithm::{
    Aead, AeadWithDefaultLengthTag, AsymmetricSignature, Hash, KeyAgreement, RawKeyAgreement,
};
use psa_crypto::types::key::{Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags};

#[no_mangle]
pub extern "C" fn mbedtls_hardware_poll(
    _data: *mut ::core::ffi::c_void,
    _output: *mut ::core::ffi::c_uchar,
    len: usize,
    olen: *mut usize,
) -> ::core::ffi::c_int {
    unsafe {
        *olen = len;
    }
    0i32
}

// Minimal P-256 field arithmetic to recover `y` from `x`

// rust-psa-crypto (https://github.com/malishav/rust-psa-crypto) only accepts uncompressed public keys
// since the plan is to remove psa in the future (in favor of embedded-cal)
// instead of fixing upstream, we will just add a small p256 arithmetic to finish ecdsa_verify
mod p256_field {
    /// A 256-bit unsigned integer, big-endian: `limbs[0]` is the most
    /// significant word.
    type Limbs = [u64; 4];

    const P: Limbs = [
        0xFFFFFFFF00000001,
        0x0000000000000000,
        0x00000000FFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ];
    const B: Limbs = [
        0x5AC635D8AA3A93E7,
        0xB3EBBD55769886BC,
        0x651D06B0CC53B0F6,
        0x3BCE3C3E27D2604B,
    ];

    fn from_be_bytes(bytes: &[u8; 32]) -> Limbs {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
        }
        limbs
    }

    fn to_be_bytes(limbs: &Limbs) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&limbs[i].to_be_bytes());
        }
        out
    }

    fn is_zero(a: &Limbs) -> bool {
        a.iter().all(|&limb| limb == 0)
    }

    fn is_ge(a: &Limbs, b: &Limbs) -> bool {
        for i in 0..4 {
            if a[i] != b[i] {
                return a[i] > b[i];
            }
        }
        true
    }

    fn add_raw(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in (0..4).rev() {
            let sum = a[i] as u128 + b[i] as u128 + carry;
            out[i] = sum as u64;
            carry = sum >> 64;
        }
        (out, carry != 0)
    }

    fn sub_raw(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
        let mut out = [0u64; 4];
        let mut borrow = 0i128;
        for i in (0..4).rev() {
            let diff = a[i] as i128 - b[i] as i128 - borrow;
            if diff < 0 {
                out[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                out[i] = diff as u64;
                borrow = 0;
            }
        }
        (out, borrow != 0)
    }

    fn add_mod(a: &Limbs, b: &Limbs, p: &Limbs) -> Limbs {
        let (sum, carry) = add_raw(a, b);
        if carry || is_ge(&sum, p) {
            sub_raw(&sum, p).0
        } else {
            sum
        }
    }

    fn sub_mod(a: &Limbs, b: &Limbs, p: &Limbs) -> Limbs {
        let (diff, borrow) = sub_raw(a, b);
        if borrow {
            add_raw(&diff, p).0
        } else {
            diff
        }
    }

    fn neg_mod(a: &Limbs, p: &Limbs) -> Limbs {
        if is_zero(a) {
            [0; 4]
        } else {
            sub_raw(p, a).0
        }
    }

    /// `i == 0` is the most significant bit.
    fn bit_at(limbs: &Limbs, i: usize) -> bool {
        let limb = limbs[i / 64];
        let shift = 63 - (i % 64);
        (limb >> shift) & 1 == 1
    }

    fn mul_mod(a: &Limbs, b: &Limbs, p: &Limbs) -> Limbs {
        let mut acc = [0u64; 4];
        for i in 0..256 {
            acc = add_mod(&acc, &acc, p);
            if bit_at(b, i) {
                acc = add_mod(&acc, a, p);
            }
        }
        acc
    }

    fn pow_mod(base: &Limbs, exp: &Limbs, p: &Limbs) -> Limbs {
        let mut result: Limbs = [0, 0, 0, 1];
        for i in 0..256 {
            result = mul_mod(&result, &result, p);
            if bit_at(exp, i) {
                result = mul_mod(&result, base, p);
            }
        }
        result
    }

    fn shr2(limbs: &Limbs) -> Limbs {
        [
            limbs[0] >> 2,
            (limbs[1] >> 2) | (limbs[0] << 62),
            (limbs[2] >> 2) | (limbs[1] << 62),
            (limbs[3] >> 2) | (limbs[2] << 62),
        ]
    }

    fn add_one(limbs: &Limbs) -> Limbs {
        add_raw(limbs, &[0, 0, 0, 1]).0
    }

    pub fn decompress_both(x: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
        let xl = from_be_bytes(x);
        if is_ge(&xl, &P) {
            return None;
        }

        let x2 = mul_mod(&xl, &xl, &P);
        let x3 = mul_mod(&x2, &xl, &P);
        let three_x = add_mod(&add_mod(&xl, &xl, &P), &xl, &P);
        let alpha = sub_mod(&add_mod(&x3, &B, &P), &three_x, &P);

        let exp = shr2(&add_one(&P));
        let y0 = pow_mod(&alpha, &exp, &P);

        if mul_mod(&y0, &y0, &P) != alpha {
            return None; // x is not a valid curve coordinate
        }

        let y1 = neg_mod(&y0, &P);
        Some((to_be_bytes(&y0), to_be_bytes(&y1)))
    }
}

#[derive(Debug)]
pub struct Crypto;

impl CryptoTrait for Crypto {
    fn supported_suites(&self) -> EdhocBuffer<MAX_SUITES_LEN> {
        EdhocBuffer::<MAX_SUITES_LEN>::new_from_slice(&[EDHOCSuite::CipherSuite2 as u8])
            .expect("This should never fail, as the slice is of the correct length")
    }

    fn sha256_digest(&mut self, message: &[u8]) -> BytesHashLen {
        let hash_alg = Hash::Sha256;
        let mut hash: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];
        psa_crypto::init().unwrap();
        hash_compute(hash_alg, message, &mut hash).unwrap();

        hash
    }

    type HashInProcess<'a>
        = BufferedHasherSha256
    where
        Self: 'a;

    #[inline]
    fn sha256_start<'a>(&'a mut self) -> Self::HashInProcess<'a> {
        Default::default()
    }

    fn hkdf_expand(&mut self, prk: &BytesHashLen, info: &[u8], result: &mut [u8]) {
        // Implementation of HKDF-Expand as per RFC5869

        let length = result.len();

        // N = ceil(L/HashLen)
        let n = if length % SHA256_DIGEST_LEN == 0 {
            length / SHA256_DIGEST_LEN
        } else {
            length / SHA256_DIGEST_LEN + 1
        };

        let mut message: [u8; MAX_INFO_LEN + SHA256_DIGEST_LEN + 1] =
            [0; MAX_INFO_LEN + SHA256_DIGEST_LEN + 1];
        message[..info.len()].copy_from_slice(info);
        message[info.len()] = 0x01;
        let mut t_i = self.hmac_sha256(&message[..info.len() + 1], prk);
        let t_i_len = core::cmp::min(result.len(), SHA256_DIGEST_LEN);
        result[..t_i_len].copy_from_slice(&t_i[..t_i_len]);

        for i in 2..=n {
            message[..SHA256_DIGEST_LEN].copy_from_slice(&t_i);
            message[SHA256_DIGEST_LEN..SHA256_DIGEST_LEN + info.len()].copy_from_slice(&info);
            message[SHA256_DIGEST_LEN + info.len()] = i as u8;
            t_i = self.hmac_sha256(&message[..SHA256_DIGEST_LEN + info.len() + 1], prk);
            let start = (i - 1) * SHA256_DIGEST_LEN;
            let t_i_len = core::cmp::min(result[start..].len(), SHA256_DIGEST_LEN);
            result[start..start + t_i_len].copy_from_slice(&t_i[..t_i_len]);
        }
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        // Implementation of HKDF-Extract as per RFC 5869

        // TODO generalize if salt is not provided
        let output = self.hmac_sha256(ikm, salt);

        output
    }

    // added for PSK
    fn hkdf_extract_psk(&mut self, salt: &BytesHashLen, ikm: &BytesElemLenPSK) -> BytesHashLen {
        // TODO
        // TODO generalize if salt is not provided
        let output = self.hmac_sha256(ikm, salt);

        output
    }

    fn aes_ccm_encrypt<const N: usize, Tag: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &[u8],
    ) -> EdhocBuffer<N> {
        psa_crypto::init().unwrap();

        let alg = Aead::AeadWithShortenedTag {
            aead_alg: AeadWithDefaultLengthTag::Ccm,
            tag_length: Tag::LEN,
        };
        let mut usage_flags: UsageFlags = Default::default();
        usage_flags.set_encrypt();

        let attributes = Attributes {
            key_type: Type::Aes,
            bits: 128,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: alg.into(),
            },
        };
        let my_key = key_management::import(attributes, None, &key[..]).unwrap();
        let mut output_buffer = EdhocBuffer::new();
        let full_range = output_buffer
            .extend_reserve(plaintext.len() + Tag::LEN)
            .unwrap();

        #[allow(deprecated, reason = "using extend_reserve")]
        let result = aead::encrypt(
            my_key,
            alg,
            iv,
            ad,
            plaintext,
            &mut output_buffer.content[full_range],
        );

        // SAFETY: The function demands that the Id is not used while destroyed.
        // We did not hand out the Id `my_key` in the last few lines, so we can destroy it.
        unsafe { key_management::destroy(my_key).unwrap() };
        result.unwrap();

        output_buffer
    }

    fn aes_ccm_decrypt<const N: usize, Tag: CcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<EdhocBuffer<N>, EDHOCError> {
        psa_crypto::init().unwrap();

        let alg = Aead::AeadWithShortenedTag {
            aead_alg: AeadWithDefaultLengthTag::Ccm,
            tag_length: Tag::LEN,
        };
        let mut usage_flags: UsageFlags = Default::default();
        usage_flags.set_decrypt();

        let attributes = Attributes {
            key_type: Type::Aes,
            bits: 128,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: alg.into(),
            },
        };
        let my_key = key_management::import(attributes, None, &key[..]).unwrap();
        let mut output_buffer = EdhocBuffer::new();
        let out_slice = output_buffer
            .extend_reserve(ciphertext.len() - Tag::LEN)
            .unwrap();

        #[allow(deprecated, reason = "using extend_reserve")]
        let result = aead::decrypt(
            my_key,
            alg,
            iv,
            ad,
            ciphertext,
            &mut output_buffer.content[out_slice],
        );
        // SAFETY: The function demands that the Id is not used while destroyed.
        // We did not hand out the Id `my_key` in the last few lines, so we can destroy it.
        unsafe { key_management::destroy(my_key).unwrap() };

        match result {
            Ok(_) => Ok(output_buffer),
            Err(_) => Err(EDHOCError::MacVerificationFailed),
        }
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        let mut peer_public_key: [u8; 33] = [0; 33];
        peer_public_key[0] = 0x02; // sign does not matter for ECDH operation
        peer_public_key[1..33].copy_from_slice(&public_key[..]);

        let alg = RawKeyAgreement::Ecdh;
        let mut usage_flags: UsageFlags = Default::default();
        usage_flags.set_derive();
        let attributes = Attributes {
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: KeyAgreement::Raw(alg).into(),
            },
        };

        psa_crypto::init().unwrap();
        let my_key = key_management::import(attributes, None, private_key).unwrap();
        let mut output_buffer: [u8; P256_ELEM_LEN] = [0; P256_ELEM_LEN];

        key_agreement::raw_key_agreement(alg, my_key, &peer_public_key, &mut output_buffer)
            .unwrap();
        // SAFETY: The function demands that the Id is not used while destroyed.
        // We did not hand out the Id `my_key` in the last few lines, so we can destroy it.
        unsafe { key_management::destroy(my_key).unwrap() };
        output_buffer
    }

    fn get_random_byte(&mut self) -> u8 {
        psa_crypto::init().unwrap();
        let mut buffer = [0u8; 1];
        let _ = generate_random(&mut buffer); // TODO: check return value
        buffer[0]
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        let alg = RawKeyAgreement::Ecdh;
        let mut usage_flags: UsageFlags = UsageFlags::default();
        usage_flags.set_export();
        usage_flags.set_derive();
        let attributes = Attributes {
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: KeyAgreement::Raw(alg).into(),
            },
        };

        psa_crypto::init().unwrap();

        let key_id = key_management::generate(attributes, None).unwrap();
        let mut private_key: [u8; P256_ELEM_LEN] = [0; P256_ELEM_LEN];
        key_management::export(key_id, &mut private_key).unwrap();

        let mut public_key: [u8; P256_ELEM_LEN * 2 + 1] = [0; P256_ELEM_LEN * 2 + 1]; // allocate buffer for: sign, x, and y coordinates
        key_management::export_public(key_id, &mut public_key).unwrap();
        let public_key: [u8; P256_ELEM_LEN] = public_key[1..33].try_into().unwrap(); // return only the x coordinate

        // SAFETY: The function demands that the Id is not used while destroyed.
        // We did not hand out the Id `key_id` in the last few lines, so we can destroy it.
        unsafe { key_management::destroy(key_id).unwrap() };

        (private_key, public_key)
    }

    fn p256_ecdsa_sign(
        &mut self,
        private_key: &BytesP256ElemLen,
        message: &[u8],
    ) -> Result<BytesSignature, EDHOCError> {
        let alg = AsymmetricSignature::Ecdsa {
            hash_alg: Hash::Sha256.into(),
        };
        let mut usage_flags: UsageFlags = Default::default();
        usage_flags.set_sign_hash();
        let attributes = Attributes {
            key_type: Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            },
            bits: 256,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags,
                permitted_algorithms: alg.into(),
            },
        };

        psa_crypto::init().unwrap();
        let hash = self.sha256_digest(message);
        let my_key = key_management::import(attributes, None, private_key)
            .map_err(|_| EDHOCError::MissingIdentity)?;

        let mut signature: BytesSignature = [0; SIGNATURE_LENGTH];
        let result = asym_signature::sign_hash(my_key, alg, &hash, &mut signature);
        // SAFETY: The function demands that the Id is not used while destroyed.
        // We did not hand out the Id `my_key` in the last few lines, so we can destroy it.
        unsafe { key_management::destroy(my_key).unwrap() };

        result.map_err(|_| EDHOCError::MissingIdentity)?;
        Ok(signature)
    }

    fn p256_ecdsa_verify(
        &mut self,
        public_key_x: &BytesP256ElemLen,
        message: &[u8],
        signature: &BytesSignature,
    ) -> Result<bool, EDHOCError> {
        let alg = AsymmetricSignature::Ecdsa {
            hash_alg: Hash::Sha256.into(),
        };
        let hash = self.sha256_digest(message);

        let Some((y_a, y_b)) = p256_field::decompress_both(public_key_x) else {
            return Ok(false);
        };
        for y in [y_a, y_b] {
            let mut peer_public_key: [u8; 65] = [0; 65];
            peer_public_key[0] = 0x04;
            peer_public_key[1..33].copy_from_slice(&public_key_x[..]);
            peer_public_key[33..65].copy_from_slice(&y);

            let mut usage_flags: UsageFlags = Default::default();
            usage_flags.set_verify_hash();
            let attributes = Attributes {
                key_type: Type::EccPublicKey {
                    curve_family: EccFamily::SecpR1,
                },
                bits: 256,
                lifetime: Lifetime::Volatile,
                policy: Policy {
                    usage_flags,
                    permitted_algorithms: alg.into(),
                },
            };

            psa_crypto::init().unwrap();
            let Ok(their_key) = key_management::import(attributes, None, &peer_public_key) else {
                continue;
            };

            let result = asym_signature::verify_hash(their_key, alg, &hash, signature);
            // SAFETY: The function demands that the Id is not used while destroyed.
            // We did not hand out the Id `their_key` in the last few lines, so we can destroy it.
            unsafe { key_management::destroy(their_key).unwrap() };

            if result.is_ok() {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl Crypto {
    pub fn hmac_sha256(&mut self, message: &[u8], key: &[u8; SHA256_DIGEST_LEN]) -> BytesHashLen {
        // implementation of HMAC as per RFC2104

        const IPAD: [u8; 64] = [0x36; 64];
        const OPAD: [u8; 64] = [0x5C; 64];

        //    (1) append zeros to the end of K to create a B byte string
        //        (e.g., if K is of length 20 bytes and B=64, then K will be
        //         appended with 44 zero bytes 0x00)
        let mut b: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
        b[0..SHA256_DIGEST_LEN].copy_from_slice(&key[..]);

        //    (2) XOR (bitwise exclusive-OR) the B byte string computed in step
        //        (1) with ipad
        let mut s2: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
        for i in 0..64 {
            s2[i] = b[i] ^ IPAD[i];
        }

        //    (3) append the stream of data 'text' to the B byte string resulting
        //        from step (2)
        s2[64..64 + message.len()].copy_from_slice(message);

        //    (4) apply H to the stream generated in step (3)
        let ih = self.sha256_digest(&s2[..64 + message.len()]);

        //    (5) XOR (bitwise exclusive-OR) the B byte string computed in
        //        step (1) with opad
        let mut s5: [u8; MAX_BUFFER_LEN] = [0; MAX_BUFFER_LEN];
        for i in 0..64 {
            s5[i] = b[i] ^ OPAD[i];
        }
        //    (6) append the H result from step (4) to the B byte string
        //        resulting from step (5)
        s5[64..64 + SHA256_DIGEST_LEN].copy_from_slice(&ih);

        //    (7) apply H to the stream generated in step (6) and output
        //        the result
        let oh = self.sha256_digest(&s5[..3 * SHA256_DIGEST_LEN]);

        oh
    }
}

/// `psa_crypto` has no streaming hash API and needs to build a full message to be hashed in memory
/// before hashing it in a single go.
#[derive(Default)]
pub struct BufferedHasherSha256(EdhocBuffer<MAX_BUFFER_LEN>);

impl digest::FixedOutput for BufferedHasherSha256 {
    #[inline]
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let hash_alg = Hash::Sha256;
        psa_crypto::init().unwrap();
        hash_compute(hash_alg, self.0.as_slice(), out).unwrap();
    }
}
impl digest::Update for BufferedHasherSha256 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.0
            .extend_from_slice(data)
            .expect("Maximum buffer length exceeded")
    }
}
impl digest::OutputSizeUser for BufferedHasherSha256 {
    type OutputSize = digest::typenum::U32;
}
impl digest::HashMarker for BufferedHasherSha256 {}

#[cfg(test)]
mod tests {
    use super::*;
    use lakers_shared::test_helper::{
        test_aes_ccm_roundtrip, test_aes_ccm_tag_16, test_aes_ccm_tag_8,
    };

    #[test]
    fn test_hmac_sha256() {
        const KEY: [u8; 32] = [0x0b; 32];
        const MESSAGE_1: [u8; 0] = [];
        const RESULT_1_TV: [u8; 32] = [
            0x51, 0x77, 0xe6, 0x37, 0xaa, 0xac, 0x0b, 0x50, 0xe5, 0xdc, 0xa8, 0xbb, 0x05, 0xb0,
            0xb5, 0x71, 0x44, 0x4b, 0xd5, 0x9b, 0x9b, 0x0d, 0x83, 0x4d, 0x50, 0x68, 0x1a, 0xf2,
            0x1f, 0xc1, 0x4b, 0x1e,
        ];
        const MESSAGE_2: [u8; 1] = [0x0a];
        const RESULT_2_TV: [u8; 32] = [
            0x30, 0x50, 0x86, 0x79, 0x39, 0x85, 0x02, 0xd9, 0xdd, 0x70, 0x7e, 0xff, 0x6c, 0x84,
            0x08, 0x9d, 0x83, 0x12, 0xcc, 0xea, 0x25, 0x36, 0x4d, 0x9c, 0xb8, 0xb0, 0xbd, 0x94,
            0xd0, 0xe6, 0x55, 0xa3,
        ];

        let result_1 = Crypto.hmac_sha256(&MESSAGE_1, &KEY);
        assert_eq!(result_1, RESULT_1_TV);

        let result_2 = Crypto.hmac_sha256(&MESSAGE_2, &KEY);
        assert_eq!(result_2, RESULT_2_TV);
    }

    #[test]
    fn test_psa_aes_ccm() {
        test_aes_ccm_roundtrip::<Crypto, CcmTagLen8>(&mut Crypto);
        test_aes_ccm_roundtrip::<Crypto, CcmTagLen16>(&mut Crypto);

        test_aes_ccm_tag_8::<Crypto>(&mut Crypto);
        test_aes_ccm_tag_16::<Crypto>(&mut Crypto);
    }

    #[test]
    fn test_psa_ecdsa() {
        test_ecdsa_roundtrip::<Crypto>(&mut Crypto);
        test_ecdsa_rejects_bad_signature::<Crypto>(&mut Crypto);
        test_ecdsa_is_deterministic::<Crypto>(&mut Crypto);
    }
}

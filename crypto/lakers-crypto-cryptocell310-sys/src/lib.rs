#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![no_std]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use core::ffi::c_void;
use lakers_shared::{Crypto as CryptoTrait, *};

fn convert_array(input: &[u32]) -> [u8; SHA256_DIGEST_LEN] {
    assert!(input.len() == SHA256_DIGEST_LEN / 4);

    let mut output = [0x00u8; SHA256_DIGEST_LEN];
    for i in 0..SHA256_DIGEST_LEN / 4 {
        output[4 * i..4 * i + 4].copy_from_slice(&input[i].to_le_bytes());
    }
    output
}

#[derive(Debug)]
pub struct Crypto;

impl CryptoTrait for Crypto {
    fn supported_suites(&self) -> EdhocBuffer<MAX_SUITES_LEN> {
        EdhocBuffer::<MAX_SUITES_LEN>::new_from_slice(&[EDHOCSuite::CipherSuite2 as u8])
            .expect("This should never fail, as the slice is of the correct length")
    }

    fn sha256_digest(&mut self, message: &[u8]) -> BytesHashLen {
        let mut buffer: [u32; 64 / 4] = [0x00; 64 / 4];

        unsafe {
            CRYS_HASH(
                CRYS_HASH_OperationMode_t_CRYS_HASH_SHA256_mode,
                // This just reads, the C code is missing a `const`.
                message.as_ptr() as *mut _,
                message.len(),
                buffer.as_mut_ptr(),
            );
        }

        convert_array(&buffer[0..SHA256_DIGEST_LEN / 4])
    }

    type HashInProcess<'a>
        = HashInProcessSha256
    where
        Self: 'a;

    #[inline]
    fn sha256_start<'a>(&'a mut self) -> Self::HashInProcess<'a> {
        Default::default()
    }

    fn hkdf_expand(&mut self, prk: &BytesHashLen, info: &[u8], result: &mut [u8]) {
        unsafe {
            CRYS_HKDF_KeyDerivFunc(
                CRYS_HKDF_HASH_OpMode_t_CRYS_HKDF_HASH_SHA256_mode,
                core::ptr::null_mut(),
                0 as usize,
                prk.clone().as_mut_ptr(),
                prk.len() as u32,
                // Function does not write there, merely misses `const` in C
                info.as_ptr() as *mut _,
                info.len() as u32,
                result.as_mut_ptr(),
                result.len() as u32,
                SaSiBool_SASI_TRUE,
            );
        }
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        // Implementation of HKDF-Extract as per RFC 5869

        // TODO generalize if salt is not provided
        let output = self.hmac_sha256(&mut ikm.clone()[..], *salt);

        output
    }

    fn aes_ccm_encrypt<const N: usize, Tag: AesCcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &[u8],
    ) -> EdhocBuffer<N> {
        let mut output = EdhocBuffer::new();
        let mut tag: CRYS_AESCCM_Mac_Res_t = Default::default();
        let mut aesccm_key: CRYS_AESCCM_Key_t = Default::default();
        let mut aesccm_ad = [0x00u8; ENC_STRUCTURE_LEN];

        aesccm_key[0..AES_CCM_KEY_LEN].copy_from_slice(&key[..]);
        aesccm_ad[0..ad.len()].copy_from_slice(&ad[..]);

        output.extend_reserve(plaintext.len()).unwrap();

        let _err = unsafe {
            CC_AESCCM(
                SaSiAesEncryptMode_t_SASI_AES_ENCRYPT,
                aesccm_key.as_mut_ptr(),
                CRYS_AESCCM_KeySize_t_CRYS_AES_Key128BitSize,
                iv.clone().as_mut_ptr(),
                iv.len() as u8,
                aesccm_ad.as_mut_ptr(),
                ad.len() as u32,
                // CC_AESCCM does not really write there, it's just missing a `const`
                plaintext.as_ptr() as *mut _,
                plaintext.len() as u32,
                #[allow(
                    deprecated,
                    reason = "hax won't allow creating a .as_mut_slice() method"
                )]
                output.content.as_mut_ptr(),
                Tag::LEN as u8,
                tag.as_mut_ptr(),
                0 as u32, // CCM
            )
        };

        output.extend_from_slice(&tag[..Tag::LEN]).unwrap();

        output
    }

    fn aes_ccm_decrypt<const N: usize, Tag: AesCcmTagLen>(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<EdhocBuffer<N>, EDHOCError> {
        let mut output = EdhocBuffer::new();
        output.extend_reserve(ciphertext.len() - Tag::LEN).unwrap();
        let mut aesccm_key: CRYS_AESCCM_Key_t = Default::default();

        aesccm_key[0..AES_CCM_KEY_LEN].copy_from_slice(&key[..]);

        assert!(ciphertext.len() - Tag::LEN <= N);

        #[allow(deprecated, reason = "using extend_reserve")]
        unsafe {
            match CC_AESCCM(
                SaSiAesEncryptMode_t_SASI_AES_DECRYPT,
                aesccm_key.as_mut_ptr(),
                CRYS_AESCCM_KeySize_t_CRYS_AES_Key128BitSize,
                iv.clone().as_mut_ptr(),
                iv.len() as u8,
                ad.as_ptr() as *mut _,
                ad.len() as u32,
                // CC_AESCCM does not really write there, it's just missing a `const`
                ciphertext.as_ptr() as *mut _,
                (ciphertext.len() - Tag::LEN) as u32,
                output.content.as_mut_ptr(),
                Tag::LEN as u8,
                // as before
                ciphertext[ciphertext.len() - Tag::LEN..].as_ptr() as *mut _,
                0 as u32, // CCM
            ) {
                CRYS_OK => Ok(output),
                _ => Err(EDHOCError::MacVerificationFailed),
            }
        }
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        let mut output = [0x0u8; P256_ELEM_LEN];
        let mut output_len: u32 = output.len() as u32;

        let mut tmp: CRYS_ECDH_TempData_t = Default::default();

        let mut public_key_compressed = [0x0u8; P256_ELEM_LEN + 1];
        public_key_compressed[0] = 0x02;
        public_key_compressed[1..].copy_from_slice(&public_key[..]);

        let mut public_key_cc310: CRYS_ECPKI_UserPublKey_t = Default::default();

        let domain =
            unsafe { CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_t_CRYS_ECPKI_DomainID_secp256r1) };

        unsafe {
            _DX_ECPKI_BuildPublKey(
                domain,
                public_key_compressed.as_mut_ptr(),
                (P256_ELEM_LEN + 1) as u32,
                EC_PublKeyCheckMode_t_CheckPointersAndSizesOnly,
                &mut public_key_cc310,
                core::ptr::null_mut(),
            );
        }

        let mut private_key_cc310: CRYS_ECPKI_UserPrivKey_t = Default::default();

        unsafe {
            CRYS_ECPKI_BuildPrivKey(
                domain,
                private_key.clone().as_mut_ptr(),
                P256_ELEM_LEN as u32,
                &mut private_key_cc310,
            );
        }

        unsafe {
            CRYS_ECDH_SVDP_DH(
                &mut public_key_cc310,
                &mut private_key_cc310,
                output.as_mut_ptr(),
                &mut output_len,
                &mut tmp,
            );
        }

        output
    }

    fn get_random_byte(&mut self) -> u8 {
        let mut rnd_context = CRYS_RND_State_t::default();
        let mut rnd_work_buffer = CRYS_RND_WorkBuff_t::default();
        unsafe {
            SaSi_LibInit();
            CRYS_RndInit(
                &mut rnd_context as *mut _ as *mut c_void,
                &mut rnd_work_buffer as *mut _,
            );
        }
        let mut buffer = [0u8; 1];
        unsafe {
            CRYS_RND_GenerateVector(
                &mut rnd_context as *mut _ as *mut c_void,
                1,
                buffer.as_mut_ptr(),
            );
        }
        buffer[0]
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        let mut rnd_context = CRYS_RND_State_t::default();
        let mut rnd_work_buffer = CRYS_RND_WorkBuff_t::default();
        unsafe {
            SaSi_LibInit();
            CRYS_RndInit(
                &mut rnd_context as *mut _ as *mut c_void,
                &mut rnd_work_buffer as *mut _,
            );
        }
        let rnd_generate_vect_func: SaSiRndGenerateVectWorkFunc_t = Some(CRYS_RND_GenerateVector);
        let curve_256 =
            unsafe { CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_t_CRYS_ECPKI_DomainID_secp256r1) };
        let crys_private_key: *mut CRYS_ECPKI_UserPrivKey_t =
            &mut CRYS_ECPKI_UserPrivKey_t::default();
        let crys_public_key: *mut CRYS_ECPKI_UserPublKey_t =
            &mut CRYS_ECPKI_UserPublKey_t::default();
        let temp_data: *mut CRYS_ECPKI_KG_TempData_t = &mut CRYS_ECPKI_KG_TempData_t::default();
        let temp_fips_buffer: *mut CRYS_ECPKI_KG_FipsContext_t =
            &mut CRYS_ECPKI_KG_FipsContext_t::default();

        unsafe {
            CRYS_ECPKI_GenKeyPair(
                &mut rnd_context as *mut _ as *mut c_void,
                rnd_generate_vect_func,
                curve_256,
                crys_private_key,
                crys_public_key,
                temp_data,
                temp_fips_buffer,
            );
        }

        let mut private_key: [u8; P256_ELEM_LEN] = [0x0; P256_ELEM_LEN];
        let mut key_size: u32 = P256_ELEM_LEN.try_into().unwrap();

        unsafe {
            CRYS_ECPKI_ExportPrivKey(crys_private_key, private_key.as_mut_ptr(), &mut key_size);
        }

        // let private_key = BytesP256ElemLen::from_public_slice(&private_key[..]);

        let mut public_key: [u8; P256_ELEM_LEN + 1] = [0x0; P256_ELEM_LEN + 1];
        let mut key_size: u32 = (P256_ELEM_LEN as u32) + 1;
        let compressed_flag: CRYS_ECPKI_PointCompression_t =
            CRYS_ECPKI_PointCompression_t_CRYS_EC_PointCompressed;

        unsafe {
            CRYS_ECPKI_ExportPublKey(
                crys_public_key,
                compressed_flag,
                public_key.as_mut_ptr(),
                &mut key_size,
            );
        }

        let public_key: [u8; P256_ELEM_LEN] = public_key[1..33].try_into().unwrap(); // discard sign byte

        (private_key, public_key)
    }
}

impl Crypto {
    fn hmac_sha256(
        &mut self,
        message: &mut [u8],
        mut key: [u8; SHA256_DIGEST_LEN],
    ) -> BytesHashLen {
        let mut buffer: [u32; 64 / 4] = [0x00; 64 / 4];

        unsafe {
            CRYS_HMAC(
                CRYS_HASH_OperationMode_t_CRYS_HASH_SHA256_mode,
                key.as_mut_ptr(),
                key.len() as u16,
                message.as_mut_ptr(),
                message.len(),
                buffer.as_mut_ptr(),
            );
        }

        convert_array(&buffer[..SHA256_DIGEST_LEN / 4])
    }
}

pub struct HashInProcessSha256(CRYS_HASHUserContext_t);

impl core::default::Default for HashInProcessSha256 {
    fn default() -> Self {
        let mut buf = CRYS_HASHUserContext_t::default();
        // unsafe: used as per C API. The context struct is used just as a buffer and thus does not
        // need to be pinned.
        let result =
            unsafe { CRYS_HASH_Init(&mut buf, CRYS_HASH_OperationMode_t_CRYS_HASH_SHA256_mode) };
        assert!(result == CRYS_OK);
        Self(buf)
    }
}

impl digest::FixedOutput for HashInProcessSha256 {
    #[inline]
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        let mut out_buffer: [u32; 64 / 4] = [0x00; 64 / 4];

        // unsafe: used as per C API.
        let result = unsafe { CRYS_HASH_Finish(&mut self.0, out_buffer.as_mut_ptr()) };
        assert!(result == CRYS_OK);

        *out = convert_array(&out_buffer[0..SHA256_DIGEST_LEN / 4]).into();
    }
}
impl digest::Update for HashInProcessSha256 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        // unsafe: used as per C API.
        let result = unsafe {
            // mut cast: C API lacks `const` qualifier
            CRYS_HASH_Update(&mut self.0, data.as_ptr() as *mut _, data.len())
        };
        assert!(result == CRYS_OK);
    }
}
impl digest::OutputSizeUser for HashInProcessSha256 {
    type OutputSize = digest::typenum::U32;
}
impl digest::HashMarker for HashInProcessSha256 {}

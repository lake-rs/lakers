use crate::consts::*;
use crate::shared::*;
use crate::ZeroTouchError;
use defmt_or_log::trace;
use lakers_shared::{Crypto as CryptoTrait, *};

#[derive(Default, Debug)]
#[repr(C)]
pub struct ZeroTouchDevice {
    pub id_u: EdhocMessageBuffer, // identifier of the device (U), equivalent to ID_CRED_I in EDHOC
    pub g_w: BytesP256ElemLen,    // public key of the enrollment server (W)
    pub loc_w: EdhocMessageBuffer, // address of the enrollment server (W)
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ZeroTouchDeviceWaitEAD2 {
    prk: BytesHashLen,
    pub h_message_1: BytesHashLen,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ZeroTouchDeviceDone {
    pub voucher: BytesMac,
}

impl ZeroTouchDevice {
    pub fn new(id_u: EdhocMessageBuffer, g_w: BytesP256ElemLen, loc_w: EdhocMessageBuffer) -> Self {
        trace!("Initializing ZeroTouchDevice");
        ZeroTouchDevice { id_u, g_w, loc_w }
    }

    pub fn prepare_ead_1<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        secret: BytesP256ElemLen,
        ss: u8,
    ) -> (ZeroTouchDeviceWaitEAD2, EADItem) {
        trace!("Enter prepare_ead_1");
        // PRK = EDHOC-Extract(salt, IKM)
        let prk = compute_prk_from_secret(crypto, &secret);

        // plaintext = (ID_U: bstr)
        let encoded_id_u = encode_id_u(&self.id_u);
        let enc_id = encrypt_enc_id(crypto, &prk, &encoded_id_u, ss);
        let value = encode_ead_1_value(&self.loc_w, &enc_id);

        let ead_1 = EADItem::new_full(EAD_AUTHZ_LABEL, true, Some(value.as_slice())).unwrap();

        (
            ZeroTouchDeviceWaitEAD2 {
                prk,
                h_message_1: [0; SHA256_DIGEST_LEN],
            },
            ead_1,
        )
    }
}

impl ZeroTouchDeviceWaitEAD2 {
    pub fn set_h_message_1(&mut self, h_message_1: BytesHashLen) {
        trace!("Enter set_h_message_1");
        self.h_message_1 = h_message_1;
    }

    pub fn process_ead_2<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        ead_2: &EADItem,
        cred_v: &[u8],
    ) -> Result<ZeroTouchDeviceDone, ZeroTouchError> {
        trace!("Enter process_ead_2");
        if ead_2.label() != EAD_AUTHZ_LABEL {
            return Err(ZeroTouchError::InvalidEADLabel);
        }
        let Some(ead_2_value) = ead_2.value_bytes() else {
            return Err(ZeroTouchError::EmptyEADValue);
        };
        match verify_voucher(crypto, ead_2_value, &self.h_message_1, cred_v, &self.prk) {
            Ok(voucher) => Ok(ZeroTouchDeviceDone { voucher }),
            Err(error) => Err(error),
        }
    }
}

fn encode_id_u(id_u: &EdhocMessageBuffer) -> EdhocMessageBuffer {
    // plaintext = (ID_U: bstr)
    let mut plaintext = EdhocMessageBuffer::new();
    plaintext
        .push(CBOR_MAJOR_BYTE_STRING + id_u.len() as u8)
        .unwrap();
    plaintext.extend_from_slice(id_u.as_slice()).unwrap();

    plaintext
}

fn encrypt_enc_id<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    prk: &BytesHashLen,
    plaintext: &EdhocMessageBuffer,
    ss: u8,
) -> EdhocMessageBuffer {
    let (k_1, iv_1) = compute_k_1_iv_1(crypto, &prk);

    // external_aad = (SS: int)
    let enc_structure = encode_enc_structure(ss);

    // ENC_ID = 'ciphertext' of COSE_Encrypt0
    crypto.aes_ccm_encrypt::<MAX_MESSAGE_SIZE_LEN, AesCcmTag8>(
        &k_1,
        &iv_1,
        &enc_structure[..],
        plaintext.as_slice(),
    )
}

fn encode_ead_1_value(loc_w: &EdhocMessageBuffer, enc_id: &EdhocMessageBuffer) -> EADBuffer {
    let mut output = EdhocBuffer::new();

    output.push(CBOR_TEXT_STRING).unwrap();
    output.push(loc_w.len() as u8).unwrap();
    output.extend_from_slice(loc_w.as_slice()).unwrap();

    output
        .push(CBOR_MAJOR_BYTE_STRING + enc_id.len() as u8)
        .unwrap();
    output.extend_from_slice(enc_id.as_slice()).unwrap();

    output
}

pub(crate) fn verify_voucher<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    received_voucher: &[u8],
    h_message_1: &BytesHashLen,
    cred_v: &[u8],
    prk: &BytesHashLen,
) -> Result<BytesMac, ZeroTouchError> {
    let prepared_voucher = &prepare_voucher(crypto, h_message_1, cred_v, prk);
    if received_voucher == prepared_voucher {
        return Ok(*prepared_voucher);
    } else {
        return Err(ZeroTouchError::VoucherVerificationFailed);
    }
}

#[cfg(test)]
mod test_device {
    use super::*;
    use crate::test_vectors::*;
    use lakers_crypto::default_crypto;

    #[test]
    fn test_encrypt_enc_id() {
        let enc_id_tv: EdhocMessageBuffer = ENC_ID_TV.try_into().unwrap();

        let enc_id = encrypt_enc_id(
            &mut default_crypto(),
            &PRK_TV.try_into().unwrap(),
            &ID_U_ENCODED_TV.try_into().unwrap(),
            SS_TV,
        );
        assert_eq!(enc_id, enc_id_tv);
    }

    #[test]
    fn test_prepare_ead_1() {
        let ead_device = ZeroTouchDevice::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );

        let (_ead_device, ead_1) =
            ead_device.prepare_ead_1(&mut default_crypto(), G_XW_TV.try_into().unwrap(), SS_TV);
        assert_eq!(ead_1.label(), EAD_AUTHZ_LABEL);
        assert_eq!(ead_1.is_critical(), true);
        assert_eq!(ead_1.value_bytes(), Some(EAD1_VALUE_TV));
    }

    #[test]
    fn test_verify_voucher() {
        let h_message_1_tv = H_MESSAGE_1_TV.try_into().unwrap();
        let prk_tv = PRK_TV.try_into().unwrap();

        let res = verify_voucher(
            &mut default_crypto(),
            &VOUCHER_MAC_TV,
            &h_message_1_tv,
            &CRED_V_TV,
            &prk_tv,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), VOUCHER_MAC_TV);

        let mut voucher_invalidated: [u8; MAC_LENGTH] = VOUCHER_MAC_TV.try_into().unwrap();
        voucher_invalidated[0] ^= 0x01; // change a byte to make the voucher invalid
        let res = verify_voucher(
            &mut default_crypto(),
            &voucher_invalidated,
            &h_message_1_tv,
            &CRED_V_TV,
            &prk_tv,
        );
        assert_eq!(res, Err(ZeroTouchError::VoucherVerificationFailed));
    }

    #[test]
    fn test_process_ead_2() {
        let ead_2_tv = EADItem::new_full(EAD_AUTHZ_LABEL, true, Some(&EAD2_VALUE_TV)).unwrap();

        let ead_device = ZeroTouchDeviceWaitEAD2 {
            prk: PRK_TV.try_into().unwrap(),
            h_message_1: H_MESSAGE_1_TV.try_into().unwrap(),
        };

        let res = ead_device.process_ead_2(
            &mut default_crypto(),
            &ead_2_tv,
            CRED_V_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let ead_device = res.unwrap();
        assert_eq!(ead_device.voucher, VOUCHER_MAC_TV); // TODO: maybe should use the encoded voucher instead?
    }
}

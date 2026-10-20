use crate::consts::*;
use lakers_shared::{Crypto as CryptoTrait, *};

pub(crate) fn compute_prk<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    a: &BytesP256ElemLen,
    g_b: &BytesP256ElemLen,
) -> BytesHashLen {
    // NOTE: salt should be h'' (the zero-length byte string), but crypto backends are hardcoded to salts of size SHA256_DIGEST_LEN (32).
    //       nevertheless, using a salt of HashLen zeros works as well (see RFC 5869, Section 2.2).
    let salt: BytesHashLen = [0u8; SHA256_DIGEST_LEN];
    let g_ab = crypto.p256_ecdh(a, g_b);
    crypto.hkdf_extract(&salt, &g_ab)
}

pub(crate) fn compute_prk_from_secret<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    g_ab: &BytesP256ElemLen,
) -> BytesHashLen {
    // NOTE: salt should be h'' (the zero-length byte string), but crypto backends are hardcoded to salts of size SHA256_DIGEST_LEN (32).
    //       nevertheless, using a salt of HashLen zeros works as well (see RFC 5869, Section 2.2).
    let salt: BytesHashLen = [0u8; SHA256_DIGEST_LEN];
    crypto.hkdf_extract(&salt, &g_ab)
}

pub(crate) fn prepare_voucher<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    h_message_1: &BytesHashLen,
    cred_v: &[u8],
    prk: &BytesP256ElemLen,
) -> BytesVoucher {
    let voucher_input = encode_voucher_input(&h_message_1, &cred_v);
    let voucher_mac = compute_voucher_mac(crypto, &prk, &voucher_input);
    voucher_mac
}

pub(crate) fn compute_k_1_iv_1<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    prk: &BytesHashLen,
) -> (BytesCcmKeyLen, BytesCcmIvLen) {
    // K_1 = EDHOC-Expand(PRK, info = (0, h'', AES_CCM_KEY_LEN), length)
    let mut k_1: BytesCcmKeyLen = [0x00; AES_CCM_KEY_LEN];
    edhoc_kdf_expand(crypto, prk, EAD_AUTHZ_INFO_K_1_LABEL, &[], &mut k_1[..]);

    // IV_1 = EDHOC-Expand(PRK, info = (1, h'', AES_CCM_IV_LEN), length)
    let mut iv_1: BytesCcmIvLen = [0x00; AES_CCM_IV_LEN];
    edhoc_kdf_expand(crypto, prk, EAD_AUTHZ_INFO_IV_1_LABEL, &[], &mut iv_1[..]);

    (k_1, iv_1)
}

pub(crate) fn parse_ead_1_value(
    value: &[u8],
) -> Result<(EdhocMessageBuffer, EdhocMessageBuffer), EDHOCError> {
    let mut seq_decoder = CBORDecoder::new(value);
    Ok((
        seq_decoder.str()?.try_into().unwrap(),
        seq_decoder.bytes()?.try_into().unwrap(),
    ))
}

pub(crate) fn encode_enc_structure(ss: u8) -> [u8; EAD_AUTHZ_ENC_STRUCTURE_LEN] {
    let encrypt0 = b"Encrypt0";

    let mut enc_structure = EdhocBuffer::<EAD_AUTHZ_ENC_STRUCTURE_LEN>::new();

    // encode Enc_structure from rfc9052 Section 5.3
    enc_structure.push(CBOR_MAJOR_ARRAY | 3 as u8).unwrap(); // 3 is the fixed number of elements in the array
    enc_structure
        .push(CBOR_MAJOR_TEXT_STRING | encrypt0.len() as u8)
        .unwrap();
    enc_structure.extend_from_slice(encrypt0).unwrap();
    enc_structure
        .push(CBOR_MAJOR_BYTE_STRING | 0x00 as u8)
        .unwrap(); // 0 for zero-length byte string (empty Header)
    enc_structure
        .push(CBOR_MAJOR_BYTE_STRING | 0x01 as u8)
        .unwrap(); // 1 for the `ss` value
    enc_structure.push(ss).unwrap();

    enc_structure
        .as_slice()
        .try_into()
        .expect("All components are fixed length")
}

// private functions

fn encode_voucher_input(h_message_1: &BytesHashLen, cred_v: &[u8]) -> EdhocMessageBuffer {
    let mut voucher_input = EdhocMessageBuffer::new();

    voucher_input.push(CBOR_BYTE_STRING).unwrap();
    voucher_input.push(SHA256_DIGEST_LEN as u8).unwrap();
    voucher_input
        .extend_from_slice(&h_message_1[..SHA256_DIGEST_LEN])
        .unwrap();

    voucher_input.push(CBOR_BYTE_STRING).unwrap();
    voucher_input.push(cred_v.len() as u8).unwrap();
    voucher_input.extend_from_slice(cred_v).unwrap();

    voucher_input
}

fn compute_voucher_mac<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    prk: &BytesHashLen,
    voucher_input: &EdhocMessageBuffer,
) -> BytesMac {
    let mut voucher_mac: BytesMac = [0x00; MAC_LENGTH];

    edhoc_kdf_expand(crypto, prk, 2, voucher_input.as_slice(), &mut voucher_mac);

    voucher_mac
}

fn edhoc_kdf_expand<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    prk: &BytesHashLen,
    label: u8,
    context: &[u8],
    result: &mut [u8],
) {
    let info = encode_info(label, context, result.len());
    crypto.hkdf_expand(prk, info.as_slice(), result);
}

#[cfg(test)]
mod test_shared {
    use super::*;
    use crate::test_vectors::*;

    use lakers_crypto::default_crypto;

    #[test]
    fn test_compute_keys() {
        let k_1_tv: BytesCcmKeyLen = K_1_TV.try_into().unwrap();
        let iv_1_tv: BytesCcmIvLen = IV_1_TV.try_into().unwrap();
        let prk_tv: BytesHashLen = PRK_TV.try_into().unwrap();

        let prk_xw = compute_prk(
            &mut default_crypto(),
            &X_TV.try_into().unwrap(),
            &G_W_TV.try_into().unwrap(),
        );
        let prk_wx = compute_prk(
            &mut default_crypto(),
            &W_TV.try_into().unwrap(),
            &G_X_TV.try_into().unwrap(),
        );
        assert_eq!(prk_xw, prk_tv);
        assert_eq!(prk_xw, prk_wx);

        let (k_1, iv_1) = compute_k_1_iv_1(&mut default_crypto(), &prk_xw);
        assert_eq!(k_1, k_1_tv);
        assert_eq!(iv_1, iv_1_tv);
    }

    #[test]
    fn test_encode_voucher_input() {
        let h_message_1_tv: BytesHashLen = H_MESSAGE_1_TV.try_into().unwrap();
        let voucher_input_tv: EdhocMessageBuffer = VOUCHER_INPUT_TV.try_into().unwrap();

        let voucher_input = encode_voucher_input(&h_message_1_tv, &CRED_V_TV);
        assert_eq!(voucher_input, voucher_input_tv);
    }

    #[test]
    fn test_compute_voucher_mac() {
        let prk_tv: BytesHashLen = PRK_TV.try_into().unwrap();
        let voucher_input_tv: EdhocMessageBuffer = VOUCHER_INPUT_TV.try_into().unwrap();
        let voucher_mac_tv: BytesMac = VOUCHER_MAC_TV.try_into().unwrap();

        let voucher_mac = compute_voucher_mac(&mut default_crypto(), &prk_tv, &voucher_input_tv);
        assert_eq!(voucher_mac, voucher_mac_tv);
    }
}

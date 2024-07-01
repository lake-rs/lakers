use crate::consts::EAD_AUTHZ_LABEL;
use crate::shared::*;
use defmt_or_log::trace;
use lakers_shared::{Crypto as CryptoTrait, *};

/// This server also stores an ACL
#[derive(PartialEq, Debug, Clone)]
pub struct ZeroTouchServer {
    w: BytesP256ElemLen,            // private key of the enrollment server (W)
    pub cred_v: EdhocMessageBuffer, // credential of the authenticator (V)
    // access control list, each device identified by an u8 kid (this is arbitrary, it is not specified in the draft)
    pub acl: Option<EdhocMessageBuffer>,
}

impl ZeroTouchServer {
    pub fn new(w: BytesP256ElemLen, cred_v: &[u8], acl: Option<EdhocMessageBuffer>) -> Self {
        trace!("Initializing ZeroTouchServer");
        let cred_v: EdhocMessageBuffer = cred_v.try_into().unwrap();
        ZeroTouchServer { w, cred_v, acl }
    }

    pub fn authorized(&self, kid: u8) -> bool {
        if let Some(acl) = self.acl.as_ref() {
            acl.contains(&kid)
        } else {
            // if no acl then allow it
            true
        }
    }

    pub fn handle_voucher_request<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        vreq: &EdhocMessageBuffer,
    ) -> Result<EdhocMessageBuffer, EDHOCError> {
        trace!("Enter handle_voucher_request");
        let (message_1, opaque_state) = parse_voucher_request(vreq)?;
        let (_method, _suites_i, g_x, _c_i, mut ead_1) = parse_message_1(&message_1)?;
        let prk = compute_prk(crypto, &self.w, &g_x);

        // Not so much "EAD Unprocessable" but more "we really would have needed that EAD"
        let ead_item = ead_1
            .pop_by_label(EAD_AUTHZ_LABEL)
            .ok_or(EDHOCError::EADUnprocessable)?;
        ead_1.processed_critical_items()?;
        let (_loc_w, enc_id) = parse_ead_1_value(&ead_item.value_bytes().unwrap())?;
        let id_u_encoded = decrypt_enc_id(crypto, &prk, &enc_id, EDHOC_SUPPORTED_SUITES[0])?;
        let id_u = decode_id_u(id_u_encoded)?;

        if self.acl.is_none() || self.authorized(id_u[3]) {
            let h_message_1 = crypto.sha256_digest(message_1.as_slice());

            let voucher = prepare_voucher(crypto, &h_message_1, &self.cred_v.as_slice(), &prk);
            let voucher_response = encode_voucher_response(&message_1, &voucher, &opaque_state);
            Ok(voucher_response)
        } else {
            Err(EDHOCError::AccessDenied)
        }
    }
}

/// This server can be used when the ACL is stored in the application layer
#[derive(PartialEq, Debug, Clone)]
pub struct ZeroTouchServerUserAcl {
    w: BytesP256ElemLen,            // private key of the enrollment server (W)
    pub cred_v: EdhocMessageBuffer, // credential of the authenticator (V)
}

impl ZeroTouchServerUserAcl {
    pub fn new(w: BytesP256ElemLen, cred_v: &[u8]) -> Self {
        trace!("Initializing ZeroTouchServerUserAcl");
        let cred_v: EdhocMessageBuffer = cred_v.try_into().unwrap();
        Self { w, cred_v }
    }

    pub fn decode_voucher_request<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        vreq: &EdhocMessageBuffer,
    ) -> Result<EdhocMessageBuffer, EDHOCError> {
        trace!("Enter decode_voucher_request");
        let (message_1, _opaque_state) = parse_voucher_request(vreq)?;
        let (_method, _suites_i, g_x, _c_i, _id_cred, ead_1) = parse_message_1(&message_1)?;
        let prk = compute_prk(crypto, &self.w, &g_x);

        let ead_item = ead_1.iter().next().ok_or(EDHOCError::EADUnprocessable)?;
        let (_loc_w, enc_id) = parse_ead_1_value(&ead_item.value_bytes().unwrap())?;
        let id_u_encoded = decrypt_enc_id(crypto, &prk, &enc_id, EDHOC_SUPPORTED_SUITES[0])?;

        decode_id_u(id_u_encoded)
    }

    pub fn prepare_voucher<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        vreq: &EdhocMessageBuffer,
    ) -> Result<EdhocMessageBuffer, EDHOCError> {
        trace!("Enter prepare_voucher");
        let (message_1, opaque_state) = parse_voucher_request(vreq)?;
        let (_method, _suites_i, g_x, _c_i, _id_cred, _ead_1) = parse_message_1(&message_1)?;
        let prk = compute_prk(crypto, &self.w, &g_x);

        let h_message_1 = crypto.sha256_digest(message_1.as_slice());

        let voucher = prepare_voucher(crypto, &h_message_1, &self.cred_v.as_slice(), &prk);
        let voucher_response = encode_voucher_response(&message_1, &voucher, &opaque_state);
        Ok(voucher_response)
    }
}

fn parse_voucher_request(
    vreq: &EdhocMessageBuffer,
) -> Result<(BufferMessage1, Option<EdhocMessageBuffer>), EDHOCError> {
    let mut decoder = CBORDecoder::new(vreq.as_slice());
    let array_size = decoder.array()?;
    if array_size != 1 && array_size != 2 {
        return Err(EDHOCError::EADUnprocessable);
    }

    let message_1: BufferMessage1 = decoder.bytes()?.try_into().unwrap();

    if array_size == 2 {
        let opaque_state: EdhocMessageBuffer = decoder.bytes()?.try_into().unwrap();
        Ok((message_1, Some(opaque_state)))
    } else {
        Ok((message_1, None))
    }
}

fn decrypt_enc_id<Crypto: CryptoTrait>(
    crypto: &mut Crypto,
    prk: &BytesHashLen,
    enc_id: &EdhocMessageBuffer,
    ss: u8,
) -> Result<EdhocMessageBuffer, EDHOCError> {
    let (k_1, iv_1) = compute_k_1_iv_1(crypto, &prk);

    // external_aad = (SS: int)
    let enc_structure = encode_enc_structure(ss);

    // ENC_ID = 'ciphertext' of COSE_Encrypt0
    crypto.aes_ccm_decrypt_tag_8(&k_1, &iv_1, &enc_structure[..], enc_id.as_slice())
}

fn decode_id_u(id_u_bstr: EdhocMessageBuffer) -> Result<EdhocMessageBuffer, EDHOCError> {
    // id_u is encoded as bstr
    let mut decoder = CBORDecoder::new(id_u_bstr.as_slice());
    let id_u: EdhocMessageBuffer = decoder.bytes()?.try_into().unwrap();
    Ok(id_u)
}

fn encode_voucher_response(
    message_1: &BufferMessage1,
    voucher: &BytesVoucher,
    opaque_state: &Option<EdhocMessageBuffer>,
) -> EdhocMessageBuffer {
    let mut output = EdhocMessageBuffer::new();

    if opaque_state.is_some() {
        output.push(CBOR_MAJOR_ARRAY | 3).unwrap();
    } else {
        output.push(CBOR_MAJOR_ARRAY | 2).unwrap();
    }
    output.push(CBOR_BYTE_STRING).unwrap();
    output.push(message_1.len() as u8).unwrap();
    output.extend_from_slice(message_1.as_slice()).unwrap();

    output
        .push(CBOR_MAJOR_BYTE_STRING + 1 + VOUCHER_LEN as u8)
        .unwrap();
    // The voucher is double-wrapped in bytes; see
    // <https://github.com/lake-rs/lakers/issues/382>
    output.push(0x48).unwrap();
    output.extend_from_slice(voucher).unwrap();

    if let Some(opaque_state) = opaque_state {
        output.push(CBOR_BYTE_STRING).unwrap();
        output.push(opaque_state.len() as u8).unwrap();
        output.extend_from_slice(opaque_state.as_slice()).unwrap();
    }

    output
}

#[cfg(test)]
mod test_enrollment_server {
    use super::*;
    use crate::test_vectors::*;
    use lakers_crypto::default_crypto;

    #[test]
    fn test_decrypt_enc_id() {
        let mut prk_tv: BytesHashLen = Default::default();
        prk_tv[..].copy_from_slice(PRK_TV);
        let id_u_encoded_tv: EdhocMessageBuffer = ID_U_ENCODED_TV.try_into().unwrap();

        let id_u_res = decrypt_enc_id(
            &mut default_crypto(),
            &prk_tv,
            &ENC_ID_TV.try_into().unwrap(),
            SS_TV,
        );
        assert!(id_u_res.is_ok());
        assert_eq!(id_u_res.unwrap(), id_u_encoded_tv);
    }

    #[test]
    fn test_prepare_voucher() {
        let h_message_1: BytesHashLen = H_MESSAGE_1_TV.try_into().unwrap();
        let prk: BytesHashLen = PRK_TV.try_into().unwrap();

        let voucher = prepare_voucher(&mut default_crypto(), &h_message_1, &CRED_V_TV, &prk);
        assert_eq!(voucher, VOUCHER_MAC_TV);
    }

    #[test]
    fn test_encode_voucher_response() {
        let message_1_tv = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let opaque_state_tv: EdhocMessageBuffer = SLO_OPAQUE_STATE_TV.try_into().unwrap();
        let voucher_response_tv: EdhocMessageBuffer = SLO_VOUCHER_RESPONSE_TV.try_into().unwrap();

        let voucher_response =
            encode_voucher_response(&message_1_tv, &VOUCHER_MAC_TV, &Some(opaque_state_tv));
        assert_eq!(voucher_response, voucher_response_tv);
    }

    #[test]
    fn test_parse_voucher_request() {
        let voucher_request_tv: EdhocMessageBuffer = VOUCHER_REQUEST_TV.try_into().unwrap();
        let message_1_tv: BufferMessage1 = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();

        let voucher_request = parse_voucher_request(&voucher_request_tv);
        assert!(voucher_request.is_ok());
        let (message_1, opaque_state) = voucher_request.unwrap();
        assert_eq!(message_1, message_1_tv);
        assert!(opaque_state.is_none());
    }

    #[test]
    fn test_handle_voucher_request_acl_none() {
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();

        let ead_server = ZeroTouchServer::new(W_TV.try_into().unwrap(), CRED_V_TV, None);

        let res = ead_server.handle_voucher_request(
            &mut default_crypto(),
            &VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let voucher_response = res.unwrap();
        assert_eq!(voucher_response, voucher_response_tv);
    }

    #[test]
    fn test_handle_voucher_request_acl_ok() {
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();

        let ead_server = ZeroTouchServer::new(
            W_TV.try_into().unwrap(),
            CRED_V_TV,
            Some(ACL_TV.try_into().unwrap()),
        );

        let res = ead_server.handle_voucher_request(
            &mut default_crypto(),
            &VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let voucher_response = res.unwrap();
        assert_eq!(voucher_response, voucher_response_tv);
    }

    #[test]
    fn test_handle_voucher_request_acl_invalid() {
        let ead_server = ZeroTouchServer::new(
            W_TV.try_into().unwrap(),
            CRED_V_TV,
            Some(ACL_INVALID_TV.try_into().unwrap()),
        );

        let res = ead_server.handle_voucher_request(
            &mut default_crypto(),
            &VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert_eq!(res.unwrap_err(), EDHOCError::AccessDenied);
    }
}

#[cfg(test)]
mod test_enrollment_server_acl_user {
    use super::*;
    use crate::test_vectors::*;
    use lakers_crypto::default_crypto;

    #[test]
    fn test_split_voucher_request_handling() {
        let voucher_response_tv: EdhocMessageBuffer = VOUCHER_RESPONSE_TV.try_into().unwrap();
        let id_u_tv: EdhocMessageBuffer = ID_U_TV.try_into().unwrap();

        let ead_server = ZeroTouchServerUserAcl::new(W_TV.try_into().unwrap(), CRED_V_TV);

        let res = ead_server.decode_voucher_request(
            &mut default_crypto(),
            &VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let id_u = res.unwrap();
        assert_eq!(id_u, id_u_tv);

        let res = ead_server.prepare_voucher(
            &mut default_crypto(),
            &VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let voucher_response = res.unwrap();
        assert_eq!(voucher_response, voucher_response_tv);
    }
}

#[cfg(test)]
mod test_server_stateless_operation {
    use super::*;
    use crate::test_vectors::*;
    use lakers_crypto::default_crypto;

    #[test]
    fn test_slo_parse_voucher_request() {
        let voucher_request_tv: EdhocMessageBuffer = SLO_VOUCHER_REQUEST_TV.try_into().unwrap();
        let message_1_tv: BufferMessage1 = MESSAGE_1_WITH_EAD_TV.try_into().unwrap();
        let opaque_state_tv: EdhocMessageBuffer = SLO_OPAQUE_STATE_TV.try_into().unwrap();

        let voucher_request = parse_voucher_request(&voucher_request_tv);
        assert!(voucher_request.is_ok());
        let (message_1, opaque_state) = voucher_request.unwrap();
        assert_eq!(message_1, message_1_tv);
        assert_eq!(opaque_state.unwrap(), opaque_state_tv);
    }

    #[test]
    fn test_slo_handle_voucher_request() {
        let voucher_response_tv: EdhocMessageBuffer = SLO_VOUCHER_RESPONSE_TV.try_into().unwrap();

        let ead_server = ZeroTouchServer::new(W_TV.try_into().unwrap(), CRED_V_TV, None);

        let res = ead_server.handle_voucher_request(
            &mut default_crypto(),
            &SLO_VOUCHER_REQUEST_TV.try_into().unwrap(),
        );
        assert!(res.is_ok());
        let voucher_response = res.unwrap();
        assert_eq!(voucher_response, voucher_response_tv);
    }
}

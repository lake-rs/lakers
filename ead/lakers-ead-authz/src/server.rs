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
        let value = ead_item.value_bytes().ok_or(EDHOCError::EADUnprocessable)?;
        let (_loc_w, enc_id) = parse_ead_1_value(value)?;
        let id_u_encoded = decrypt_enc_id(crypto, &prk, &enc_id, EDHOC_SUPPORTED_SUITES[0])?;
        let id_u = decode_id_u(id_u_encoded)?;

        // A too-short ID_U has no KID; with an ACL it cannot be authorized.
        let kid = id_u.as_slice().get(3).copied();
        if self.acl.is_none() || kid.is_some_and(|kid| self.authorized(kid)) {
            let h_message_1 = crypto.sha256_digest(message_1.as_slice());

            let voucher = prepare_voucher(crypto, &h_message_1, &self.cred_v.as_slice(), &prk);
            encode_voucher_response(&message_1, &voucher, &opaque_state)
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
        let (_method, _suites_i, g_x, _c_i, ead_1) = parse_message_1(&message_1)?;
        let prk = compute_prk(crypto, &self.w, &g_x);

        let ead_item = ead_1.iter().next().ok_or(EDHOCError::EADUnprocessable)?;
        let value = ead_item.value_bytes().ok_or(EDHOCError::EADUnprocessable)?;
        let (_loc_w, enc_id) = parse_ead_1_value(value)?;
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
        let (_method, _suites_i, g_x, _c_i, _ead_1) = parse_message_1(&message_1)?;
        let prk = compute_prk(crypto, &self.w, &g_x);

        let h_message_1 = crypto.sha256_digest(message_1.as_slice());

        let voucher = prepare_voucher(crypto, &h_message_1, &self.cred_v.as_slice(), &prk);
        encode_voucher_response(&message_1, &voucher, &opaque_state)
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
    // aes_ccm_decrypt subtracts the tag length without checking, so a shorter ENC_ID is malformed.
    if enc_id.len() < CcmTagLen8::LEN {
        return Err(EDHOCError::EADUnprocessable);
    }

    let (k_1, iv_1) = compute_k_1_iv_1(crypto, &prk);

    // external_aad = (SS: int)
    let enc_structure = encode_enc_structure(ss);

    // ENC_ID = 'ciphertext' of COSE_Encrypt0
    crypto.aes_ccm_decrypt::<MAX_MESSAGE_SIZE_LEN, CcmTagLen8>(
        &k_1,
        &iv_1,
        &enc_structure[..],
        enc_id.as_slice(),
    )
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
) -> Result<EdhocMessageBuffer, EDHOCError> {
    let mut output = EdhocMessageBuffer::new();

    if opaque_state.is_some() {
        output.push(CBOR_MAJOR_ARRAY | 3).map_err(enc_err)?;
    } else {
        output.push(CBOR_MAJOR_ARRAY | 2).map_err(enc_err)?;
    }
    // A one-byte header cannot express a length over 255; reject rather than truncate.
    let message_1_len: u8 = message_1.len().try_into().map_err(enc_err)?;
    output.push(CBOR_BYTE_STRING).map_err(enc_err)?;
    output.push(message_1_len).map_err(enc_err)?;
    output
        .extend_from_slice(message_1.as_slice())
        .map_err(enc_err)?;

    output
        .push(CBOR_MAJOR_BYTE_STRING + 1 + VOUCHER_LEN as u8)
        .map_err(enc_err)?;
    // The voucher is double-wrapped in bytes; see
    // <https://github.com/lake-rs/lakers/issues/382>
    output.push(0x48).map_err(enc_err)?;
    output.extend_from_slice(voucher).map_err(enc_err)?;

    if let Some(opaque_state) = opaque_state {
        let opaque_state_len: u8 = opaque_state.len().try_into().map_err(enc_err)?;
        output.push(CBOR_BYTE_STRING).map_err(enc_err)?;
        output.push(opaque_state_len).map_err(enc_err)?;
        output
            .extend_from_slice(opaque_state.as_slice())
            .map_err(enc_err)?;
    }

    Ok(output)
}

#[cfg(test)]
mod test_enrollment_server {
    use super::*;
    use crate::authenticator::encode_voucher_request;
    use crate::test_vectors::*;
    use crate::ZeroTouchDevice;
    use lakers_crypto::default_crypto;

    // Layout of `MESSAGE_1_WITH_EAD_TV`: METHOD, SUITES_I, G_X and C_I, then the EAD items.
    const G_X_OFFSET: usize = 6;
    const G_X_LEN: usize = 32;
    const EAD_OFFSET: usize = G_X_OFFSET + G_X_LEN + 1;

    /// A `message_1` built from the test-vector preamble (through `C_I`) with `ead` appended.
    ///
    /// The preamble embeds `G_X_TV`; the short-ID_U test relies on it matching the `G_XW_TV` secret
    /// used by `ZeroTouchDevice::prepare_ead_1`.
    fn message_1_with_ead(ead: &[u8]) -> EdhocMessageBuffer {
        // The short-ID_U test would otherwise only fail as a confusing MacVerificationFailed.
        debug_assert_eq!(
            &MESSAGE_1_WITH_EAD_TV[G_X_OFFSET..G_X_OFFSET + G_X_LEN],
            G_X_TV
        );
        let mut message_1 =
            EdhocMessageBuffer::new_from_slice(&MESSAGE_1_WITH_EAD_TV[..EAD_OFFSET]).unwrap();
        message_1.extend_from_slice(ead).unwrap();
        message_1
    }

    /// A voucher request whose `message_1` carries a well-formed authz `EAD_1` encrypting a 1-byte
    /// `ID_U` (too short to carry a KID).
    fn short_id_u_voucher_request() -> EdhocMessageBuffer {
        let device = ZeroTouchDevice::new(
            EdhocMessageBuffer::new_from_slice(&[0x00]).unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );
        let (_, ead_1) =
            device.prepare_ead_1(&mut default_crypto(), G_XW_TV.try_into().unwrap(), SS_TV);
        let message_1 = message_1_with_ead(ead_1.encode().unwrap().as_slice());
        encode_voucher_request(&message_1, &None).unwrap()
    }

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
    fn test_handle_voucher_request_no_ead_value_returns_error() {
        // message_1 with the authz label but no EAD value
        let message_1 = message_1_with_ead(&[EAD_AUTHZ_LABEL as u8]);
        let vreq = encode_voucher_request(&message_1, &None).unwrap();

        let server = ZeroTouchServer::new(W_TV.try_into().unwrap(), CRED_V_TV, None);
        let res = server.handle_voucher_request(&mut default_crypto(), &vreq);
        assert_eq!(res.unwrap_err(), EDHOCError::EADUnprocessable);
    }

    #[test]
    fn test_decode_voucher_request_no_ead_value_returns_error() {
        let message_1 = message_1_with_ead(&[EAD_AUTHZ_LABEL as u8]);
        let vreq = encode_voucher_request(&message_1, &None).unwrap();

        let server = ZeroTouchServerUserAcl::new(W_TV.try_into().unwrap(), CRED_V_TV);
        let res = server.decode_voucher_request(&mut default_crypto(), &vreq);
        assert_eq!(res.unwrap_err(), EDHOCError::EADUnprocessable);
    }

    #[test]
    fn test_handle_voucher_request_short_enc_id_returns_error() {
        // EAD_1 value = empty text string + a byte string shorter than the AEAD tag.
        for short_enc_id in [&[][..], &[0xaa, 0xbb, 0xcc][..]] {
            let mut value = EdhocMessageBuffer::new();
            value.push(0x60).unwrap(); // empty text string (LOC_W)
            value
                .push(CBOR_MAJOR_BYTE_STRING | short_enc_id.len() as u8)
                .unwrap();
            value.extend_from_slice(short_enc_id).unwrap();

            let ead = EADItem::new_full(EAD_AUTHZ_LABEL, true, Some(value.as_slice()))
                .unwrap()
                .encode()
                .unwrap();
            let message_1 = message_1_with_ead(ead.as_slice());
            let vreq = encode_voucher_request(&message_1, &None).unwrap();

            let server = ZeroTouchServer::new(W_TV.try_into().unwrap(), CRED_V_TV, None);
            let res = server.handle_voucher_request(&mut default_crypto(), &vreq);
            assert_eq!(res.unwrap_err(), EDHOCError::EADUnprocessable);
        }
    }

    #[test]
    fn test_handle_voucher_request_short_id_u_returns_error() {
        let vreq = short_id_u_voucher_request();

        let server = ZeroTouchServer::new(
            W_TV.try_into().unwrap(),
            CRED_V_TV,
            Some(ACL_TV.try_into().unwrap()),
        );
        let res = server.handle_voucher_request(&mut default_crypto(), &vreq);
        assert_eq!(res.unwrap_err(), EDHOCError::AccessDenied);
    }

    #[test]
    fn test_handle_voucher_request_short_id_u_without_acl_is_allowed() {
        // Without an ACL the server enrolls any device, so a short ID_U is allowed.
        let vreq = short_id_u_voucher_request();

        let server = ZeroTouchServer::new(W_TV.try_into().unwrap(), CRED_V_TV, None);
        assert!(server
            .handle_voucher_request(&mut default_crypto(), &vreq)
            .is_ok());
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
            encode_voucher_response(&message_1_tv, &VOUCHER_MAC_TV, &Some(opaque_state_tv))
                .unwrap();
        assert_eq!(voucher_response, voucher_response_tv);
    }

    #[test]
    fn test_encode_voucher_response_too_long_returns_error() {
        // A response is strictly larger than its request, so a large request (or a large
        // opaque_state) must yield an error rather than overflow the buffer.
        let big_message_1 =
            BufferMessage1::new_from_slice(&[0u8; MAX_MESSAGE_SIZE_LEN - 10]).unwrap();
        assert!(encode_voucher_response(&big_message_1, &VOUCHER_MAC_TV, &None).is_err());

        let message_1 = BufferMessage1::new_from_slice(&[0u8; 40]).unwrap();
        let opaque_state =
            EdhocMessageBuffer::new_from_slice(&[0u8; MAX_MESSAGE_SIZE_LEN - 20]).unwrap();
        assert!(encode_voucher_response(&message_1, &VOUCHER_MAC_TV, &Some(opaque_state)).is_err());
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

//! Implementation of [EDHOC] (Ephemeral Diffie-Hellman Over COSE, RFC9528), a lightweight authenticated key
//! exchange for the Internet of Things.
//!
//! The crate provides a high-level interface through the [EdhocInitiator] and the [EdhocResponder]
//! structs. Both these wrap the lower level [State] struct that is mainly used through internal
//! functions in the `edhoc` module. This separation is relevant because the lower level tools are
//! subject of ongoing formal verification, whereas the high-level interfaces aim for good
//! usability.
//!
//! Both [EdhocInitiator] and [EdhocResponder] are used in a type stated way. Following the EDHOC
//! protocol, they generate (or process) messages, progressively provide more information about
//! their peer, and on eventually devolve into an [EdhocInitiatorDone] and [EdhocResponderDone],
//! respectively, through which the EDHOC key material can be obtained.
//!
//! [EDHOC]: https://datatracker.ietf.org/doc/html/rfc9528
#![cfg_attr(not(test), no_std)]

use defmt_or_log::trace;
pub use {lakers_shared::Crypto as CryptoTrait, lakers_shared::*};

mod edhoc;
pub use edhoc::*;

/// Starting point for performing EDHOC in the role of the Initiator.
#[derive(Debug)]
pub struct EdhocInitiator<Crypto: CryptoTrait> {
    state: InitiatorStart,       // opaque state
    i: Option<BytesP256ElemLen>, // static public key of myself
    cred_i: Option<Credential>,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorWaitM2<Crypto: CryptoTrait> {
    state: WaitM2, // opaque state
    i: Option<BytesP256ElemLen>,
    cred_i: Option<Credential>,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorProcessingM2<Crypto: CryptoTrait> {
    state: ProcessingM2, // opaque state
    i: Option<BytesP256ElemLen>,
    cred_i: Option<Credential>,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorProcessedM2<Crypto: CryptoTrait> {
    state: ProcessedM2, // opaque state
    cred_i: Option<Credential>,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorWaitM4<Crypto: CryptoTrait> {
    state: WaitM4, // opaque state
    // cred_i: Option<Credential>,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorProcessingM4<Crypto: CryptoTrait> {
    state: ProcessingM4, // opaque state
    // cred_i: Option<Credential>,
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocInitiatorDone<Crypto: CryptoTrait> {
    state: Completed,
    crypto: Crypto,
}

/// Starting point for performing EDHOC in the role of the Responder.
#[derive(Debug)]
pub struct EdhocResponder<Crypto: CryptoTrait> {
    state: ResponderStart,       // opaque state
    r: Option<BytesP256ElemLen>, // private authentication key of R
    cred_r: Credential,          // R's full credential
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderProcessedM1<Crypto: CryptoTrait> {
    state: ProcessingM1,         // opaque state
    r: Option<BytesP256ElemLen>, // private authentication key of R
    cred_r: Credential,          // R's full credential
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderWaitM3<Crypto: CryptoTrait> {
    state: WaitM3, // opaque state
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderProcessingM3<Crypto: CryptoTrait> {
    state: ProcessingM3, // opaque state
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderProcessedM3<Crypto: CryptoTrait> {
    state: ProcessedM3, // opaque state
    crypto: Crypto,
}

#[derive(Debug)]
pub struct EdhocResponderDone<Crypto: CryptoTrait> {
    state: Completed,
    crypto: Crypto,
}

impl<Crypto: CryptoTrait> EdhocResponder<Crypto> {
    pub fn new(
        mut crypto: Crypto,
        method: EDHOCMethod,
        r: Option<BytesP256ElemLen>,
        cred_r: Credential,
    ) -> Self {
        trace!("Initializing EdhocResponder");
        let (y, g_y) = crypto.p256_generate_key_pair();

        EdhocResponder {
            state: ResponderStart {
                y,
                g_y,
                method: method.into(),
                cred_r: cred_r.clone(),
            },
            r,
            cred_r,
            crypto,
        }
    }

    pub fn process_message_1(
        mut self,
        message_1: &BufferMessage1,
    ) -> Result<(EdhocResponderProcessedM1<Crypto>, ConnId, EadItems), EDHOCError> {
        trace!("Enter process_message_1");
        let (state, c_i, ead_1) = r_process_message_1(&self.state, &mut self.crypto, message_1)?;

        Ok((
            EdhocResponderProcessedM1 {
                state,
                r: self.r,
                cred_r: self.cred_r,
                crypto: self.crypto,
            },
            c_i,
            ead_1,
        ))
    }
}

impl<Crypto: CryptoTrait> EdhocResponderProcessedM1<Crypto> {
    pub fn prepare_message_2(
        mut self,
        cred_transfer: CredentialTransfer,
        c_r: Option<ConnId>,
        ead_2: &EadItems,
    ) -> Result<(EdhocResponderWaitM3<Crypto>, BufferMessage2), EDHOCError> {
        trace!("Enter prepare_message_2");
        let c_r = match c_r {
            Some(c_r) => c_r,
            None => generate_connection_identifier_cbor(&mut self.crypto),
        };
        match r_prepare_message_2(
            &self.state,
            &mut self.crypto,
            self.cred_r,
            self.r.as_ref(),
            c_r,
            cred_transfer,
            ead_2,
        ) {
            Ok((state, message_2)) => Ok((
                EdhocResponderWaitM3 {
                    state,
                    crypto: self.crypto,
                },
                message_2,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocResponderWaitM3<Crypto> {
    pub fn parse_message_3(
        mut self,
        message_3: &'a BufferMessage3,
        cred_i: Option<Credential>,
        cred_r: Option<Credential>,
    ) -> Result<(EdhocResponderProcessingM3<Crypto>, Option<IdCred>, EadItems), EDHOCError> {
        trace!("Enter parse_message_3");
        match r_parse_message_3(&mut self.state, &mut self.crypto, message_3, cred_i, cred_r) {
            Ok((state, id_cred_i, ead_3)) => Ok((
                EdhocResponderProcessingM3 {
                    state,
                    crypto: self.crypto,
                },
                id_cred_i,
                ead_3,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocResponderProcessingM3<Crypto> {
    pub fn verify_message_3(
        mut self,
        cred_i: Credential,
        cred_r: Option<Credential>,
    ) -> Result<(EdhocResponderProcessedM3<Crypto>, [u8; SHA256_DIGEST_LEN]), EDHOCError> {
        trace!("Enter verify_message_3");
        match r_verify_message_3(&mut self.state, &mut self.crypto, cred_i, cred_r) {
            Ok((state, prk_out)) => Ok((
                EdhocResponderProcessedM3 {
                    state,
                    crypto: self.crypto,
                },
                prk_out,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<Crypto: CryptoTrait> EdhocResponderProcessedM3<Crypto> {
    pub fn prepare_message_4(
        mut self,
        // cred_transfer: CredentialTransfer,
        ead_4: &EadItems,
    ) -> Result<
        (
            EdhocResponderDone<Crypto>,
            BufferMessage4,
            // [u8; SHA256_DIGEST_LEN]
        ),
        EDHOCError,
    > {
        trace!("Enter prepare_message_4");
        match r_prepare_message_4(
            &self.state,
            &mut self.crypto,
            // cred_transfer,
            ead_4,
        ) {
            Ok((state, message_4)) => Ok((
                EdhocResponderDone {
                    state,
                    crypto: self.crypto,
                },
                message_4,
            )),
            Err(error) => Err(error),
        }
    }
    pub fn completed_without_message_4(
        self,
    ) -> Result<(EdhocResponderDone<Crypto>, [u8; SHA256_DIGEST_LEN]), EDHOCError> {
        trace!("Enter completed");
        match r_complete_without_message_4(&self.state) {
            Ok((state, prk_out)) => Ok((
                EdhocResponderDone {
                    state,
                    crypto: self.crypto,
                },
                prk_out,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<Crypto: CryptoTrait> EdhocResponderDone<Crypto> {
    pub fn edhoc_exporter(&mut self, label: u8, context: &[u8], result: &mut [u8]) {
        edhoc_exporter(&self.state, &mut self.crypto, label, context, result);
    }

    pub fn edhoc_key_update(&mut self, context: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
        edhoc_key_update(&mut self.state, &mut self.crypto, context)
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiator<Crypto> {
    pub fn new(mut crypto: Crypto, method: EDHOCMethod, selected_suite: EDHOCSuite) -> Self {
        trace!("Initializing EdhocInitiator");
        let suites_i = prepare_suites_i(&crypto.supported_suites(), selected_suite.into()).unwrap();
        let (x, g_x) = crypto.p256_generate_key_pair();
        EdhocInitiator {
            state: InitiatorStart {
                x,
                g_x,
                method: method.into(),
                suites_i,
                cred_i: None,
            },
            i: None,
            cred_i: None,
            crypto,
        }
    }

    pub fn set_identity(&mut self, i: Option<BytesP256ElemLen>, cred_i: Credential) {
        self.i = i;
        self.cred_i = Some(cred_i.clone());
        self.state.cred_i = Some(cred_i);
    }

    pub fn prepare_message_1(
        mut self,
        c_i: Option<ConnId>,
        ead_1: &EadItems,
    ) -> Result<(EdhocInitiatorWaitM2<Crypto>, BufferMessage1), EDHOCError> {
        trace!("Enter prepare_message_1");
        let c_i = match c_i {
            Some(c_i) => c_i,
            None => generate_connection_identifier_cbor(&mut self.crypto),
        };
        match i_prepare_message_1(&self.state, &mut self.crypto, c_i, ead_1) {
            Ok((state, message_1)) => Ok((
                EdhocInitiatorWaitM2 {
                    state,
                    i: self.i,
                    cred_i: self.cred_i,
                    crypto: self.crypto,
                },
                message_1,
            )),
            Err(error) => Err(error),
        }
    }

    pub fn compute_ephemeral_secret(&mut self, g_a: &BytesP256ElemLen) -> BytesP256ElemLen {
        self.crypto.p256_ecdh(&self.state.x, g_a)
    }

    pub fn selected_cipher_suite(&self) -> u8 {
        self.state.suites_i[self.state.suites_i.len() - 1]
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorWaitM2<Crypto> {
    pub fn parse_message_2(
        mut self,
        message_2: &'a BufferMessage2,
    ) -> Result<
        (
            EdhocInitiatorProcessingM2<Crypto>,
            ConnId,
            Option<IdCred>,
            EadItems,
        ),
        EDHOCError,
    > {
        trace!("Enter parse_message_2");
        match i_parse_message_2(&self.state, &mut self.crypto, message_2) {
            Ok((state, c_r, id_cred_r, ead_2)) => Ok((
                EdhocInitiatorProcessingM2 {
                    state,
                    i: self.i,
                    cred_i: self.cred_i,
                    crypto: self.crypto,
                },
                c_r,
                id_cred_r,
                ead_2,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorProcessingM2<Crypto> {
    pub fn set_identity(
        &mut self,
        i: Option<BytesP256ElemLen>,
        cred_i: Credential,
    ) -> Result<(), EDHOCError> {
        if self.i.is_some() || self.cred_i.is_some() {
            return Err(EDHOCError::IdentityAlreadySet);
        }
        trace!("identity in setidentiyt: {:?}", i);
        self.i = i;
        self.cred_i = Some(cred_i);
        Ok(())
    }

    pub fn verify_message_2(
        mut self,
        valid_cred_r: Credential,
    ) -> Result<EdhocInitiatorProcessedM2<Crypto>, EDHOCError> {
        trace!("Enter verify_message_2");
        let i_opt = match (self.state.method, self.i.as_ref()) {
            (EDHOCMethod::StatStat, Some(i)) => Some(i),
            (EDHOCMethod::StatStat, None) => return Err(EDHOCError::MissingIdentity),
            (EDHOCMethod::PSK, _) => None, // ignore i in PSK mode
        };

        match i_verify_message_2(&self.state, &mut self.crypto, valid_cred_r, i_opt) {
            Ok(state) => Ok(EdhocInitiatorProcessedM2 {
                state,
                cred_i: self.cred_i,
                crypto: self.crypto,
            }),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorProcessedM2<Crypto> {
    pub fn prepare_message_3(
        mut self,
        cred_transfer: CredentialTransfer,
        ead_3: &EadItems,
    ) -> Result<
        (
            EdhocInitiatorWaitM4<Crypto>,
            BufferMessage3,
            [u8; SHA256_DIGEST_LEN],
        ),
        EDHOCError,
    > {
        trace!("Enter prepare_message_3");
        let Some(cred_i) = self.cred_i.clone() else {
            return Err(EDHOCError::MissingIdentity);
        };
        match i_prepare_message_3(
            &mut self.state,
            &mut self.crypto,
            cred_i,
            cred_transfer,
            ead_3,
        ) {
            Ok((state, message_3, prk_out)) => Ok((
                EdhocInitiatorWaitM4 {
                    state,
                    crypto: self.crypto,
                    // cred_i: self.cred_i,
                },
                message_3,
                prk_out,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorWaitM4<Crypto> {
    pub fn parse_message_4(
        mut self,
        message_4: &'a BufferMessage4,
    ) -> Result<(EdhocInitiatorProcessingM4<Crypto>, EadItems), EDHOCError> {
        trace!("Enter parse_message_4");
        match i_parse_message_4(&mut self.state, &mut self.crypto, message_4) {
            Ok((state, ead_4)) => Ok((
                EdhocInitiatorProcessingM4 {
                    state: state,
                    // cred_i: self.cred_i,
                    crypto: self.crypto,
                },
                ead_4,
            )),
            Err(error) => Err(error),
        }
    }
    pub fn completed_without_message_4(self) -> Result<EdhocInitiatorDone<Crypto>, EDHOCError> {
        trace!("Enter completed");
        match i_complete_without_message_4(&self.state) {
            Ok(state) => Ok(EdhocInitiatorDone {
                state,
                crypto: self.crypto,
            }),
            Err(error) => Err(error),
        }
    }
}

impl<'a, Crypto: CryptoTrait> EdhocInitiatorProcessingM4<Crypto> {
    pub fn verify_message_4(
        // mut self,
        self,
        // valid_cred_r: Credential,
    ) -> Result<EdhocInitiatorDone<Crypto>, EDHOCError> {
        trace!("Enter verify_message_4");
        match i_verify_message_4(&self.state) {
            Ok(state) => Ok(EdhocInitiatorDone {
                state,
                crypto: self.crypto,
            }),
            Err(error) => Err(error),
        }
    }
}

impl<Crypto: CryptoTrait> EdhocInitiatorDone<Crypto> {
    pub fn edhoc_exporter(&mut self, label: u8, context: &[u8], result: &mut [u8]) {
        edhoc_exporter(&self.state, &mut self.crypto, label, context, result);
    }

    pub fn edhoc_key_update(&mut self, context: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
        edhoc_key_update(&mut self.state, &mut self.crypto, context)
    }
}

pub fn generate_connection_identifier_cbor<Crypto: CryptoTrait>(crypto: &mut Crypto) -> ConnId {
    let c_i = generate_connection_identifier(crypto);
    #[allow(deprecated)]
    ConnId::from_int_raw(if c_i >= 0 && c_i <= 23 {
        c_i as u8 // verbatim encoding of single byte integer
    } else if c_i < 0 && c_i >= -24 {
        // negative single byte integer encoding
        CBOR_NEG_INT_1BYTE_START - 1 + c_i.unsigned_abs()
    } else {
        0
    })
}

/// generates an identifier that can be serialized as a single CBOR integer, i.e. -24 <= x <= 23
pub fn generate_connection_identifier<Crypto: CryptoTrait>(crypto: &mut Crypto) -> i8 {
    let mut conn_id = crypto.get_random_byte() as i8;
    while conn_id < -24 || conn_id > 23 {
        conn_id = crypto.get_random_byte() as i8;
    }
    conn_id
}

// Implements auth credential checking according to draft-tiloca-lake-implem-cons
pub fn credential_check_or_fetch(
    cred_expected: Option<Credential>,
    id_cred_received: IdCred,
) -> Result<Credential, EDHOCError> {
    trace!("Enter credential_check_or_fetch");
    // Processing of auth credentials according to draft-tiloca-lake-implem-cons
    // Comments tagged with a number refer to steps in Section 4.3.1. of draft-tiloca-lake-implem-cons
    if let Some(cred_expected) = cred_expected {
        // 1. Does ID_CRED_X point to a stored authentication credential? YES
        // IMPL: compare cred_i_expected with id_cred
        //   IMPL: assume cred_i_expected is well formed
        let credentials_match = if id_cred_received.reference_only() {
            id_cred_received.as_full_value() == cred_expected.by_kid()?.as_full_value()
        } else {
            id_cred_received.as_full_value() == cred_expected.by_value()?.as_full_value()
        };

        // 2. Is this authentication credential still valid?
        // IMPL,TODO: check cred_r_expected is still valid

        // Continue by considering CRED_X as the authentication credential of the other peer.
        // IMPL: ready to proceed, including process ead_2

        if credentials_match {
            Ok(cred_expected)
        } else {
            Err(EDHOCError::UnexpectedCredential)
        }
    } else {
        // 1. Does ID_CRED_X point to a stored authentication credential? NO
        // IMPL: cred_i_expected provided by application is None
        //       id_cred must be a full credential
        // 3. Is the trust model Pre-knowledge-only? NO (hardcoded to NO for now)
        // 4. Is the trust model Pre-knowledge + TOFU? YES (hardcoded to YES for now)
        // 6. Validate CRED_X. Generally a CCS has to be validated only syntactically and semantically, unlike a certificate or a CWT.
        //    Is the validation successful?
        // 5. Is the authentication credential authorized for use in the context of this EDHOC session?
        // IMPL,TODO: we just skip this step for now
        // 7. Store CRED_X as valid and trusted.
        //   Pair it with consistent credential identifiers, for each supported type of credential identifier.

        if let Some(cred) = id_cred_received.get_ccs() {
            Ok(cred)
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    // 8. Is this authentication credential good to use in the context of this EDHOC session?
    // IMPL,TODO: we just skip this step for now
}

#[cfg(test)]
mod test_vectors_common {
    use hexlit::hex;
    use lakers_shared::*;
    pub const ID_CRED_PSK: &[u8] = &hex!("a1044120");
    pub const CRED_I_PSK: &[u8] =
        &hex!("A20269696E69746961746F7208A101A30104024110205050930FF462A77A3540CF546325DEA214");
    pub const CRED_R_PSK: &[u8] =
        &hex!("A20269726573706F6E64657208A101A30104024110205050930FF462A77A3540CF546325DEA214");

    pub const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
    pub const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    pub const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
    pub const _G_I_Y_COORD: &[u8] =
        &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"); // not used
    pub const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");

    pub const MESSAGE_1_TV_FIRST_TIME: BufferMessage1 = BufferMessage1::new_from_array(&hex!(
        "03065820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e"
    ));
    pub const MESSAGE_1_TV: BufferMessage1 = BufferMessage1::new_from_array(&hex!(
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637"
    ));
}

#[cfg(test)]
mod test {
    use super::*;
    use lakers_crypto::default_crypto;
    use test_vectors_common::*;

    #[test]
    fn test_new_initiator() {
        let _initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );
    }

    #[test]
    fn test_new_responder() {
        let r_arr: [u8; 32] = R.try_into().expect("Wrong length of responder private key");
        let r_opt: Option<[u8; 32]> = Some(r_arr);
        let _responder = EdhocResponder::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            r_opt,
            //R.try_into().expect("Wrong length of responder private key"),
            Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap(),
        );
    }

    #[test]
    fn test_prepare_message_1() {
        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );

        let c_i = generate_connection_identifier_cbor(&mut default_crypto());
        let result = initiator.prepare_message_1(Some(c_i), &EadItems::new());
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_message_1() {
        let r_arr: [u8; 32] = R.try_into().expect("Wrong length of responder private key");
        let r_opt: Option<[u8; 32]> = Some(r_arr);
        let responder = EdhocResponder::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            r_opt,
            //R.try_into().expect("Wrong length of responder private key"),
            Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap(),
        );

        // process message_1 first time, when unsupported suite is selected
        let error = responder.process_message_1(&MESSAGE_1_TV_FIRST_TIME);
        assert!(error.is_err());
        assert_eq!(error.unwrap_err(), EDHOCError::UnsupportedCipherSuite);

        // We need to create a new responder -- no message is supposed to be processed twice by a
        // responder or initiator
        let r_arr: [u8; 32] = R.try_into().expect("Wrong length of responder private key");
        let r_opt: Option<[u8; 32]> = Some(r_arr);
        let responder = EdhocResponder::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            r_opt,
            //R.try_into().expect("Wrong length of responder private key"),
            Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap(),
        );

        // process message_1 second time
        let error = responder.process_message_1(&MESSAGE_1_TV);
        assert!(error.is_ok());
    }

    #[test]
    fn test_generate_connection_identifier() {
        let conn_id = generate_connection_identifier(&mut default_crypto());
        assert!(conn_id >= -24 && conn_id <= 23);
    }

    #[cfg(feature = "test-ead-none")]
    #[test]
    fn test_handshake() {
        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );
        let r_arr: [u8; 32] = R.try_into().expect("Wrong length of responder private key");
        let r_opt: Option<[u8; 32]> = Some(r_arr);

        let responder = EdhocResponder::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            r_opt,
            cred_r.clone(),
        ); // has to select an identity before learning who is I

        // ---- begin initiator handling
        // if needed: prepare ead_1
        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();
        // ---- end initiator handling

        // ---- begin responder handling
        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        // if ead_1: process ead_1
        // if needed: prepare ead_2
        let (responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();
        // ---- end responder handling

        // ---- being initiator handling
        let (mut initiator, _c_r, id_cred_r, _ead_2) =
            initiator.parse_message_2(&message_2).unwrap();
        let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r.unwrap()).unwrap();
        let i_arr: [u8; 32] = I.try_into().expect("Wrong length of responder private key");
        let i_opt: Option<[u8; 32]> = Some(i_arr);
        initiator
            .set_identity(
                i_opt,
                //I.try_into().expect("Wrong length of initiator private key"),
                cred_i.clone(),
            )
            .unwrap(); // exposing own identity only after validating cred_r
        let initiator = initiator.verify_message_2(valid_cred_r).unwrap();

        // if needed: prepare ead_3
        let (initiator, message_3, i_prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();
        // ---- end initiator handling

        // ---- begin responder handling
        let (responder, id_cred_i, _ead_3) =
            responder.parse_message_3(&message_3, None, None).unwrap();
        let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i.unwrap()).unwrap();
        let (responder, r_prk_out) = responder.verify_message_3(valid_cred_i, None).unwrap();

        // Send message_4
        let (mut responder, message_4) = responder.prepare_message_4(&EadItems::new()).unwrap();
        // ---- end responder handling

        let (initiator, _ead_4) = initiator.parse_message_4(&message_4).unwrap();
        let mut initiator = initiator.verify_message_4().unwrap();
        // ---- end initiator handling

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let mut i_oscore_secret = [0; 16];
        initiator.edhoc_exporter(0u8, &[], &mut i_oscore_secret); // label is 0
        let mut i_oscore_salt = [0; 8];
        initiator.edhoc_exporter(1u8, &[], &mut i_oscore_salt); // label is 1

        let mut r_oscore_secret = [0; 16];
        responder.edhoc_exporter(0u8, &[], &mut r_oscore_secret); // label is 0
        let mut r_oscore_salt = [0; 8];
        responder.edhoc_exporter(1u8, &[], &mut r_oscore_salt); // label is 1

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);

        // test key update with context from draft-ietf-lake-traces
        let context = &[
            0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
            0xbc, 0xea,
        ];
        let i_prk_out_new = initiator.edhoc_key_update(context);
        let r_prk_out_new = responder.edhoc_key_update(context);

        assert_eq!(i_prk_out_new, r_prk_out_new);
    }
}

#[cfg(feature = "test-ead-authz")]
#[cfg(test)]
mod test_authz {
    use super::*;
    use hexlit::hex;
    use lakers_crypto::default_crypto;
    use lakers_ead_authz::*;
    use test_vectors_common::*;

    // U
    const ID_U_TV: &[u8] = &hex!("a104412b");

    // V -- nothing to do, will reuse CRED_R from above to act as CRED_V

    // W
    pub const W_TV: &[u8] =
        &hex!("4E5E15AB35008C15B89E91F9F329164D4AACD53D9923672CE0019F9ACD98573F");
    const G_W_TV: &[u8] = &hex!("FFA4F102134029B3B156890B88C9D9619501196574174DCB68A07DB0588E4D41");
    const LOC_W_TV: &[u8] = &hex!("636F61703A2F2F656E726F6C6C6D656E742E736572766572");

    // TODO: have a setup_test function that prepares the common objects for the ead tests
    #[test]
    fn test_handshake_authz() {
        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let mock_fetch_cred_i = |id_cred_i: IdCred| -> Result<Credential, EDHOCError> {
            if id_cred_i.as_full_value() == cred_i.by_kid()?.as_full_value() {
                Ok(cred_i.clone())
            } else {
                Err(EDHOCError::UnexpectedCredential)
            }
        };

        // ==== initialize edhoc ====
        let mut initiator = EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );
        let responder = EdhocResponder::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            R.try_into().expect("Wrong length of responder private key"),
            cred_r.clone(),
        );

        // ==== initialize ead-authz ====
        let device = ZeroTouchDevice::new(
            ID_U_TV.try_into().unwrap(),
            G_W_TV.try_into().unwrap(),
            LOC_W_TV.try_into().unwrap(),
        );
        let authenticator = ZeroTouchAuthenticator::default();

        let single_byte_kid = cred_i.kid.as_ref().unwrap()[0]; // FIXME: add longer kid support in ACL
        let acl = EdhocMessageBuffer::new_from_array(&[single_byte_kid]);
        let server = ZeroTouchServer::new(
            W_TV.try_into().unwrap(),
            CRED_R.try_into().unwrap(),
            Some(acl),
        );

        // ==== begin edhoc with ead-authz ====

        let (mut device, ead_item) = device.prepare_ead_1(
            &mut default_crypto(),
            initiator.compute_ephemeral_secret(&device.g_w),
            initiator.selected_cipher_suite(),
        );
        let mut ead_1 = EadItems::new();
        ead_1.try_push(ead_item).unwrap();
        let (initiator, message_1) = initiator.prepare_message_1(None, &ead_1).unwrap();
        device.set_h_message_1(initiator.state.h_message_1.clone());

        let (responder, _c_i, ead_1) = responder.process_message_1(&message_1).unwrap();
        let ead_2 = if let Some(ead_item) = ead_1.iter().next() {
            let (authenticator, _loc_w, voucher_request) =
                authenticator.process_ead_1(&ead_item, &message_1).unwrap();

            // the line below mocks a request to the server: let voucher_response = auth_client.post(loc_w, voucher_request)?
            let voucher_response = server
                .handle_voucher_request(&mut default_crypto(), &voucher_request)
                .unwrap();

            let res = authenticator.prepare_ead_2(&voucher_response);
            assert!(res.is_ok());
            let mut eads_2 = EadItems::new();
            eads_2
                .try_push(authenticator.prepare_ead_2(&voucher_response).unwrap())
                .unwrap();

            eads_2
        } else {
            EadItems::new()
        };
        let (responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByValue, None, &ead_2)
            .unwrap();

        let (mut initiator, _c_r, id_cred_r, ead_2) =
            initiator.parse_message_2(&message_2).unwrap();
        let valid_cred_r = credential_check_or_fetch(None, id_cred_r).unwrap();
        let result =
            device.process_ead_2(&mut default_crypto(), ead_2.iter().next().unwrap(), CRED_R);
        assert!(result.is_ok());
        initiator
            .set_identity(
                I.try_into().expect("Wrong length of initiator private key"),
                cred_i.clone(),
            )
            .unwrap();
        let initiator = initiator.verify_message_2(valid_cred_r).unwrap();

        let (initiator, message_3, i_prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();
        let _initiator = initiator.completed_without_message_4();
        let (responder, id_cred_i, _ead_3) = responder.parse_message_3(&message_3).unwrap();
        let valid_cred_i = if id_cred_i.reference_only() {
            mock_fetch_cred_i(id_cred_i).unwrap()
        } else {
            id_cred_i.get_ccs().unwrap()
        };
        let (responder, r_prk_out) = responder.verify_message_3(valid_cred_i).unwrap();

        let mut _responder = responder.completed_without_message_4();
        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);
    }
}

#![cfg_attr(not(test), no_std)]
#![allow(warnings)]

pub use {
    edhoc_consts::State as EdhocState, edhoc_consts::*, edhoc_crypto::default_crypto,
    edhoc_crypto_trait::Crypto as CryptoTrait,
};

#[cfg(any(feature = "ead-none", feature = "ead-zeroconf"))]
pub use edhoc_ead::*;

mod edhoc;
use edhoc::*;

use edhoc_consts::*;

#[derive(Default, Debug)]
pub struct EdhocInitiator<'a> {
    state: State,             // opaque state
    i: &'a [u8],              // private authentication key of I
    cred_i: &'a [u8],         // I's full credential
    cred_r: Option<&'a [u8]>, // R's full credential (if provided)
}

#[derive(Default, Debug)]
pub struct EdhocInitiatorWaitM2<'a> {
    state: State,             // opaque state
    i: &'a [u8],              // private authentication key of I
    cred_i: &'a [u8],         // I's full credential
    cred_r: Option<&'a [u8]>, // R's full credential (if provided)
}

#[derive(Default, Debug)]
pub struct EdhocInitiatorBuildM3<'a> {
    state: State,             // opaque state
    i: &'a [u8],              // private authentication key of I
    cred_i: &'a [u8],         // I's full credential
    cred_r: Option<&'a [u8]>, // R's full credential (if provided)
}

#[derive(Default, Debug)]
pub struct EdhocInitiatorDone {
    state: State, // opaque state
}

#[derive(Default, Debug)]
pub struct EdhocResponder<'a> {
    state: State,             // opaque state
    r: &'a [u8],              // private authentication key of R
    cred_r: &'a [u8],         // R's full credential
    cred_i: Option<&'a [u8]>, // I's full credential (if provided)
}

#[derive(Default, Debug)]
pub struct EdhocResponderBuildM2<'a> {
    state: State,             // opaque state
    r: &'a [u8],              // private authentication key of R
    cred_r: &'a [u8],         // R's full credential
    cred_i: Option<&'a [u8]>, // I's full credential (if provided)
}

#[derive(Default, Debug)]
pub struct EdhocResponderWaitM3<'a> {
    state: State,             // opaque state
    r: &'a [u8],              // private authentication key of R
    cred_r: &'a [u8],         // R's full credential
    cred_i: Option<&'a [u8]>, // I's full credential (if provided)
}

#[derive(Default, Debug)]
pub struct EdhocResponderDone {
    state: State, // opaque state
}

impl<'a> EdhocResponder<'a> {
    pub fn new(
        state: State,
        r: &'a [u8],
        cred_r: &'a [u8],
        cred_i: Option<&'a [u8]>,
    ) -> EdhocResponder<'a> {
        assert!(r.len() == P256_ELEM_LEN);

        EdhocResponder {
            state,
            r,
            cred_r,
            cred_i,
        }
    }

    pub fn process_message_1(
        self,
        message_1: &BufferMessage1,
    ) -> Result<EdhocResponderBuildM2<'a>, EDHOCError> {
        let state = r_process_message_1(self.state, &mut default_crypto(), message_1)?;

        Ok(EdhocResponderBuildM2 {
            state,
            r: self.r,
            cred_r: self.cred_r,
            cred_i: self.cred_i,
        })
    }
}

impl<'a> EdhocResponderBuildM2<'a> {
    pub fn prepare_message_2(
        self,
        c_r: u8,
    ) -> Result<(EdhocResponderWaitM3<'a>, BufferMessage2), EDHOCError> {
        let (y, g_y) = default_crypto().p256_generate_key_pair();

        match r_prepare_message_2(
            self.state,
            &mut default_crypto(),
            &self.cred_r,
            self.r.try_into().expect("Wrong length of private key"),
            y,
            g_y,
            c_r,
        ) {
            Ok((state, message_2)) => Ok((
                EdhocResponderWaitM3 {
                    state,
                    r: self.r,
                    cred_r: self.cred_r,
                    cred_i: self.cred_i,
                },
                message_2,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a> EdhocResponderWaitM3<'a> {
    pub fn process_message_3(
        self,
        message_3: &BufferMessage3,
    ) -> Result<(EdhocResponderDone, [u8; SHA256_DIGEST_LEN]), EDHOCError> {
        match r_process_message_3(self.state, &mut default_crypto(), message_3, self.cred_i) {
            Ok((state, prk_out)) => Ok((EdhocResponderDone { state }, prk_out)),
            Err(error) => Err(error),
        }
    }
}

impl EdhocResponderDone {
    pub fn edhoc_exporter(
        &mut self,
        label: u8,
        context: &[u8],
        length: usize,
    ) -> Result<[u8; MAX_BUFFER_LEN], EDHOCError> {
        let mut context_buf: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        match edhoc_exporter(
            self.state,
            &mut default_crypto(),
            label,
            &context_buf,
            context.len(),
            length,
        ) {
            Ok((state, output)) => {
                self.state = state;
                Ok(output)
            }
            Err(error) => Err(error),
        }
    }

    pub fn edhoc_key_update(
        &mut self,
        context: &[u8],
    ) -> Result<[u8; SHA256_DIGEST_LEN], EDHOCError> {
        let mut context_buf = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        match edhoc_key_update(
            self.state,
            &mut default_crypto(),
            &context_buf,
            context.len(),
        ) {
            Ok((state, prk_out_new)) => {
                self.state = state;
                Ok(prk_out_new)
            }
            Err(error) => Err(error),
        }
    }
}

impl<'a> EdhocInitiator<'a> {
    pub fn new(
        state: State,
        i: &'a [u8],
        cred_i: &'a [u8],
        cred_r: Option<&'a [u8]>,
    ) -> EdhocInitiator<'a> {
        assert!(i.len() == P256_ELEM_LEN);

        EdhocInitiator {
            state,
            i,
            cred_i,
            cred_r,
        }
    }

    pub fn prepare_message_1(
        self: EdhocInitiator<'a>,
        c_i: u8,
    ) -> Result<(EdhocInitiatorWaitM2<'a>, BufferMessage1), EDHOCError> {
        let (x, g_x) = default_crypto().p256_generate_key_pair();

        match i_prepare_message_1(self.state, &mut default_crypto(), x, g_x, c_i) {
            Ok((state, message_1)) => Ok((
                EdhocInitiatorWaitM2 {
                    state,
                    i: self.i,
                    cred_i: self.cred_i,
                    cred_r: self.cred_r,
                },
                message_1,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a> EdhocInitiatorWaitM2<'a> {
    pub fn process_message_2(
        self,
        message_2: &BufferMessage2,
    ) -> Result<(EdhocInitiatorBuildM3<'a>, u8), EDHOCError> {
        match i_process_message_2(
            self.state,
            &mut default_crypto(),
            message_2,
            self.cred_r,
            self.i
                .try_into()
                .expect("Wrong length of initiator private key"),
        ) {
            Ok((state, c_r, _kid)) => Ok((
                EdhocInitiatorBuildM3 {
                    state,
                    i: self.i,
                    cred_i: self.cred_i,
                    cred_r: self.cred_r,
                },
                c_r,
            )),
            Err(error) => Err(error),
        }
    }
}

impl<'a> EdhocInitiatorBuildM3<'a> {
    pub fn prepare_message_3(
        self,
    ) -> Result<(EdhocInitiatorDone, BufferMessage3, [u8; SHA256_DIGEST_LEN]), EDHOCError> {
        match i_prepare_message_3(
            self.state,
            &mut default_crypto(),
            &get_id_cred(self.cred_i),
            self.cred_i,
        ) {
            Ok((state, message_3, prk_out)) => {
                Ok((EdhocInitiatorDone { state }, message_3, prk_out))
            }
            Err(error) => Err(error),
        }
    }
}

impl EdhocInitiatorDone {
    pub fn edhoc_exporter(
        &mut self,
        label: u8,
        context: &[u8],
        length: usize,
    ) -> Result<[u8; MAX_BUFFER_LEN], EDHOCError> {
        let mut context_buf: BytesMaxContextBuffer = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        match edhoc_exporter(
            self.state,
            &mut default_crypto(),
            label,
            &context_buf,
            context.len(),
            length,
        ) {
            Ok((state, output)) => {
                self.state = state;
                Ok(output)
            }
            Err(error) => Err(error),
        }
    }

    pub fn edhoc_key_update(
        &mut self,
        context: &[u8],
    ) -> Result<[u8; SHA256_DIGEST_LEN], EDHOCError> {
        let mut context_buf = [0x00u8; MAX_KDF_CONTEXT_LEN];
        context_buf[..context.len()].copy_from_slice(context);

        match edhoc_key_update(
            self.state,
            &mut default_crypto(),
            &context_buf,
            context.len(),
        ) {
            Ok((state, prk_out_new)) => {
                self.state = state;
                Ok(prk_out_new)
            }
            Err(error) => Err(error),
        }
    }
}

pub fn generate_connection_identifier_cbor() -> u8 {
    let c_i = generate_connection_identifier();
    if c_i >= 0 && c_i <= 23 {
        c_i as u8 // verbatim encoding of single byte integer
    } else if c_i < 0 && c_i >= -24 {
        // negative single byte integer encoding
        CBOR_NEG_INT_1BYTE_START - 1 + (c_i.abs() as u8)
    } else {
        0
    }
}

/// generates an identifier that can be serialized as a single CBOR integer, i.e. -24 <= x <= 23
pub fn generate_connection_identifier() -> i8 {
    let mut conn_id = default_crypto().get_random_byte() as i8;
    while conn_id < -24 || conn_id > 23 {
        conn_id = default_crypto().get_random_byte() as i8;
    }
    conn_id
}

#[cfg(test)]
mod test {
    use super::*;
    use edhoc_consts::*;
    use hex::FromHex;
    use hexlit::hex;

    const ID_CRED_I: &[u8] = &hex!("a104412b");
    const ID_CRED_R: &[u8] = &hex!("a104410a");
    const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
    const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
    const G_I: &[u8] = &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"); // used
    const _G_I_Y_COORD: &[u8] =
        &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"); // not used
    const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
    const G_R: &[u8] = &hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const C_R_TV: [u8; 1] = hex!("27");

    const MESSAGE_1_TV_FIRST_TIME: &str =
        "03065820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e";
    const MESSAGE_1_TV: &str =
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637";

    #[test]
    fn test_new_initiator() {
        let state: EdhocState = Default::default();
        let _initiator = EdhocInitiator::new(state, I, CRED_I, Some(CRED_R));
        let _initiator = EdhocInitiator::new(state, I, CRED_I, None);
    }

    #[test]
    fn test_new_responder() {
        let state: EdhocState = Default::default();
        let _responder = EdhocResponder::new(state, R, CRED_R, Some(CRED_I));
        let _responder = EdhocResponder::new(state, R, CRED_R, None);
    }

    #[test]
    fn test_prepare_message_1() {
        let state: EdhocState = Default::default();
        let mut initiator = EdhocInitiator::new(state, I, CRED_I, Some(CRED_R));

        let c_i = generate_connection_identifier_cbor();
        let message_1 = initiator.prepare_message_1(c_i);
        assert!(message_1.is_ok());
    }

    #[test]
    fn test_process_message_1() {
        let message_1_tv_first_time = EdhocMessageBuffer::from_hex(MESSAGE_1_TV_FIRST_TIME);
        let message_1_tv = EdhocMessageBuffer::from_hex(MESSAGE_1_TV);
        let state: EdhocState = Default::default();
        let responder = EdhocResponder::new(state, R, CRED_R, Some(CRED_I));

        // process message_1 first time, when unsupported suite is selected
        let error = responder.process_message_1(&message_1_tv_first_time);
        assert!(error.is_err());
        assert_eq!(error.unwrap_err(), EDHOCError::UnsupportedCipherSuite);

        // We need to create a new responder -- no message is supposed to be processed twice by a
        // responder or initiator
        let responder = EdhocResponder::new(state, R, CRED_R, Some(CRED_I));

        // process message_1 second time
        let error = responder.process_message_1(&message_1_tv);
        assert!(error.is_ok());
    }

    #[test]
    fn test_generate_connection_identifier() {
        let conn_id = generate_connection_identifier();
        assert!(conn_id >= -24 && conn_id <= 23);
    }

    #[cfg(feature = "ead-none")]
    #[test]
    fn test_handshake() {
        let state_initiator: EdhocState = Default::default();
        let mut initiator = EdhocInitiator::new(state_initiator, I, CRED_I, Some(CRED_R));
        let state_responder: EdhocState = Default::default();
        let responder = EdhocResponder::new(state_responder, R, CRED_R, Some(CRED_I));

        let c_i: u8 = generate_connection_identifier_cbor();
        let (initiator, result) = initiator.prepare_message_1(c_i).unwrap(); // to update the state

        let responder = responder.process_message_1(&result).unwrap();

        let c_r = generate_connection_identifier_cbor();
        let (responder, message_2) = responder.prepare_message_2(c_r).unwrap();

        assert!(c_r != 0xff);
        let (initiator, _) = initiator.process_message_2(&message_2).unwrap();

        let (mut initiator, message_3, i_prk_out) = initiator.prepare_message_3().unwrap();

        let (mut responder, r_prk_out) = responder.process_message_3(&message_3).unwrap();

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let i_oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
        assert!(i_oscore_secret.is_ok());
        let i_oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1
        assert!(i_oscore_salt.is_ok());

        let r_oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
        assert!(r_oscore_secret.is_ok());
        let r_oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1
        assert!(r_oscore_salt.is_ok());

        assert_eq!(i_oscore_secret.unwrap(), r_oscore_secret.unwrap());
        assert_eq!(i_oscore_salt.unwrap(), r_oscore_salt.unwrap());

        // test key update with context from draft-ietf-lake-traces
        let i_prk_out_new = initiator.edhoc_key_update(&[
            0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
            0xbc, 0xea,
        ]);
        assert!(i_prk_out_new.is_ok());
        let r_prk_out_new = responder.edhoc_key_update(&[
            0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
            0xbc, 0xea,
        ]);
        assert!(r_prk_out_new.is_ok());

        assert_eq!(i_prk_out_new.unwrap(), r_prk_out_new.unwrap());
    }

    // U
    const U_TV: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const ID_U_TV: &[u8] = &hex!("a104412b");

    // V
    pub const CRED_V_TV: &[u8] = &hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");

    // W
    pub const W_TV: &[u8] =
        &hex!("4E5E15AB35008C15B89E91F9F329164D4AACD53D9923672CE0019F9ACD98573F");
    const G_W: &[u8] = &hex!("FFA4F102134029B3B156890B88C9D9619501196574174DCB68A07DB0588E4D41");
    const LOC_W: &[u8] = &hex!("636F61703A2F2F656E726F6C6C6D656E742E736572766572");

    #[cfg(feature = "ead-zeroconf")]
    #[test]
    fn test_ead_zeroconf() {
        let state_initiator: EdhocState = Default::default();
        let mut initiator = EdhocInitiator::new(state_initiator, I, CRED_I, None);
        let state_responder: EdhocState = Default::default();
        let responder = EdhocResponder::new(state_responder, R, CRED_V_TV, Some(CRED_I));

        let u: BytesP256ElemLen = U_TV.try_into().unwrap();
        let id_u: EdhocMessageBuffer = ID_U_TV.try_into().unwrap();
        let g_w: BytesP256ElemLen = G_W.try_into().unwrap();
        let loc_w: EdhocMessageBuffer = LOC_W.try_into().unwrap();
        ead_initiator_set_global_state(EADInitiatorState::new(id_u, g_w, loc_w));

        let ead_initiator_state = ead_initiator_get_global_state();
        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::Start
        );

        ead_responder_set_global_state(EADResponderState::new());
        let ead_responder_state = ead_responder_get_global_state();
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::Start
        );

        let w: BytesP256ElemLen = W_TV.try_into().unwrap();
        mock_ead_server_set_global_state(MockEADServerState::new(
            CRED_V_TV,
            W_TV.try_into().unwrap(),
        ));

        let c_i = generate_connection_identifier_cbor();
        let (initiator, message_1) = initiator.prepare_message_1(c_i).unwrap();
        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::WaitEAD2
        );

        let responder = responder.process_message_1(&message_1).unwrap();
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::ProcessedEAD1
        );

        let c_r = generate_connection_identifier_cbor();
        let (responder, message_2) = responder.prepare_message_2(c_r).unwrap();
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::Completed
        );

        let (initiator, _) = initiator.process_message_2(&message_2).unwrap();

        assert_eq!(
            ead_initiator_state.protocol_state,
            EADInitiatorProtocolState::Completed
        );

        let (initiator, message_3, i_prk_out) = initiator.prepare_message_3().unwrap();

        let (mut responder, r_prk_out) = responder.process_message_3(&message_3).unwrap();
        assert_eq!(i_prk_out, r_prk_out);
        assert_eq!(
            ead_responder_state.protocol_state,
            EADResponderProtocolState::Completed
        );
    }
}

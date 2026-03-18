use lakers::{
    // EdhocInitiator as EdhocInitiatorRust, // alias to conflict with the C-compatible struct
    *,
};
use lakers_crypto::{default_crypto, CryptoTrait};

use crate::*;

/// structs compatible with the C FFI

#[repr(C)]
pub struct EdhocInitiator {
    pub method: EDHOCMethod,
    pub start: InitiatorStart,
    pub wait_m2: WaitM2,
    pub processing_m2: ProcessingM2C,
    pub processed_m2: ProcessedM2C,
    pub wait_m4: WaitM4,
    pub cred_i: *mut CredentialC,
    pub completed: Completed,
}

#[no_mangle]
pub unsafe extern "C" fn initiator_new(initiator: *mut EdhocInitiator, method: EDHOCMethod) -> i8 {
    let mut crypto = default_crypto();
    let suites_i =
        prepare_suites_i(&crypto.supported_suites(), EDHOCSuite::CipherSuite2.into()).unwrap();
    let (x, g_x) = crypto.p256_generate_key_pair();

    let start = InitiatorStart {
        x,
        g_x,
        suites_i,
        method,
    };

    (*initiator).method = method;
    core::ptr::write(&mut (*initiator).start, start);

    0
}

#[no_mangle]
pub unsafe extern "C" fn initiator_prepare_message_1(
    initiator_c: *mut EdhocInitiator,
    // input params
    c_i: *mut u8,
    ead_1_c: *mut EadItemsC,
    // output params
    message_1: *mut EdhocMessageBuffer,
) -> i8 {
    if message_1.is_null() {
        return -1;
    }
    let crypto = &mut default_crypto();

    let c_i = if c_i.is_null() {
        generate_connection_identifier_cbor(crypto)
    } else {
        #[allow(deprecated)]
        ConnId::from_int_raw(*c_i)
    };

    let state = core::ptr::read(&(*initiator_c).start);

    let ead_1 = if ead_1_c.is_null() {
        EadItems::new()
    } else {
        (*ead_1_c).to_rust()
    };

    let result = match i_prepare_message_1(&state, crypto, c_i, &ead_1) {
        Ok((state, msg_1)) => {
            core::ptr::write(&mut *message_1, msg_1);
            core::ptr::write(&mut (*initiator_c).wait_m2, state);
            0
        }
        Err(err) => err as i8,
    };

    result
}

#[no_mangle]
pub unsafe extern "C" fn initiator_parse_message_2(
    // input params
    initiator_c: *mut EdhocInitiator,
    message_2: *const EdhocMessageBuffer,
    // output params
    c_r_out: *mut u8,
    // `ID_CRED_R` is only present for the stat/stat method. C has no `Option<T>`,
    // so this flag tells the caller whether `id_cred_r_out` contains meaningful
    // data for the parsed message 2.
    has_id_cred_r_out: *mut bool,
    id_cred_r_out: *mut IdCred,
    ead_2_c_out: *mut EadItemsC,
) -> i8 {
    // this is a parsing function, so all output parameters are mandatory
    if initiator_c.is_null()
        || message_2.is_null()
        || c_r_out.is_null()
        || has_id_cred_r_out.is_null()
        || id_cred_r_out.is_null()
        || ead_2_c_out.is_null()
    {
        return -1;
    }
    let crypto = &mut default_crypto();

    // manually take `state` because Rust cannot move out of a dereferenced raw pointer directly
    // (raw pointers do not have ownership information, requiring manual handling of the data)
    let state = core::ptr::read(&(*initiator_c).wait_m2);

    let result = match i_parse_message_2(&state, crypto, &(*message_2)) {
        Ok((state, c_r, _details, ead_2)) => {
            ProcessingM2C::copy_into_c(state, &mut (*initiator_c).processing_m2);
            let c_r = c_r.as_slice();
            assert_eq!(c_r.len(), 1, "C API only supports short C_R");
            *c_r_out = c_r[0];

            match (*initiator_c).processing_m2.method_specifics.kind {
                ProcessingM2MethodSpecificsKindC::Pm2StatStat => {
                    *has_id_cred_r_out = true;
                    let stat =
                        unsafe { &(*initiator_c).processing_m2.method_specifics.data.statstat };
                    *id_cred_r_out = stat.id_cred_r.clone();
                }
                ProcessingM2MethodSpecificsKindC::Pm2Psk => {
                    *has_id_cred_r_out = false;
                    // In the PSK method there is no `ID_CRED_R`. We still write a
                    // default value so the output struct is initialized on the C side;
                    // callers must consult `has_id_cred_r_out` before using it.
                    *id_cred_r_out = IdCred::default();
                }
            }

            EadItemsC::copy_into_c(ead_2, ead_2_c_out);

            (*initiator_c).processing_m2.ead_2 = ead_2_c_out;

            0
        }
        Err(err) => err as i8,
    };

    result
}

#[no_mangle]
pub unsafe extern "C" fn initiator_verify_message_2(
    // input params
    initiator_c: *mut EdhocInitiator,
    i: *const BytesP256ElemLen,
    cred_i: *mut CredentialC,
    cred_expected: *mut CredentialC,
) -> i8 {
    if initiator_c.is_null() || cred_i.is_null() {
        return -1;
    }
    let crypto = &mut default_crypto();

    let state = core::ptr::read(&(*initiator_c).processing_m2).to_rust();

    let identity = match (*initiator_c).start.method {
        EDHOCMethod::StatStat => {
            if i.is_null() {
                return -1;
            }
            InitiatorIdentity::StatStat { i: *i }
        }
        EDHOCMethod::PSK => InitiatorIdentity::Psk {},
        _ => return -1,
    };

    let cred_expected = if cred_expected.is_null() {
        None
    } else {
        Some((*cred_expected).to_rust())
    };

    let valid_cred_r = match &state.method_specifics {
        ProcessingM2MethodSpecifics::StatStat { id_cred_r, .. } => {
            lakers::credential_check_or_fetch(cred_expected, id_cred_r.clone())
        }
        ProcessingM2MethodSpecifics::Psk {} => cred_expected.ok_or(EDHOCError::MissingIdentity),
    };

    match valid_cred_r
        .and_then(|valid_cred_r| i_verify_message_2(&state, crypto, valid_cred_r, identity))
    {
        Ok(state) => {
            ProcessedM2C::copy_into_c(state, &mut (*initiator_c).processed_m2);
            (*initiator_c).cred_i = cred_i;
            0
        }
        Err(err) => err as i8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn initiator_prepare_message_3(
    // input params
    initiator_c: *mut EdhocInitiator,
    cred_transfer: CredentialTransfer,
    ead_3_c: *mut EadItemsC,
    // output params
    message_3: *mut EdhocMessageBuffer,
    prk_out_c: *mut [u8; SHA256_DIGEST_LEN],
) -> i8 {
    if initiator_c.is_null() || message_3.is_null() || prk_out_c.is_null() {
        return -1;
    }
    let crypto = &mut default_crypto();

    let state = core::ptr::read(&(*initiator_c).processed_m2).to_rust();

    let ead_3 = if ead_3_c.is_null() {
        EadItems::new()
    } else {
        (*ead_3_c).to_rust()
    };

    match i_prepare_message_3(
        &state,
        crypto,
        (*(*initiator_c).cred_i).to_rust(),
        cred_transfer,
        &ead_3,
    ) {
        Ok((state, msg_3, prk_out)) => {
            (*initiator_c).wait_m4 = state;
            *message_3 = msg_3;
            *prk_out_c = prk_out;
            0
        }
        Err(err) => err as i8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn initiator_process_message_4(
    // input params
    initiator_c: *mut EdhocInitiator,
    message_4: *const EdhocMessageBuffer,
    // output params
    ead_4_c_out: *mut EadItemsC,
) -> i8 {
    // this is a parsing function, so all output parameters are mandatory
    if initiator_c.is_null() || message_4.is_null() || ead_4_c_out.is_null() {
        return -1;
    }
    let crypto = &mut default_crypto();

    let mut state = core::ptr::read(&(*initiator_c).wait_m4);

    let result = match i_process_message_4(&mut state, crypto, &(*message_4)) {
        Ok((state, ead_4)) => {
            (*initiator_c).completed = state;

            EadItemsC::copy_into_c(ead_4, ead_4_c_out);

            0
        }
        Err(err) => err as i8,
    };

    result
}

#[no_mangle]
pub unsafe extern "C" fn completed_without_message_4(
    // input params
    initiator_c: *mut EdhocInitiator,
) -> i8 {
    if initiator_c.is_null() {
        return -1;
    }
    let state = core::ptr::read(&(*initiator_c).wait_m4);

    match i_complete_without_message_4(&state) {
        Ok(state) => {
            (*initiator_c).completed = state;
            0
        }
        Err(err) => err as i8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn initiator_compute_ephemeral_secret(
    initiator_c: *const EdhocInitiator,
    g_a: *const BytesP256ElemLen,
    secret_c_out: *mut BytesP256ElemLen,
) -> i8 {
    if initiator_c.is_null() || g_a.is_null() || secret_c_out.is_null() {
        return -1;
    }

    let state = core::ptr::read(&(*initiator_c).start);

    let secret = default_crypto().p256_ecdh(&state.x, &(*g_a));
    core::ptr::copy_nonoverlapping(secret.as_ptr(), secret_c_out as *mut u8, secret.len());

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexlit::hex;

    const R_STATSTAT: BytesP256ElemLen =
        hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
    const CRED_R_STATSTAT: &[u8] = &hex!(
        "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072"
    );
    const CRED_I_PSK: &[u8] =
        &hex!("a20269696e69746961746f7208a101A30104024110205050930ff462a77a3540cf546325dea214");
    const CRED_R_PSK: &[u8] =
        &hex!("a20269726573706f6e64657208a101a30104024110205050930ff462a77a3540cf546325dea214");

    fn make_ffi_initiator() -> EdhocInitiator {
        EdhocInitiator {
            method: EDHOCMethod::StatStat,
            start: InitiatorStart {
                suites_i: Default::default(),
                method: EDHOCMethod::StatStat,
                x: Default::default(),
                g_x: Default::default(),
            },
            wait_m2: WaitM2 {
                method: EDHOCMethod::StatStat,
                x: Default::default(),
                h_message_1: Default::default(),
            },
            processing_m2: ProcessingM2C::default(),
            processed_m2: ProcessedM2C::default(),
            wait_m4: WaitM4 {
                prk_4e3m: Default::default(),
                th_4: Default::default(),
                prk_out: Default::default(),
                prk_exporter: Default::default(),
            },
            cred_i: core::ptr::null_mut(),
            completed: Completed {
                prk_out: Default::default(),
                prk_exporter: Default::default(),
            },
        }
    }

    fn prepare_message_2_for_method(method: EDHOCMethod) -> (EdhocInitiator, EdhocMessageBuffer) {
        let mut initiator = make_ffi_initiator();
        let mut message_1 = EdhocMessageBuffer::default();

        unsafe {
            assert_eq!(initiator_new(&mut initiator, method), 0);
            assert_eq!(
                initiator_prepare_message_1(
                    &mut initiator,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    &mut message_1,
                ),
                0
            );
        }

        let responder = match method {
            EDHOCMethod::StatStat => EdhocResponder::new(
                default_crypto(),
                ResponderIdentity::StatStat { r: R_STATSTAT },
                Credential::parse_ccs(CRED_R_STATSTAT.try_into().unwrap()).unwrap(),
            ),
            EDHOCMethod::PSK => EdhocResponder::new(
                default_crypto(),
                ResponderIdentity::Psk,
                Credential::parse_ccs_symmetric(CRED_R_PSK.try_into().unwrap()).unwrap(),
            ),
            _ => panic!("unexpected method"),
        };

        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (_responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        (initiator, message_2)
    }

    fn credential_to_c(cred: Credential) -> CredentialC {
        let mut cred_c = core::mem::MaybeUninit::<CredentialC>::uninit();
        unsafe {
            CredentialC::copy_into_c(cred, cred_c.as_mut_ptr());
            cred_c.assume_init()
        }
    }

    #[test]
    // initiator_new_stores_requested_method creates an FFI initiator struct,
    // calls initiator_new, and checks that both initiator.method and
    // initiator.start.method were set to the requested method.
    fn initiator_new_stores_requested_method() {
        let mut initiator = make_ffi_initiator();
        unsafe {
            assert_eq!(initiator_new(&mut initiator, EDHOCMethod::PSK), 0);
        }
        assert!(matches!(initiator.method, EDHOCMethod::PSK));
        assert!(matches!(initiator.start.method, EDHOCMethod::PSK));
    }

    #[test]
    fn initiator_parse_message_2_reports_id_cred_for_statstat() {
        let (mut initiator, message_2) = prepare_message_2_for_method(EDHOCMethod::StatStat);
        let mut c_r_out = 0u8;
        let mut has_id_cred_r_out = false;
        let mut id_cred_r_out = IdCred::default();
        let mut ead_2_out = EadItemsC::default();

        let rc = unsafe {
            initiator_parse_message_2(
                &mut initiator,
                &message_2,
                &mut c_r_out,
                &mut has_id_cred_r_out,
                &mut id_cred_r_out,
                &mut ead_2_out,
            )
        };

        assert_eq!(rc, 0);
        assert!(has_id_cred_r_out);
        assert_ne!(id_cred_r_out, IdCred::default());
    }

    #[test]
    fn initiator_parse_message_2_reports_no_id_cred_for_psk() {
        let (mut initiator, message_2) = prepare_message_2_for_method(EDHOCMethod::PSK);
        let mut c_r_out = 0u8;
        let mut has_id_cred_r_out = true;
        let mut id_cred_r_out = IdCred::default();
        let mut ead_2_out = EadItemsC::default();

        let rc = unsafe {
            initiator_parse_message_2(
                &mut initiator,
                &message_2,
                &mut c_r_out,
                &mut has_id_cred_r_out,
                &mut id_cred_r_out,
                &mut ead_2_out,
            )
        };

        assert_eq!(rc, 0);
        assert!(!has_id_cred_r_out);
        assert_eq!(id_cred_r_out, IdCred::default());
    }

    #[test]
    fn initiator_verify_message_2_accepts_null_i_for_psk() {
        let (mut initiator, message_2) = prepare_message_2_for_method(EDHOCMethod::PSK);
        let mut c_r_out = 0u8;
        let mut has_id_cred_r_out = false;
        let mut id_cred_r_out = IdCred::default();
        let mut ead_2_out = EadItemsC::default();

        let parse_rc = unsafe {
            initiator_parse_message_2(
                &mut initiator,
                &message_2,
                &mut c_r_out,
                &mut has_id_cred_r_out,
                &mut id_cred_r_out,
                &mut ead_2_out,
            )
        };
        assert_eq!(parse_rc, 0);
        assert!(!has_id_cred_r_out);

        let mut cred_i_c = credential_to_c(
            Credential::parse_ccs_symmetric(CRED_I_PSK.try_into().unwrap()).unwrap(),
        );
        let mut valid_cred_r_c = credential_to_c(
            Credential::parse_ccs_symmetric(CRED_R_PSK.try_into().unwrap()).unwrap(),
        );

        let verify_rc = unsafe {
            initiator_verify_message_2(
                &mut initiator,
                core::ptr::null(),
                &mut cred_i_c,
                &mut valid_cred_r_c,
            )
        };

        assert_eq!(verify_rc, 0);
        assert!(matches!(
            initiator.processed_m2.to_rust().method_specifics,
            ProcessedM2MethodSpecifics::Psk { .. }
        ));
    }

    #[test]
    fn initiator_verify_message_2_resolves_cred_for_statstat() {
        let mut initiator = make_ffi_initiator();
        let mut message_1 = EdhocMessageBuffer::default();
        unsafe {
            assert_eq!(initiator_new(&mut initiator, EDHOCMethod::StatStat), 0);
            assert_eq!(
                initiator_prepare_message_1(
                    &mut initiator,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    &mut message_1,
                ),
                0
            );
        }

        let responder = EdhocResponder::new(
            default_crypto(),
            ResponderIdentity::StatStat { r: R_STATSTAT },
            Credential::parse_ccs(CRED_R_STATSTAT.try_into().unwrap()).unwrap(),
        );
        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (_responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByValue, None, &EadItems::new())
            .unwrap();

        let mut c_r_out = 0u8;
        let mut has_id_cred_r_out = false;
        let mut id_cred_r_out = IdCred::default();
        let mut ead_2_out = EadItemsC::default();

        let parse_rc = unsafe {
            initiator_parse_message_2(
                &mut initiator,
                &message_2,
                &mut c_r_out,
                &mut has_id_cred_r_out,
                &mut id_cred_r_out,
                &mut ead_2_out,
            )
        };
        assert_eq!(parse_rc, 0);
        assert!(has_id_cred_r_out);

        let cred_i = Credential::parse_ccs(
            hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
                .as_slice()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let mut cred_i_c = credential_to_c(cred_i);
        let i_statstat: BytesP256ElemLen =
            hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");

        let verify_rc = unsafe {
            initiator_verify_message_2(
                &mut initiator,
                &i_statstat,
                &mut cred_i_c,
                core::ptr::null_mut(),
            )
        };

        // This synthetic setup does not build a full stat/stat transcript that reaches
        // successful verification, but getting a MAC verification failure here shows that
        // the wrapper resolved the responder credential internally and progressed past the
        // old MissingIdentity / caller-must-validate stage.
        assert_eq!(verify_rc, EDHOCError::MacVerificationFailed as i8);
    }
}

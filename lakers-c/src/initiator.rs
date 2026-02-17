use lakers::{
    // EdhocInitiator as EdhocInitiatorRust, // alias to conflict with the C-compatible struct
    *,
};
use lakers_crypto::{default_crypto, CryptoTrait};

use crate::*;

/// structs compatible with the C FFI
// Added C structs because of the Option<> in Rust
#[derive(Debug)]
#[repr(C)]
pub struct EdhocInitiator {
    pub start: InitiatorStartC,
    pub wait_m2: WaitM2C,
    pub processing_m2: ProcessingM2C,
    pub processed_m2: ProcessedM2C,
    pub wait_m4: WaitM4C,
    pub processing_m4: ProcessingM4,
    pub cred_i: *mut CredentialC,
    pub completed: Completed,
}

#[no_mangle]
pub unsafe extern "C" fn initiator_new(initiator: *mut EdhocInitiator) -> i8 {
    let mut crypto = default_crypto();
    let suites_i =
        prepare_suites_i(&crypto.supported_suites(), EDHOCSuite::CipherSuite2.into()).unwrap();
    let (x, g_x) = crypto.p256_generate_key_pair();
    let cred_i = None;
    let start = InitiatorStart {
        x,
        g_x,
        suites_i,
        cred_i,
        method: EDHOCMethod::StatStat,
    };

    // core::ptr::write(&mut (*initiator).start, start);
    InitiatorStartC::copy_into_c(start, &mut (*initiator).start);

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

    let state_c = core::ptr::read(&(*initiator_c).start);
    let state = state_c.to_rust();

    let ead_1 = if ead_1_c.is_null() {
        EadItems::new()
    } else {
        (*ead_1_c).to_rust()
    };

    let result = match i_prepare_message_1(&state, crypto, c_i, &ead_1) {
        Ok((state_next, msg_1)) => {
            core::ptr::write(&mut *message_1, msg_1);
            // core::ptr::write(&mut (*initiator_c).wait_m2, state);
            WaitM2C::copy_into_c(state_next, &mut (*initiator_c).wait_m2);
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
    id_cred_r_out: *mut IdCred,
    ead_2_c_out: *mut EadItemsC,
) -> i8 {
    // this is a parsing function, so all output parameters are mandatory
    if initiator_c.is_null()
        || message_2.is_null()
        || c_r_out.is_null()
        || id_cred_r_out.is_null()
        || ead_2_c_out.is_null()
    {
        return -1;
    }
    let crypto = &mut default_crypto();

    // manually take `state` because Rust cannot move out of a dereferenced raw pointer directly
    // (raw pointers do not have ownership information, requiring manual handling of the data)
    let state_c = core::ptr::read(&(*initiator_c).wait_m2);
    let state = state_c.to_rust();

    let result = match i_parse_message_2(&state, crypto, &(*message_2)) {
        Ok((state_next, c_r, id_cred_r, ead_2)) => {
            let id_cred_r = match id_cred_r {
                Some(v) => v,
                None => return EDHOCError::MissingIdentity as i8,
            };

            ProcessingM2C::copy_into_c(state_next, &mut (*initiator_c).processing_m2);
            let c_r = c_r.as_slice();
            assert_eq!(c_r.len(), 1, "C API only supports short C_R");
            *c_r_out = c_r[0];
            *id_cred_r_out = id_cred_r;

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
    valid_cred_r: *mut CredentialC,
) -> i8 {
    if initiator_c.is_null() || i.is_null() || cred_i.is_null() || valid_cred_r.is_null() {
        return -1;
    }
    let crypto = &mut default_crypto();

    let state_c = core::ptr::read(&(*initiator_c).processing_m2);
    let state = state_c.to_rust();

    match i_verify_message_2(&state, crypto, (*valid_cred_r).to_rust(), Some(&(*i))) {
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

    let state_c = core::ptr::read(&(*initiator_c).processed_m2);
    let state = state_c.to_rust();

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
            WaitM4C::copy_into_c(state, &mut (*initiator_c).wait_m4);
            *message_3 = msg_3;
            *prk_out_c = prk_out;
            0
        }
        Err(err) => err as i8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn initiator_parse_message_4(
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

    let state_c = core::ptr::read(&(*initiator_c).wait_m4);
    let mut state = state_c.to_rust();

    let result = match i_parse_message_4(&mut state, crypto, &(*message_4)) {
        Ok((state, ead_4)) => {
            (*initiator_c).processing_m4 = state;

            EadItemsC::copy_into_c(ead_4, ead_4_c_out);

            0
        }
        Err(err) => err as i8,
    };

    result
}

#[no_mangle]
pub unsafe extern "C" fn initiator_verify_message_4(initiator_c: *mut EdhocInitiator) -> i8 {
    if initiator_c.is_null() {
        return -1;
    }

    let mut state = core::ptr::read(&(*initiator_c).processing_m4);
    match i_verify_message_4(&mut state) {
        Ok(completed) => {
            (*initiator_c).completed = completed;
            0
        }
        Err(err) => err as i8,
    }
}
#[no_mangle]
pub unsafe extern "C" fn completed_without_message_4(
    // input params
    initiator_c: *mut EdhocInitiator,
) -> i8 {
    if initiator_c.is_null() {
        return -1;
    }
    let state_c = core::ptr::read(&(*initiator_c).wait_m4);
    let state = state_c.to_rust();

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

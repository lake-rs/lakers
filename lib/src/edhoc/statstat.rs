use super::{
    compute_mac_2, compute_mac_3, compute_prk_3e2m, compute_prk_4e3m, compute_salt_3e2m,
    compute_salt_4e3m, compute_th_3, compute_th_4, decode_plaintext_2, decode_plaintext_3,
    decrypt_message_3, encode_plaintext_2, encode_plaintext_3, encrypt_message_3, BufferMessage3,
    BufferPlaintext2, BytesHashLen, BytesMac3, BytesP256ElemLen, ConnId, Credential, CredentialKey,
    CredentialTransfer, DecodedMessage2, EDHOCError, EadItems, IdCred, ParsedMessage2Details,
    ParsedMessage3, PreparedMessage2, PreparedMessage3, ProcessedM2, ProcessedM2MethodSpecifics,
    ProcessingM1, ProcessingM2, ProcessingM2MethodSpecifics, ProcessingM3,
    ProcessingM3MethodSpecifics, Th4Input, VerifiedMessage2, VerifiedMessage3, WaitM3,
    WaitM3MethodSpecifics,
};
use lakers_shared::Crypto as CryptoTrait;
pub(crate) fn r_prepare_message_2_statstat(
    state: &ProcessingM1,
    crypto: &mut impl CryptoTrait,
    cred_r: Credential,
    r: &BytesP256ElemLen, // R's static private DH key
    c_r: ConnId,
    cred_transfer: CredentialTransfer,
    ead_2: &EadItems,
    th_2: &BytesHashLen,
    prk_2e: &BytesHashLen,
) -> Result<PreparedMessage2, EDHOCError> {
    // compute prk_3e2m
    let salt_3e2m = compute_salt_3e2m(crypto, &prk_2e, &th_2);
    let prk_3e2m = compute_prk_3e2m(crypto, &salt_3e2m, r, &state.g_x);

    let id_cred_r = match cred_transfer {
        CredentialTransfer::ByValue => cred_r.by_value()?,
        CredentialTransfer::ByReference => cred_r.by_kid()?,
    };

    // compute MAC_2
    let mac_2 = compute_mac_2(
        crypto,
        &prk_3e2m,
        c_r,
        id_cred_r.as_full_value(),
        cred_r.bytes.as_slice(),
        &th_2,
        ead_2,
    );

    // compute ciphertext_2
    let plaintext_2 =
        encode_plaintext_2(c_r, Some((id_cred_r.as_encoded_value(), &mac_2)), &ead_2)?;
    // step is actually from processing of message_3
    // but we do it here to avoid storing plaintext_2 in State
    let th_3 = compute_th_3(crypto, &th_2, &plaintext_2, Some(cred_r.bytes.as_slice()));

    Ok(PreparedMessage2 {
        plaintext_2,
        prk_3e2m,
        th_3,
        method_specifics: WaitM3MethodSpecifics::StatStat {},
    })
}

pub(crate) fn r_parse_message_3_statstat(
    state: &WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
) -> Result<ParsedMessage3, EDHOCError> {
    let plaintext_3 = decrypt_message_3(crypto, &state.prk_3e2m, &state.th_3, message_3, None);

    if let Ok(plaintext_3) = plaintext_3 {
        let decoded_p3_res = decode_plaintext_3(&plaintext_3);

        if let Ok((id_cred_i, mac_3, ead_3)) = decoded_p3_res {
            Ok(ParsedMessage3 {
                method_specifics: ProcessingM3MethodSpecifics::StatStat {
                    mac_3,
                    id_cred_i: id_cred_i.clone(), // needed for compute_mac_3
                },
                id_cred: id_cred_i.clone(),
                plaintext_3, // NOTE: this is needed for th_4, which needs valid_cred_i, which is only available at the 'verify' step
                ead_3: ead_3.clone(), // NOTE: this clone could be avoided by using a reference or an index to the ead_3 item in plaintext_3
            })
        } else {
            Err(decoded_p3_res.unwrap_err())
        }
    } else {
        // error handling for err = decrypt_message_3(&prk_3e2m, &th_3, message_3);
        Err(plaintext_3.unwrap_err())
    }
}

pub(crate) fn r_verify_message_3_statstat(
    state: &ProcessingM3,
    crypto: &mut impl CryptoTrait,
    valid_cred_i: Credential,
    mac_3: BytesMac3,
    id_cred_i: &IdCred,
    salt_4e3m: &BytesHashLen,
) -> Result<VerifiedMessage3, EDHOCError> {
    let prk_4e3m = match valid_cred_i.key {
        CredentialKey::EC2Compact(public_key) => {
            compute_prk_4e3m(crypto, &salt_4e3m, &state.y, &public_key)
        }
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    // compute mac_3
    let expected_mac_3 = compute_mac_3(
        crypto,
        &prk_4e3m,
        &state.th_3,
        id_cred_i.as_full_value(),
        valid_cred_i.bytes.as_slice(),
        &state.ead_3,
    );

    // verify mac_3
    if mac_3 == expected_mac_3 {
        let th_4 = compute_th_4(
            crypto,
            &state.th_3,
            valid_cred_i.bytes.as_slice(),
            Th4Input::Stat {
                plaintext_3: &state.plaintext_3,
            },
        );

        Ok(VerifiedMessage3 { prk_4e3m, th_4 })
    } else {
        Err(EDHOCError::MacVerificationFailed)
    }
}

pub(crate) fn i_parse_message_2_statstat(
    plaintext_2: &BufferPlaintext2,
) -> Result<DecodedMessage2, EDHOCError> {
    let (c_r, id_cred_r, mac_2, ead_2) = decode_plaintext_2(plaintext_2)?;

    Ok(DecodedMessage2 {
        method_specifics: ProcessingM2MethodSpecifics::StatStat {
            mac_2,
            id_cred_r: id_cred_r.clone(),
        },
        c_r,
        parsed_details: ParsedMessage2Details::StatStat { id_cred_r },
        ead_2,
    })
}

pub(crate) fn i_verify_message_2_statstat(
    state: &ProcessingM2,
    crypto: &mut impl CryptoTrait,
    valid_cred_r: Credential,
    i: &BytesP256ElemLen, // I's static private DH key
) -> Result<VerifiedMessage2, EDHOCError> {
    // verify mac_2
    let salt_3e2m = compute_salt_3e2m(crypto, &state.prk_2e, &state.th_2);

    let prk_3e2m = match valid_cred_r.key {
        CredentialKey::EC2Compact(public_key) => {
            compute_prk_3e2m(crypto, &salt_3e2m, &state.x, &public_key)
        }
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let (id_cred_r, mac_2) = match &state.method_specifics {
        ProcessingM2MethodSpecifics::StatStat { id_cred_r, mac_2 } => (id_cred_r, *mac_2),
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let expected_mac_2 = compute_mac_2(
        crypto,
        &prk_3e2m,
        state.c_r,
        id_cred_r.as_full_value(),
        valid_cred_r.bytes.as_slice(),
        &state.th_2,
        &state.ead_2,
    );

    if mac_2 == expected_mac_2 {
        // step is actually from processing of message_3
        // but we do it here to avoid storing plaintext_2 in State
        let th_3 = compute_th_3(
            crypto,
            &state.th_2,
            &state.plaintext_2,
            Some(valid_cred_r.bytes.as_slice()),
        );
        let salt_4e3m = compute_salt_4e3m(crypto, &prk_3e2m, &th_3);
        let prk_4e3m = compute_prk_4e3m(crypto, &salt_4e3m, i, &state.g_y);

        Ok(VerifiedMessage2 {
            method_specifics: ProcessedM2MethodSpecifics::StatStat {},
            prk_3e2m,
            prk_4e3m,
            th_3,
        })
    } else {
        Err(EDHOCError::MacVerificationFailed)
    }
}

pub(crate) fn i_prepare_message_3_statstat(
    state: &ProcessedM2,
    crypto: &mut impl CryptoTrait,
    cred_i: Credential,
    cred_transfer: CredentialTransfer,
    ead_3: &EadItems,
) -> Result<PreparedMessage3, EDHOCError> {
    let id_cred_i = match cred_transfer {
        CredentialTransfer::ByValue => cred_i.by_value()?,
        CredentialTransfer::ByReference => cred_i.by_kid()?,
    };

    let mac_3 = compute_mac_3(
        crypto,
        &state.prk_4e3m,
        &state.th_3,
        id_cred_i.as_full_value(),
        cred_i.bytes.as_slice(),
        ead_3,
    );

    let plaintext_3 = encode_plaintext_3(Some((id_cred_i.as_encoded_value(), &mac_3)), &ead_3)?;
    let message_3 = encrypt_message_3(crypto, &state.prk_3e2m, &state.th_3, &plaintext_3, None)?;

    let th_4 = compute_th_4(
        crypto,
        &state.th_3,
        cred_i.bytes.as_slice(),
        Th4Input::Stat {
            plaintext_3: &plaintext_3,
        },
    );

    Ok(PreparedMessage3 { message_3, th_4 })
}

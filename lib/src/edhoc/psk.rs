// use defmt_or_log::trace;
use super::{
    compute_prk_4e3m_psk, compute_salt_4e3m, compute_th_3, compute_th_4, decode_plaintext_2_psk,
    decode_plaintext_3_psk, decrypt_message_3, encode_ciphertext_3a, encode_plaintext_2,
    encode_plaintext_3, encrypt_decrypt_ciphertext_3a, encrypt_message_3, parse_message_3,
    BufferCiphertext3, BufferMessage3, BufferPlaintext2, BytesHashLen, ConnId, Credential,
    CredentialKey, CredentialTransfer, DecodedMessage2, EDHOCError, EadItems, IdCred,
    ParsedMessage2Details, ParsedMessage3, PreparedMessage2, PreparedMessage3, ProcessedM2,
    ProcessedM2MethodSpecifics, ProcessingM2, ProcessingM2MethodSpecifics, ProcessingM3,
    ProcessingM3MethodSpecifics, Th4Input, VerifiedMessage2, VerifiedMessage3, WaitM3,
    WaitM3MethodSpecifics,
};
use lakers_shared::{CBORDecoder, Crypto as CryptoTrait};

pub(crate) fn r_prepare_message_2_psk(
    crypto: &mut impl CryptoTrait,
    cred_r: Credential,
    c_r: ConnId,
    ead_2: &EadItems,
    th_2: &BytesHashLen,
    prk_2e: &BytesHashLen,
) -> Result<PreparedMessage2, EDHOCError> {
    // compute ciphertext_2
    let plaintext_2 = encode_plaintext_2(c_r, None, &ead_2)?;

    // step is actually from processing of message_3
    // but we do it here to avoid storing plaintext_2 in State
    let th_3 = compute_th_3(crypto, &th_2, &plaintext_2, None);

    Ok(PreparedMessage2 {
        plaintext_2,
        prk_3e2m: *prk_2e,
        th_3,
        method_specifics: WaitM3MethodSpecifics::Psk { cred_r },
    })
}

pub(crate) fn r_parse_message_3_psk(
    state: &WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
    cred_r: &Credential,
) -> Result<ParsedMessage3, EDHOCError> {
    r_parse_message_3_psk_with_cred_resolver(
        state,
        crypto,
        message_3,
        cred_r,
        recover_cred_i_from_id_cred_psk,
    )
}

pub(crate) fn r_parse_message_3_psk_with_cred_resolver<F>(
    state: &WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
    cred_r: &Credential,
    resolve_cred_i: F,
) -> Result<ParsedMessage3, EDHOCError>
where
    F: Fn(&IdCred) -> Result<Credential, EDHOCError>,
{
    let res = parse_message_3(message_3)?;
    let plaintext_3a = encrypt_decrypt_ciphertext_3a(crypto, &state.prk_3e2m, &state.th_3, &res);
    let mut decoder = CBORDecoder::new(plaintext_3a.as_slice());
    let id_cred_psk_encoded = decoder
        .any_as_encoded()
        .map_err(|_| EDHOCError::ParsingError)?;
    let id_cred_psk = IdCred::from_encoded_value(id_cred_psk_encoded)?;
    let ciphertext_3b_bytes = decoder
        .remaining_buffer()
        .map_err(|_| EDHOCError::ParsingError)?;

    let cred_i = resolve_cred_i(&id_cred_psk)?;

    let mut ciphertext_3b = BufferCiphertext3::new();
    ciphertext_3b
        .fill_with_slice(ciphertext_3b_bytes)
        .map_err(|_| EDHOCError::ParsingError)?;

    let plaintext_3b = decrypt_message_3(
        crypto,
        &state.prk_3e2m,
        &state.th_3,
        &ciphertext_3b,
        Some((
            id_cred_psk.as_encoded_value(),
            cred_i.bytes.as_slice(),
            cred_r.bytes.as_slice(),
        )),
    )?;

    let decoded_p3_res = decode_plaintext_3_psk(&plaintext_3b);
    if let Ok(ead_3) = decoded_p3_res {
        Ok(ParsedMessage3 {
            method_specifics: ProcessingM3MethodSpecifics::Psk {
                id_cred_psk: id_cred_psk.clone(),
                cred_r: cred_r.clone(),
            },
            id_cred: id_cred_psk,
            plaintext_3: plaintext_3b, // NOTE: this is needed for th_4, which needs valid_cred_i, which is only available at the 'verify' step
            ead_3: ead_3.clone(), // NOTE: this clone could be avoided by using a reference or an index to the ead_3 item in plaintext_3
        })
    } else {
        Err(decoded_p3_res.unwrap_err())
    }
}

pub(crate) fn r_verify_message_3_psk(
    state: &ProcessingM3,
    crypto: &mut impl CryptoTrait,
    valid_cred_i: Credential,
    id_cred_psk: &IdCred,
    cred_r: &Credential,
    salt_4e3m: &BytesHashLen,
) -> Result<VerifiedMessage3, EDHOCError> {
    let prk_4e3m = match valid_cred_i.key {
        CredentialKey::Symmetric(psk) => compute_prk_4e3m_psk(crypto, &salt_4e3m, &psk),
        // FIXME: find a good definition of error
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let th_4 = compute_th_4(
        crypto,
        &state.th_3,
        valid_cred_i.bytes.as_slice(),
        Th4Input::Psk {
            id_cred: id_cred_psk.as_encoded_value(),
            cred_r: cred_r.bytes.as_slice(),
            ead_3: &state.ead_3,
        },
    );
    Ok(VerifiedMessage3 { prk_4e3m, th_4 })
}

pub(crate) fn i_parse_message_2_psk(
    plaintext_2: &BufferPlaintext2,
) -> Result<DecodedMessage2, EDHOCError> {
    let (c_r, ead_2) = decode_plaintext_2_psk(plaintext_2)?;

    Ok(DecodedMessage2 {
        method_specifics: ProcessingM2MethodSpecifics::Psk {},
        c_r,
        parsed_details: ParsedMessage2Details::Psk {},
        ead_2,
    })
}

pub(crate) fn i_verify_message_2_psk(
    state: &ProcessingM2,
    crypto: &mut impl CryptoTrait,
    valid_cred_r: Credential,
) -> Result<VerifiedMessage2, EDHOCError> {
    let prk_3e2m = state.prk_2e;

    let th_3 = compute_th_3(crypto, &state.th_2, &state.plaintext_2, None);
    // message 3 processing
    let salt_4e3m = compute_salt_4e3m(crypto, &prk_3e2m, &th_3);

    let psk = match valid_cred_r.key {
        CredentialKey::Symmetric(psk) => psk,
        // FIXME: find a good definition of error
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let prk_4e3m = compute_prk_4e3m_psk(crypto, &salt_4e3m, &psk);

    Ok(VerifiedMessage2 {
        method_specifics: ProcessedM2MethodSpecifics::Psk {
            cred_r: valid_cred_r,
        },
        prk_3e2m,
        prk_4e3m,
        th_3,
    })
}

pub(crate) fn i_prepare_message_3_psk(
    state: &ProcessedM2,
    crypto: &mut impl CryptoTrait,
    cred_i: Credential,
    cred_transfer: CredentialTransfer,
    ead_3: &EadItems,
) -> Result<PreparedMessage3, EDHOCError> {
    let id_cred_psk = match cred_transfer {
        CredentialTransfer::ByValue => cred_i.by_value()?,
        CredentialTransfer::ByReference => cred_i.by_kid()?,
    };

    let cred_r = match &state.method_specifics {
        ProcessedM2MethodSpecifics::Psk { cred_r } => cred_r,
        // FIXME: find a good definition of error
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let mut message_3: BufferMessage3 = BufferMessage3::new();

    let plaintext_3 = encode_plaintext_3(None, &ead_3)?;
    let ciphertext_3b = encrypt_message_3(
        crypto,
        &state.prk_3e2m,
        &state.th_3,
        &plaintext_3,
        Some((
            id_cred_psk.as_encoded_value(),
            cred_i.bytes.as_slice(),
            cred_r.bytes.as_slice(),
        )),
    )?;
    // compute ciphertext_3a
    let pt_3a = id_cred_psk.as_encoded_value();
    let mut ct_3a: BufferCiphertext3 = BufferCiphertext3::new();
    ct_3a
        .extend_from_slice(pt_3a)
        .map_err(|_| EDHOCError::EncodingError)?;
    ct_3a
        .extend_from_slice(ciphertext_3b.as_slice())
        .map_err(|_| EDHOCError::EncodingError)?;
    let ciphertext_3a = encrypt_decrypt_ciphertext_3a(crypto, &state.prk_3e2m, &state.th_3, &ct_3a);
    // CBOR encoding of ct_3a
    let encoded_ciphertext_3a = encode_ciphertext_3a(ciphertext_3a)?;
    //compute message_3
    message_3
        .extend_from_slice(encoded_ciphertext_3a.as_slice())
        .map_err(|_| EDHOCError::EncodingError)?;
    let th_4 = compute_th_4(
        crypto,
        &state.th_3,
        cred_i.bytes.as_slice(),
        Th4Input::Psk {
            id_cred: id_cred_psk.as_encoded_value(),
            cred_r: cred_r.bytes.as_slice(),
            ead_3: ead_3,
        },
    );
    Ok(PreparedMessage3 { message_3, th_4 })
}

fn recover_cred_i_from_id_cred_psk(id_cred_psk: &IdCred) -> Result<Credential, EDHOCError> {
    if let Some(cred_i) = id_cred_psk.get_ccs() {
        Ok(cred_i)
    } else {
        Err(EDHOCError::MissingIdentity)
    }
}

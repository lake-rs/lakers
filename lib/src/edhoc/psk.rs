// use defmt_or_log::trace;
use super::*;
use lakers_shared::Crypto as CryptoTrait;

pub fn r_prepare_message_2_psk(
    state: &ProcessingM1,
    crypto: &mut impl CryptoTrait,
    cred_r: Credential,
    c_r: ConnId,
    ead_2: &EadItems,
) -> Result<(WaitM3, BufferMessage2), EDHOCError> {
    // compute TH_2
    let th_2 = compute_th_2(crypto, &state.g_y, &state.h_message_1);

    // compute prk_3e2m
    let prk_2e = compute_prk_2e(crypto, &state.y, &state.g_x, &th_2);
    // let salt_3e2m = compute_salt_3e2m(crypto, &prk_2e, &th_2);
    let prk_3e2m = prk_2e;

    // compute ciphertext_2
    let plaintext_2 = encode_plaintext_2(c_r, None, &ead_2)?;

    // step is actually from processing of message_3
    // but we do it here to avoid storing plaintext_2 in State
    let th_3 = compute_th_3(crypto, &th_2, &plaintext_2, None);

    let mut ct: BufferCiphertext2 = BufferCiphertext2::new();
    ct.fill_with_slice(plaintext_2.as_slice()).unwrap(); // TODO(hax): can we prove with hax that this won't panic since they use the same underlying buffer length?

    let ciphertext_2 = encrypt_decrypt_ciphertext_2(crypto, &prk_2e, &th_2, &ct);

    ct.fill_with_slice(ciphertext_2.as_slice()).unwrap(); // TODO(hax): same as just above.

    let message_2 = encode_message_2(&state.g_y, &ct);

    Ok((
        WaitM3 {
            method_specifics: WaitM3MethodSpecifics::Psk { cred_r },
            y: state.y,
            prk_3e2m: prk_3e2m,
            th_3: th_3,
        },
        message_2,
    ))
}

pub fn r_parse_message_3_psk(
    state: &WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
    cred_r: &Credential,
) -> Result<(ProcessingM3, IdCred, EadItems), EDHOCError> {
    r_parse_message_3_psk_with_cred_resolver(
        state,
        crypto,
        message_3,
        cred_r,
        recover_cred_i_from_id_cred_psk,
    )
}

pub fn r_parse_message_3_psk_with_cred_resolver<F>(
    state: &WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
    cred_r: &Credential,
    resolve_cred_i: F,
) -> Result<(ProcessingM3, IdCred, EadItems), EDHOCError>
where
    F: Fn(&IdCred) -> Result<Credential, EDHOCError>,
{
    let res = parse_message_3(message_3)?;
    let plaintext_3a = encrypt_decrypt_ciphertext_3a(crypto, &state.prk_3e2m, &state.th_3, &res);
    let id_cred_psk = IdCred::from_encoded_value(&[plaintext_3a.as_slice()[0]])?;

    let cred_i = resolve_cred_i(&id_cred_psk)?;

    let mut ciphertext_3b = BufferCiphertext3::new();
    let _ = ciphertext_3b.fill_with_slice(&plaintext_3a.as_slice()[1..]);

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
        Ok((
            ProcessingM3 {
                method_specifics: ProcessingM3MethodSpecifics::Psk {
                    id_cred_psk: id_cred_psk.clone(),
                    cred_r: cred_r.clone(),
                },
                y: state.y,
                prk_3e2m: state.prk_3e2m,
                th_3: state.th_3,
                plaintext_3: plaintext_3b, // NOTE: this is needed for th_4, which needs valid_cred_i, which is only available at the 'verify' step
                ead_3: ead_3.clone(), // NOTE: this clone could be avoided by using a reference or an index to the ead_3 item in plaintext_3
            },
            id_cred_psk,
            ead_3,
        ))
    } else {
        Err(decoded_p3_res.unwrap_err())
    }
}

pub fn r_verify_message_3_psk(
    state: &ProcessingM3,
    crypto: &mut impl CryptoTrait,
    valid_cred_i: Credential,
    id_cred_psk: &IdCred,
    cred_r: &Credential,
) -> Result<(ProcessedM3, BytesHashLen), EDHOCError> {
    // compute salt_4e3m
    let salt_4e3m = compute_salt_4e3m(crypto, &state.prk_3e2m, &state.th_3);

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
    // compute prk_out
    // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
    let mut prk_out: BytesHashLen = Default::default();
    edhoc_kdf(crypto, &prk_4e3m, 7u8, &th_4, &mut prk_out);

    // compute prk_exporter from prk_out
    // PRK_exporter  = EDHOC-KDF( PRK_out, 10, h'', hash_length )
    let mut prk_exporter = BytesHashLen::default();
    edhoc_kdf(crypto, &prk_out, 10u8, &[], &mut prk_exporter);

    Ok((
        ProcessedM3 {
            prk_4e3m: prk_4e3m,
            th_4: th_4,
            prk_out: prk_out,
            prk_exporter: prk_exporter,
        },
        prk_out,
    ))
}

pub fn i_parse_message_2_psk<'a>(
    state: &WaitM2,
    crypto: &mut impl CryptoTrait,
    message_2: &BufferMessage2,
) -> Result<(ProcessingM2, ConnId, ParsedMessage2Details, EadItems), EDHOCError> {
    let res = parse_message_2(message_2);
    if let Ok((g_y, ciphertext_2)) = res {
        let th_2 = compute_th_2(crypto, &g_y, &state.h_message_1);

        // compute prk_2e
        let prk_2e = compute_prk_2e(crypto, &state.x, &g_y, &th_2);

        let plaintext_2 = encrypt_decrypt_ciphertext_2(crypto, &prk_2e, &th_2, &ciphertext_2);

        // decode plaintext_2
        let plaintext_2_decoded = decode_plaintext_2_psk(&plaintext_2);

        if let Ok((c_r_2, ead_2)) = plaintext_2_decoded {
            let state = ProcessingM2 {
                method_specifics: ProcessingM2MethodSpecifics::Psk {},
                prk_2e,
                th_2,
                x: state.x,
                g_y,
                plaintext_2,
                c_r: c_r_2,
                ead_2: ead_2.clone(), // needed for compute_mac_2
            };

            Ok((state, c_r_2, ParsedMessage2Details::Psk {}, ead_2))
        } else {
            Err(EDHOCError::ParsingError)
        }
    } else {
        Err(res.unwrap_err())
    }
}

pub fn i_verify_message_2_psk(
    state: &ProcessingM2,
    crypto: &mut impl CryptoTrait,
    valid_cred_r: Credential,
) -> Result<ProcessedM2, EDHOCError> {
    // verify mac_2
    let _salt_3e2m = compute_salt_3e2m(crypto, &state.prk_2e, &state.th_2);

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

    let state = ProcessedM2 {
        method_specifics: ProcessedM2MethodSpecifics::Psk {
            cred_r: valid_cred_r,
        },
        prk_3e2m: prk_3e2m,
        prk_4e3m: prk_4e3m,
        th_3: th_3,
    };

    Ok(state)
}

pub fn i_prepare_message_3_psk(
    state: &ProcessedM2,
    crypto: &mut impl CryptoTrait,
    cred_i: Credential,
    cred_transfer: CredentialTransfer,
    ead_3: &EadItems,
) -> Result<(WaitM4, BufferMessage3, BytesHashLen), EDHOCError> {
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
    );
    // compute ciphertext_3a
    let pt_3a = id_cred_psk.as_encoded_value();
    let mut ct_3a: BufferCiphertext3 = BufferCiphertext3::new();
    ct_3a.extend_from_slice(pt_3a).unwrap();
    ct_3a.extend_from_slice(ciphertext_3b.as_slice()).unwrap();
    let ciphertext_3a = encrypt_decrypt_ciphertext_3a(crypto, &state.prk_3e2m, &state.th_3, &ct_3a);
    // CBOR encoding of ct_3a
    let encoded_ciphertext_3a = encode_ciphertext_3a(ciphertext_3a)?;
    //compute message_3
    message_3
        .extend_from_slice(encoded_ciphertext_3a.as_slice())
        .unwrap();
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
    // compute prk_out
    // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
    let mut prk_out: BytesHashLen = Default::default();
    edhoc_kdf(crypto, &state.prk_4e3m, 7u8, &th_4, &mut prk_out);

    // compute prk_exporter from prk_out
    // PRK_exporter  = EDHOC-KDF( PRK_out, 10, h'', hash_length )
    let mut prk_exporter: BytesHashLen = Default::default();
    edhoc_kdf(crypto, &prk_out, 10u8, &[], &mut prk_exporter);

    Ok((
        WaitM4 {
            prk_4e3m: state.prk_4e3m,
            th_4: th_4,
            prk_out: prk_out,
            prk_exporter: prk_exporter,
        },
        message_3,
        prk_out,
    ))
}

fn recover_cred_i_from_id_cred_psk(id_cred_psk: &IdCred) -> Result<Credential, EDHOCError> {
    if let Some(cred_i) = id_cred_psk.get_ccs() {
        Ok(cred_i)
    } else {
        Err(EDHOCError::MissingIdentity)
    }
}

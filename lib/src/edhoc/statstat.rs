use super::*;
use lakers_shared::Crypto as CryptoTrait;
pub fn r_prepare_message_2_statstat(
    state: &ProcessingM1,
    crypto: &mut impl CryptoTrait,
    cred_r: Credential,
    r: &BytesP256ElemLen, // R's static private DH key
    c_r: ConnId,
    cred_transfer: CredentialTransfer,
    ead_2: &EadItems,
) -> Result<(WaitM3, BufferMessage2), EDHOCError> {
    // compute TH_2
    let th_2 = compute_th_2(crypto, &state.g_y, &state.h_message_1);

    // compute prk_3e2m
    let prk_2e = compute_prk_2e(crypto, &state.y, &state.g_x, &th_2);
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
    let plaintext_2 = encode_plaintext_2(c_r, id_cred_r.as_encoded_value(), &mac_2, &ead_2)?;

    // step is actually from processing of message_3
    // but we do it here to avoid storing plaintext_2 in State
    let th_3 = compute_th_3(crypto, &th_2, &plaintext_2, cred_r.bytes.as_slice());

    let mut ct: BufferCiphertext2 = BufferCiphertext2::new();
    ct.fill_with_slice(plaintext_2.as_slice()).unwrap(); // TODO(hax): can we prove with hax that this won't panic since they use the same underlying buffer length?

    let ciphertext_2 = encrypt_decrypt_ciphertext_2(crypto, &prk_2e, &th_2, &ct);

    ct.fill_with_slice(ciphertext_2.as_slice()).unwrap(); // TODO(hax): same as just above.

    let message_2 = encode_message_2(&state.g_y, &ct);

    Ok((
        WaitM3 {
            method_specifics: WaitM3MethodSpecifics::StatStat {},
            y: state.y,
            prk_3e2m: prk_3e2m,
            th_3: th_3,
        },
        message_2,
    ))
}

pub fn r_parse_message_3_statstat(
    state: &mut WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
) -> Result<(ProcessingM3, IdCred, EadItems), EDHOCError> {
    let plaintext_3 = decrypt_message_3(crypto, &state.prk_3e2m, &state.th_3, message_3);

    if let Ok(plaintext_3) = plaintext_3 {
        let decoded_p3_res = decode_plaintext_3(&plaintext_3);

        if let Ok((id_cred_i, mac_3, ead_3)) = decoded_p3_res {
            Ok((
                ProcessingM3 {
                    method_specifics: ProcessingM3MethodSpecifics::StatStat {
                        mac_3,
                        id_cred_i: id_cred_i.clone(), // needed for compute_mac_3
                    },
                    y: state.y,
                    prk_3e2m: state.prk_3e2m,
                    th_3: state.th_3,
                    plaintext_3, // NOTE: this is needed for th_4, which needs valid_cred_i, which is only available at the 'verify' step
                    ead_3: ead_3.clone(), // NOTE: this clone could be avoided by using a reference or an index to the ead_3 item in plaintext_3
                },
                id_cred_i,
                ead_3,
            ))
        } else {
            Err(decoded_p3_res.unwrap_err())
        }
    } else {
        // error handling for err = decrypt_message_3(&prk_3e2m, &th_3, message_3);
        Err(plaintext_3.unwrap_err())
    }
}

pub fn r_verify_message_3_statstat(
    state: &ProcessingM3,
    crypto: &mut impl CryptoTrait,
    valid_cred_i: Credential,
) -> Result<(ProcessedM3, BytesHashLen), EDHOCError> {
    // compute salt_4e3m
    let salt_4e3m = compute_salt_4e3m(crypto, &state.prk_3e2m, &state.th_3);

    let prk_4e3m = match valid_cred_i.key {
        CredentialKey::EC2Compact(public_key) => {
            compute_prk_4e3m(crypto, &salt_4e3m, &state.y, &public_key)
        }
        CredentialKey::Symmetric(_psk) => todo!("PSK not implemented"),
    };

    let id_cred_i = match &state.method_specifics {
        ProcessingM3MethodSpecifics::StatStat { id_cred_i, .. } => id_cred_i,
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

    let mac_3 = match state.method_specifics {
        ProcessingM3MethodSpecifics::StatStat { mac_3, .. } => mac_3,
    };

    // verify mac_3
    if mac_3 == expected_mac_3 {
        let th_4 = compute_th_4(
            crypto,
            &state.th_3,
            &state.plaintext_3,
            valid_cred_i.bytes.as_slice(),
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
    } else {
        Err(EDHOCError::MacVerificationFailed)
    }
}

pub fn i_parse_message_2_statstat<'a>(
    state: &WaitM2,
    crypto: &mut impl CryptoTrait,
    message_2: &BufferMessage2,
) -> Result<(ProcessingM2, ConnId, IdCred, EadItems), EDHOCError> {
    let res = parse_message_2(message_2);
    if let Ok((g_y, ciphertext_2)) = res {
        let th_2 = compute_th_2(crypto, &g_y, &state.h_message_1);

        // compute prk_2e
        let prk_2e = compute_prk_2e(crypto, &state.x, &g_y, &th_2);

        let plaintext_2 = encrypt_decrypt_ciphertext_2(crypto, &prk_2e, &th_2, &ciphertext_2);

        // decode plaintext_2
        let plaintext_2_decoded = decode_plaintext_2(&plaintext_2);

        if let Ok((c_r_2, id_cred_r, mac_2, ead_2)) = plaintext_2_decoded {
            let state = ProcessingM2 {
                method_specifics: ProcessingM2MethodSpecifics::StatStat {
                    mac_2,
                    id_cred_r: id_cred_r.clone(), // needed for compute_mac_2
                },
                prk_2e,
                th_2,
                x: state.x,
                g_y,
                plaintext_2: plaintext_2,
                c_r: c_r_2,
                ead_2: ead_2.clone(), // needed for compute_mac_2
            };

            Ok((state, c_r_2, id_cred_r, ead_2))
        } else {
            Err(EDHOCError::ParsingError)
        }
    } else {
        Err(res.unwrap_err())
    }
}

pub fn i_verify_message_2_statstat(
    state: &ProcessingM2,
    crypto: &mut impl CryptoTrait,
    valid_cred_r: Credential,
    i: &BytesP256ElemLen, // I's static private DH key
) -> Result<ProcessedM2, EDHOCError> {
    // verify mac_2
    let salt_3e2m = compute_salt_3e2m(crypto, &state.prk_2e, &state.th_2);

    let prk_3e2m = match valid_cred_r.key {
        CredentialKey::EC2Compact(public_key) => {
            compute_prk_3e2m(crypto, &salt_3e2m, &state.x, &public_key)
        }
        CredentialKey::Symmetric(_psk) => todo!("PSK not implemented"),
    };

    let id_cred_r = match &state.method_specifics {
        ProcessingM2MethodSpecifics::StatStat { id_cred_r, .. } => id_cred_r,
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

    let mac_2 = match state.method_specifics {
        ProcessingM2MethodSpecifics::StatStat { mac_2, .. } => mac_2,
    };

    if mac_2 == expected_mac_2 {
        // step is actually from processing of message_3
        // but we do it here to avoid storing plaintext_2 in State
        let th_3 = compute_th_3(
            crypto,
            &state.th_2,
            &state.plaintext_2,
            valid_cred_r.bytes.as_slice(),
        );
        // message 3 processing

        let salt_4e3m = compute_salt_4e3m(crypto, &prk_3e2m, &th_3);

        let prk_4e3m = compute_prk_4e3m(crypto, &salt_4e3m, i, &state.g_y);

        let state = ProcessedM2 {
            // We need the method for next step. Since we are in the branch of StatStat,
            // we can add EDHOCMethod::StatStat
            method: EDHOCMethod::StatStat,
            prk_3e2m: prk_3e2m,
            prk_4e3m: prk_4e3m,
            th_3: th_3,
        };

        Ok(state)
    } else {
        Err(EDHOCError::MacVerificationFailed)
    }
}

pub fn i_prepare_message_3_statstat(
    state: &ProcessedM2,
    crypto: &mut impl CryptoTrait,
    cred_i: Credential,
    cred_transfer: CredentialTransfer,
    ead_3: &EadItems,
) -> Result<(WaitM4, BufferMessage3, BytesHashLen), EDHOCError> {
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

    let plaintext_3 = encode_plaintext_3(id_cred_i.as_encoded_value(), &mac_3, &ead_3)?;
    let message_3 = encrypt_message_3(crypto, &state.prk_3e2m, &state.th_3, &plaintext_3);

    let th_4 = compute_th_4(crypto, &state.th_3, &plaintext_3, cred_i.bytes.as_slice());

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

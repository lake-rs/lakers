use core::clone::Clone;
use digest::Digest;
use lakers_shared::{Crypto as CryptoTrait, *};

pub fn edhoc_exporter(
    state: &Completed,
    crypto: &mut impl CryptoTrait,
    label: u8,
    context: &[u8],
    result: &mut [u8],
) {
    edhoc_kdf(crypto, &state.prk_exporter, label, context, result);
}

pub fn edhoc_key_update(
    state: &mut Completed,
    crypto: &mut impl CryptoTrait,
    context: &[u8],
) -> BytesHashLen {
    // new PRK_out
    state.prk_out = edhoc_kdf_owned(crypto, &state.prk_out, 11u8, context);

    // new PRK_exporter
    state.prk_exporter = edhoc_kdf_owned(crypto, &state.prk_out, 10u8, &[]);

    state.prk_out
}

pub fn r_process_message_1(
    state: &ResponderStart,
    crypto: &mut impl CryptoTrait,
    message_1: &BufferMessage1,
) -> Result<(ProcessingM1, ConnId, EadItems), EDHOCError> {
    // Step 1: decode message_1
    // g_x will be saved to the state
    if let Ok((method, suites_i, g_x, c_i, ead_1)) = parse_message_1(message_1) {
        // Define credential.
        // FIXME: add an error if it does not match
        // verify that the method is supported
        match EDHOCMethod::try_from(method) {
            Ok(_supported_method) => {
                // Step 2: verify that the selected cipher suite is supported
                if suites_i[suites_i.len() - 1] == EDHOC_SUPPORTED_SUITES[0] {
                    let h_message_1 = crypto.sha256_digest(message_1.as_slice());
                    let method =
                        EDHOCMethod::try_from(method).map_err(|_| EDHOCError::UnsupportedMethod)?;
                    Ok((
                        ProcessingM1 {
                            method,
                            y: state.y,
                            g_y: state.g_y,
                            c_i,
                            g_x,
                            h_message_1,
                        },
                        c_i,
                        ead_1,
                    ))
                } else {
                    Err(EDHOCError::UnsupportedCipherSuite)
                }
            }
            Err(_) => Err(EDHOCError::UnsupportedMethod),
        }
    } else {
        Err(EDHOCError::ParsingError)
    }
}

pub fn r_prepare_message_2(
    state: &ProcessingM1,
    crypto: &mut impl CryptoTrait,
    cred_r: Credential,
    r: Option<&BytesP256ElemLen>, // R's static private DH key
    c_r: ConnId,
    cred_transfer: CredentialTransfer,
    ead_2: &EadItems,
) -> Result<(WaitM3, BufferMessage2), EDHOCError> {
    // compute TH_2
    let th_2 = compute_th_2(crypto, &state.g_y, &state.h_message_1);

    // compute prk_3e2m
    let prk_2e = compute_prk_2e(crypto, &state.y, &state.g_x, &th_2);

    let salt_3e2m = compute_salt_3e2m(crypto, &prk_2e, &th_2);

    let prk_3e2m = match cred_r.key {
        CredentialKey::EC2Compact(_public_key) => {
            compute_prk_3e2m(crypto, &salt_3e2m, r.unwrap(), &state.g_x)
        }
        CredentialKey::Symmetric(_psk) if state.method == EDHOCMethod::PSK.into() => prk_2e,
        _ => Err(EDHOCError::UnsupportedMethod)?,
    };

    let id_cred_r = match cred_transfer {
        CredentialTransfer::ByValue => cred_r.by_value()?,
        CredentialTransfer::ByReference => cred_r.by_kid()?,
    };

    let mac_2 = match state.method {
        EDHOCMethod::StatStat => Some(compute_mac_2(
            crypto,
            &prk_3e2m,
            c_r,
            id_cred_r.as_full_value(),
            cred_r.bytes.as_slice(),
            &th_2,
            ead_2,
        )),
        EDHOCMethod::PSK => None,
    };
    // compute ciphertext_2
    let plaintext_2 = match state.method {
        EDHOCMethod::StatStat => encode_plaintext_2(
            c_r,
            Some(id_cred_r.as_encoded_value()),
            mac_2.as_ref(),
            &ead_2,
        ),
        EDHOCMethod::PSK => encode_plaintext_2(c_r, None, None, &ead_2),
    }?;

    // step is actually from processing of message_3
    // but we do it here to avoid storing plaintext_2 in State
    let th_3 = compute_th_3(
        crypto,
        &th_2,
        &plaintext_2,
        if state.method == EDHOCMethod::PSK {
            None
        } else {
            Some(cred_r.bytes.as_slice())
        },
    );
    let mut ct: BufferCiphertext2 = BufferCiphertext2::new();
    ct.fill_with_slice(plaintext_2.as_slice()).unwrap(); // TODO(hax): can we prove with hax that this won't panic since they use the same underlying buffer length?

    let ciphertext_2 = encrypt_decrypt_ciphertext_2(crypto, &prk_2e, &th_2, &ct);

    ct.fill_with_slice(ciphertext_2.as_slice()).unwrap(); // TODO(hax): same as just above.

    let message_2 = encode_message_2(&state.g_y, &ct);

    Ok((
        WaitM3 {
            method: state.method,
            y: state.y,
            prk_3e2m: prk_3e2m,
            th_3: th_3,
        },
        message_2,
    ))
}

pub fn r_parse_message_3(
    state: &mut WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
    // FIXME: cred_i should be recovered from id_Cred_psk, but so should cred_r...
    cred_i: Option<Credential>,
    cred_r: Option<Credential>,
) -> Result<(ProcessingM3, Option<IdCred>, EadItems), EDHOCError> {
    match state.method {
        EDHOCMethod::PSK => {
            let res = parse_message_3(message_3)?;
            let plaintext_3a =
                encrypt_decrypt_ciphertext_3a(crypto, &state.prk_3e2m, &state.th_3, &res);
            let id_cred_psk = IdCred::from_encoded_value(&[plaintext_3a.as_slice()[0]])?;

            let mut ciphertext_3b = BufferCiphertext3::new();
            let _ = ciphertext_3b.fill_with_slice(&plaintext_3a.as_slice()[1..]); // changed 1 to 4

            // compute salt_4e3m
            let salt_4e3m = compute_salt_4e3m(crypto, &state.prk_3e2m, &state.th_3);

            let prk_4e3m = match cred_r.clone().unwrap().key {
                CredentialKey::Symmetric(psk) => compute_prk_4e3m_psk(crypto, &salt_4e3m, &psk),
                _ => panic!("Unusported key method"),
            };

            let plaintext_3b = decrypt_message_3(
                crypto,
                &prk_4e3m,
                &state.th_3,
                &ciphertext_3b,
                Some(id_cred_psk.as_encoded_value()),
                Some(cred_i.unwrap().bytes.as_slice()),
                Some(cred_r.unwrap().bytes.as_slice()),
            )?;

            let mut decoded_p3_res = decode_plaintext_3(state.method, &plaintext_3b);
            // FIXME: if PSK, we copy the id_cred_psk in the id_cred_i field, needed for verification
            let id_cred_i = Some(id_cred_psk);

            decoded_p3_res = decoded_p3_res.map(|(_, mac_3, ead_3)| (id_cred_i, mac_3, ead_3));

            let (id_cred_i, mac_3, ead_3) = decoded_p3_res?;

            Ok((
                ProcessingM3 {
                    method: state.method,
                    mac_3,
                    y: state.y,
                    prk_3e2m: state.prk_3e2m,
                    th_3: state.th_3,
                    id_cred_i: id_cred_i.clone(), // needed for compute_mac_3
                    plaintext_3: plaintext_3b, // NOTE: this is needed for th_4, which needs valid_cred_i, which is only available at the 'verify' step
                    ead_3: ead_3.clone(), // NOTE: this clone could be avoided by using a reference or an index to the ead_3 item in plaintext_3
                },
                id_cred_i,
                ead_3,
            ))
        }
        EDHOCMethod::StatStat => {
            let plaintext_3 = decrypt_message_3(
                crypto,
                &state.prk_3e2m,
                &state.th_3,
                message_3,
                None,
                None,
                None,
            );

            if let Ok(plaintext_3) = plaintext_3 {
                let decoded_p3_res = decode_plaintext_3(state.method, &plaintext_3);

                if let Ok((id_cred_i, mac_3, ead_3)) = decoded_p3_res {
                    Ok((
                        ProcessingM3 {
                            method: state.method,
                            mac_3,
                            y: state.y,
                            prk_3e2m: state.prk_3e2m,
                            th_3: state.th_3,
                            id_cred_i: id_cred_i.clone(), // needed for compute_mac_3
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
    }
}

pub fn r_verify_message_3(
    state: &mut ProcessingM3,
    crypto: &mut impl CryptoTrait,
    valid_cred_i: Credential,
    cred_r: Option<Credential>,
) -> Result<(ProcessedM3, BytesHashLen), EDHOCError> {
    // compute salt_4e3m
    let salt_4e3m = compute_salt_4e3m(crypto, &state.prk_3e2m, &state.th_3);

    let prk_4e3m = match (&valid_cred_i.key, state.method) {
        (CredentialKey::EC2Compact(public_key), EDHOCMethod::StatStat) => {
            compute_prk_4e3m(crypto, &salt_4e3m, &state.y, public_key)
        }
        (CredentialKey::Symmetric(psk), EDHOCMethod::PSK) => {
            compute_prk_4e3m_psk(crypto, &salt_4e3m, &psk)
        }
        _ => Err(EDHOCError::UnsupportedMethod)?,
    };

    // compute mac_3
    let expected_mac_3 = match state.method {
        EDHOCMethod::StatStat => Some(compute_mac_3(
            crypto,
            &prk_4e3m,
            &state.th_3,
            state.id_cred_i.clone().unwrap().as_full_value(),
            valid_cred_i.bytes.as_slice(),
            &state.ead_3,
        )),
        EDHOCMethod::PSK => None,
    };

    // verify mac_3
    let cred_r_bytes = cred_r.as_ref().map(|c| c.bytes.as_slice());
    if state.mac_3 == expected_mac_3 {
        let th_4 = compute_th_4(
            crypto,
            &state.th_3,
            &state.plaintext_3,
            state.method,
            Some(state.id_cred_i.clone().unwrap().as_encoded_value()),
            Some(&state.ead_3),
            &valid_cred_i.bytes.as_slice(),
            cred_r_bytes,
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
                prk_4e3m,
                th_4,
                prk_out,
                prk_exporter,
            },
            prk_out,
        ))
    } else {
        Err(EDHOCError::MacVerificationFailed)
    }
}

pub fn r_prepare_message_4(
    state: &ProcessedM3,
    crypto: &mut impl CryptoTrait,
    ead_4: &EadItems, // FIXME: make it a list of EADItem
) -> Result<(Completed, BufferMessage4), EDHOCError> {
    // compute ciphertext_4
    let plaintext_4 = encode_plaintext_4(&ead_4)?;
    let message_4 = encrypt_message_4(crypto, &state.prk_4e3m, &state.th_4, &plaintext_4);

    Ok((
        Completed {
            prk_out: state.prk_out,
            prk_exporter: state.prk_exporter,
        },
        message_4,
    ))
}

pub fn r_complete_without_message_4(
    state: &ProcessedM3,
) -> Result<(Completed, [u8; SHA256_DIGEST_LEN]), EDHOCError> {
    Ok((
        Completed {
            prk_out: state.prk_out,
            prk_exporter: state.prk_exporter,
        },
        state.prk_out,
    ))
}

pub fn i_prepare_message_1(
    state: &InitiatorStart,
    crypto: &mut impl CryptoTrait,
    c_i: ConnId,
    ead_1: &EadItems,
) -> Result<(WaitM2, BufferMessage1), EDHOCError> {
    // Encode message_1 as a sequence of CBOR encoded data items as specified in Section 5.2.1
    let message_1 = encode_message_1(state.method, &state.suites_i, &state.g_x, c_i, &ead_1)?;

    // hash message_1 here to avoid saving the whole message in the state
    let h_message_1 = crypto.sha256_digest(message_1.as_slice());

    Ok((
        WaitM2 {
            x: state.x,
            method: state.method.into(),
            h_message_1,
            cred_i: state.cred_i.clone(), // Added for PSK
        },
        message_1,
    ))
}

// returns c_r
pub fn i_parse_message_2<'a>(
    state: &WaitM2,
    crypto: &mut impl CryptoTrait,
    message_2: &BufferMessage2,
    // cred_transfer: CredentialTransfer,
) -> Result<(ProcessingM2, ConnId, Option<IdCred>, EadItems), EDHOCError> {
    let res = parse_message_2(message_2);
    //println!("message_2 parsed by I: {:?}", res);
    if let Ok((g_y, ciphertext_2)) = res {
        let th_2 = compute_th_2(crypto, &g_y, &state.h_message_1);
        // compute prk_2e
        let prk_2e = compute_prk_2e(crypto, &state.x, &g_y, &th_2);

        let plaintext_2 = encrypt_decrypt_ciphertext_2(crypto, &prk_2e, &th_2, &ciphertext_2);
        // decode plaintext_2
        let plaintext_2_decoded = decode_plaintext_2(state.method, &plaintext_2);

        if let Ok((c_r_2, id_cred_r, mac_2, ead_2)) = plaintext_2_decoded {
            let state = ProcessingM2 {
                method: state.method,
                mac_2,
                prk_2e,
                th_2,
                x: state.x,
                g_y,
                plaintext_2,
                c_r: c_r_2,
                id_cred_r: id_cred_r.clone(), // needed for compute_mac_2. In psk this is id_cred_psk
                ead_2: ead_2.clone(),         // needed for compute_mac_2
            };
            Ok((state, c_r_2, id_cred_r, ead_2))
        } else {
            Err(EDHOCError::ParsingError)
        }
    } else {
        Err(res.unwrap_err())
    }
}

pub fn i_verify_message_2(
    state: &ProcessingM2,
    crypto: &mut impl CryptoTrait,
    valid_cred_r: Credential,
    i: Option<&BytesP256ElemLen>, // I's static private DH key
) -> Result<ProcessedM2, EDHOCError> {
    // verify mac_2
    let salt_3e2m = compute_salt_3e2m(crypto, &state.prk_2e, &state.th_2);

    let prk_3e2m = match valid_cred_r.key {
        CredentialKey::EC2Compact(public_key) => {
            compute_prk_3e2m(crypto, &salt_3e2m, &state.x, &public_key)
        }
        CredentialKey::Symmetric(_psk) if state.method == EDHOCMethod::PSK.into() => state.prk_2e,
        _ => Err(EDHOCError::UnsupportedMethod)?,
    };

    let expected_mac_2 = match state.method {
        m if m == EDHOCMethod::StatStat.into() => Some(compute_mac_2(
            crypto,
            &prk_3e2m,
            state.c_r,
            state.id_cred_r.clone().unwrap().as_full_value(),
            valid_cred_r.bytes.as_slice(),
            &state.th_2,
            &state.ead_2,
        )),
        m if m == EDHOCMethod::PSK.into() => None,
        _ => Err(EDHOCError::UnsupportedMethod)?,
    };

    if state.mac_2 == expected_mac_2 {
        // step is actually from processing of message_3
        // but we do it here to avoid storing plaintext_2 in State
        let th_3 = compute_th_3(
            crypto,
            &state.th_2,
            &state.plaintext_2,
            if state.method == EDHOCMethod::PSK.into() {
                None
            } else {
                Some(valid_cred_r.bytes.as_slice())
            },
        );
        // message 3 processing

        let salt_4e3m = compute_salt_4e3m(crypto, &prk_3e2m, &th_3);
        let prk_4e3m = match valid_cred_r.key {
            CredentialKey::EC2Compact(_public_key) => {
                compute_prk_4e3m(crypto, &salt_4e3m, i.unwrap(), &state.g_y)
            }
            CredentialKey::Symmetric(psk) if state.method == EDHOCMethod::PSK.into() => {
                compute_prk_4e3m_psk(crypto, &salt_4e3m, &psk)
            }
            _ => Err(EDHOCError::UnsupportedMethod)?,
        };

        let state = ProcessedM2 {
            method: state.method,
            prk_3e2m: prk_3e2m,
            prk_4e3m: prk_4e3m,
            th_3: th_3,
            cred_r: Some(valid_cred_r), // Added for PSK. Needed to encrypt message 3
        };

        Ok(state)
    } else {
        Err(EDHOCError::MacVerificationFailed)
    }
}

pub fn i_prepare_message_3(
    state: &ProcessedM2,
    crypto: &mut impl CryptoTrait,
    cred_i: Credential,
    cred_transfer: CredentialTransfer,
    ead_3: &EadItems, // FIXME: make it a list of EADItem
) -> Result<(WaitM4, BufferMessage3, BytesHashLen), EDHOCError> {
    let id_cred_i = match cred_transfer {
        CredentialTransfer::ByValue => cred_i.by_value()?,
        CredentialTransfer::ByReference => cred_i.by_kid()?,
    };

    let mac_3 = match state.method {
        m if m == EDHOCMethod::StatStat.into() => Some(compute_mac_3(
            crypto,
            &state.prk_4e3m,
            &state.th_3,
            id_cred_i.as_full_value(),
            cred_i.bytes.as_slice(),
            ead_3,
        )),
        m if m == EDHOCMethod::PSK.into() => None,
        _ => return Err(EDHOCError::UnsupportedMethod),
    };
    let mac_3_ref: Option<&[u8; 8]> = mac_3.as_ref().map(|m| m);

    // compute ciphertext_3
    let plaintext_3 = match state.method {
        m if m == EDHOCMethod::StatStat.into() => {
            encode_plaintext_3(Some(id_cred_i.as_encoded_value()), mac_3_ref, &ead_3)
        }
        m if m == EDHOCMethod::PSK.into() => encode_plaintext_3(None, None, &ead_3),
        _ => Err(EDHOCError::UnsupportedMethod),
    }?;

    let mut message_3: BufferMessage3 = BufferMessage3::new();
    if state.method == EDHOCMethod::PSK.into() {
        let ciphertext_3b = encrypt_message_3(
            crypto,
            &state.prk_4e3m,
            &state.th_3,
            &plaintext_3,
            Some(id_cred_i.as_encoded_value()),
            Some(cred_i.bytes.as_slice()),
            Some(state.cred_r.clone().unwrap().bytes.as_slice()),
        );
        // compute ciphertext_3a
        // id_cred_i is the id_cred_psk
        let pt_3a = id_cred_i.as_encoded_value();

        let mut ct_3a: BufferCiphertext3 = BufferCiphertext3::new();
        ct_3a.extend_from_slice(pt_3a).unwrap();
        ct_3a.extend_from_slice(ciphertext_3b.as_slice()).unwrap();
        let ciphertext_3a =
            encrypt_decrypt_ciphertext_3a(crypto, &state.prk_3e2m, &state.th_3, &ct_3a);
        // CBOR encoding of ct_3a
        let encoded_ciphertext_3a = encode_ciphertext_3a(ciphertext_3a)?;
        //compute message_3
        message_3
            .extend_from_slice(encoded_ciphertext_3a.as_slice())
            .unwrap();
    } else {
        let regular_message_3 = encrypt_message_3(
            crypto,
            &state.prk_3e2m,
            &state.th_3,
            &plaintext_3,
            None,
            None,
            None,
        );
        message_3
            .fill_with_slice(regular_message_3.as_slice())
            .unwrap();
    };
    let cred_r_bytes = state.cred_r.as_ref().map(|c| c.bytes.as_slice());
    let th_4 = compute_th_4(
        crypto,
        &state.th_3,
        &plaintext_3,
        state.method,
        Some(id_cred_i.clone().as_encoded_value()),
        Some(&ead_3),
        &cred_i.bytes.as_slice(),
        //Some(&state.cred_r.clone().unwrap().bytes.as_slice()),
        cred_r_bytes,
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
            ead_3: ead_3.clone(),
            prk_out: prk_out,
            prk_exporter: prk_exporter,
        },
        message_3,
        prk_out,
    ))
}

pub fn i_parse_message_4(
    state: &mut WaitM4,
    crypto: &mut impl CryptoTrait,
    message_4: &BufferMessage4,
) -> Result<(ProcessingM4, EadItems), EDHOCError> {
    let plaintext_4 = decrypt_message_4(crypto, &state.prk_4e3m, &state.th_4, &message_4)?;

    let decoded_p4_res = decode_plaintext_4(&plaintext_4);

    if let Ok(ead_4) = decoded_p4_res {
        Ok((
            ProcessingM4 {
                prk_4e3m: state.prk_4e3m,
                th_4: state.th_4,
                prk_out: state.prk_out,
                prk_exporter: state.prk_exporter,
            },
            ead_4,
        ))
    } else {
        Err(decoded_p4_res.unwrap_err())
    }
}

// FIXME
pub fn i_verify_message_4(
    state: &ProcessingM4,
    // crypto: &mut impl CryptoTrait,
) -> Result<Completed, EDHOCError> {
    // // compute prk_out
    // // PRK_out = EDHOC-KDF( PRK_4e3m, 7, TH_4, hash_length )
    // let mut th_4_buf: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    // th_4_buf[..state.th_4.len()].copy_from_slice(&state.th_4[..]);

    // let mut prk_out: BytesHashLen = Default::default();
    // edhoc_kdf(crypto, &state.prk_4e3m, 7u8, &th_4_buf, &mut prk_out);

    // // compute prk_exporter from prk_out
    // // PRK_exporter  = EDHOC-KDF( PRK_out, 10, h'', hash_length )
    // let mut prk_exporter: BytesHashLen = Default::default();
    // edhoc_kdf(crypto, &prk_out, 10u8, &[], &mut prk_exporter);

    let state = Completed {
        prk_exporter: state.prk_exporter,
        prk_out: state.prk_out,
    };

    Ok(state)
}

pub fn i_complete_without_message_4(state: &WaitM4) -> Result<Completed, EDHOCError> {
    Ok(Completed {
        prk_out: state.prk_out,
        prk_exporter: state.prk_exporter,
    })
}

// pub fn i_complete_without_message_4(state: &WaitM4) -> Result<(Completed,[u8; SHA256_DIGEST_LEN]), EDHOCError> {
//     Ok((Completed {
//         prk_out: state.prk_out,
//         prk_exporter: state.prk_exporter,
//     },
//     state.prk_out))
// }

fn encode_message_1(
    method: EDHOCMethod,
    suites: &EdhocBuffer<MAX_SUITES_LEN>,
    g_x: &BytesP256ElemLen,
    c_i: ConnId,
    ead_1: &EadItems,
) -> Result<BufferMessage1, EDHOCError> {
    let mut output = BufferMessage1::new();

    output.push(method.into()).unwrap(); // CBOR unsigned int less than 24 is encoded verbatim

    if suites.len() == 1 {
        // only one suite, will be encoded as a single integer
        if suites[0] <= CBOR_UINT_1BYTE {
            output.push(suites[0]).unwrap();
        } else {
            output.push(CBOR_UINT_1BYTE).unwrap();
            output.push(suites[0]).unwrap(); // assume it is smaller than 255, which all suites are
        }
    } else {
        // several suites, will be encoded as an array
        output
            .push(CBOR_MAJOR_ARRAY + (suites.len() as u8))
            .unwrap();
        for &suite in suites.as_slice().iter() {
            if suite <= CBOR_UINT_1BYTE {
                output.push(suite).unwrap();
            } else {
                output.push(CBOR_UINT_1BYTE).unwrap();
                output.push(suite).unwrap();
            }
        }
    };

    output.push(CBOR_BYTE_STRING).unwrap(); // CBOR byte string magic number
    output.push(P256_ELEM_LEN as u8).unwrap(); // length of the byte string
    output.extend_from_slice(&g_x[..]).unwrap();
    output.extend_from_slice(c_i.as_cbor()).unwrap();

    ead_1.encode(&mut output)?;

    Ok(output)
}

fn encode_message_2(g_y: &BytesP256ElemLen, ciphertext_2: &BufferCiphertext2) -> BufferMessage2 {
    let mut output: BufferMessage2 = BufferMessage2::new();

    output.push(CBOR_BYTE_STRING).unwrap();
    output
        .push(P256_ELEM_LEN as u8 + ciphertext_2.len() as u8)
        .unwrap();
    output.extend_from_slice(g_y).unwrap();
    output.extend_from_slice(ciphertext_2.as_slice()).unwrap();

    output
}

fn compute_th_2(
    crypto: &mut impl CryptoTrait,
    g_y: &BytesP256ElemLen,
    h_message_1: &BytesHashLen,
) -> BytesHashLen {
    // Whether this makes sense to build as a whole on the stack and then hash or feed into a
    // hasher is probably a stack-size-vs-flash-size trade-off, which has yet to be evaluated.
    let mut message = [0x00; 4 + P256_ELEM_LEN + SHA256_DIGEST_LEN];
    message[0] = CBOR_BYTE_STRING;
    message[1] = P256_ELEM_LEN as u8;
    message[2..2 + P256_ELEM_LEN].copy_from_slice(g_y);
    message[2 + P256_ELEM_LEN] = CBOR_BYTE_STRING;
    message[3 + P256_ELEM_LEN] = SHA256_DIGEST_LEN as u8;
    message[4 + P256_ELEM_LEN..4 + P256_ELEM_LEN + SHA256_DIGEST_LEN]
        .copy_from_slice(&h_message_1[..]);

    crypto.sha256_digest(message.as_slice())
}

fn compute_th_3(
    crypto: &mut impl CryptoTrait,
    th_2: &BytesHashLen,
    plaintext_2: &BufferPlaintext2,
    cred_r: Option<&[u8]>,
) -> BytesHashLen {
    let mut hash = crypto.sha256_start();

    hash.update([CBOR_BYTE_STRING, th_2.len() as u8]);
    hash.update(th_2);

    hash.update(plaintext_2.as_slice());
    if let Some(bytes) = cred_r {
        hash.update(bytes);
    }

    hash.finalize().into()
}

fn compute_th_4(
    crypto: &mut impl CryptoTrait,
    th_3: &BytesHashLen,
    plaintext_3: &BufferPlaintext3,
    method: EDHOCMethod,
    id_cred: Option<&[u8]>,
    ead_3: Option<&EadItems>,
    cred_i: &[u8],
    cred_r: Option<&[u8]>,
) -> BytesHashLen {
    let mut hash = crypto.sha256_start();

    hash.update([CBOR_BYTE_STRING, th_3.len() as u8]);
    hash.update(th_3);

    match method {
        EDHOCMethod::PSK => {
            // PSK order: TH_3 || ID_CRED_PSK || EAD_3 || CRED_I || CRED_R
            if let (Some(id), Some(ead), Some(cr)) = (id_cred, ead_3, cred_r) {
                let mut ead_buf = EdhocBuffer::<MAX_EAD_LEN>::new();
                ead.encode(&mut ead_buf).unwrap(); // or propagate error
                hash.update(id);
                hash.update(ead_buf.as_slice());
                hash.update(cred_i);
                hash.update(cr);
            } else {
                panic!("PSK selected but missing required fields");
            }
        }
        EDHOCMethod::StatStat => {
            // Non-PSK order: TH_3 || PLAINTEXT_3 || CRED_I
            hash.update(plaintext_3.as_slice());
            hash.update(cred_i);
        }
    }

    hash.finalize().into()
}

// TODO: consider moving this to a new 'edhoc crypto primitives' module
fn edhoc_kdf(
    crypto: &mut impl CryptoTrait,
    prk: &BytesHashLen,
    label: u8,
    context: &[u8],
    result: &mut [u8],
) {
    let info = encode_info(label, context, result.len());

    crypto.hkdf_expand(prk, info.as_slice(), result);
}

/// Variant of [`edhoc_kdf`] that returns a filled fixed-size buffer.
///
/// This is a dedicated function because there's a whole lot of users of [`edhoc_kdf`] that just
/// create a buffer, fill it and return it -- so this function does that.
#[inline]
fn edhoc_kdf_owned<const N: usize>(
    crypto: &mut impl CryptoTrait,
    prk: &BytesHashLen,
    label: u8,
    context: &[u8],
) -> [u8; N] {
    let mut result = [0; N];
    edhoc_kdf(crypto, prk, label, context, &mut result);
    result
}

fn encode_plaintext_3(
    id_cred_i: Option<&[u8]>,
    mac_3: Option<&BytesMac3>,
    ead_3: &EadItems,
) -> Result<BufferPlaintext3, EDHOCError> {
    let mut plaintext_3: BufferPlaintext3 = BufferPlaintext3::new();
    // plaintext: P = ( ? PAD, ID_CRED_I / bstr / int, Signature_or_MAC_3, ? EAD_3 )

    if let Some(id_cred) = id_cred_i {
        plaintext_3
            .extend_from_slice(id_cred)
            .or(Err(EDHOCError::EncodingError))?;
    };
    // let offset_cred = plaintext_3.len();
    if let Some(mac_3) = mac_3 {
        plaintext_3
            .push(CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_3 as u8)
            .or(Err(EDHOCError::EncodingError))?;
        let _ = plaintext_3.extend_from_slice(mac_3);
    }

    ead_3.encode(&mut plaintext_3)?;

    Ok(plaintext_3)
}

fn encode_plaintext_4(ead_4: &EadItems) -> Result<BufferPlaintext4, EDHOCError> {
    let mut plaintext_4: BufferPlaintext4 = BufferPlaintext4::new();

    ead_4.encode(&mut plaintext_4)?;

    Ok(plaintext_4)
}

fn encode_ciphertext_3a(ciphertext: EdhocMessageBuffer) -> Result<BufferCiphertext3, EDHOCError> {
    let mut ciphertext_3a: BufferCiphertext3 = BufferCiphertext3::new();
    // plaintext_3a: P = ( ID_CRED_PSK / bstr / int )
    ciphertext_3a
        .push(CBOR_MAJOR_BYTE_STRING | ciphertext.len() as u8)
        .or(Err(EDHOCError::EncodingError))?;
    let _ = ciphertext_3a.extend_from_slice(ciphertext.as_slice());

    Ok(ciphertext_3a)
}

pub fn encode_enc_structure(
    external_aad: &EdhocBuffer<MAX_BUFFER_LEN>,
) -> (EdhocBuffer<MAX_BUFFER_LEN>, usize) {
    let encrypt0 = b"Encrypt0";

    let mut enc_structure = EdhocBuffer::<MAX_BUFFER_LEN>::new();

    // CBOR array of 3 elements
    enc_structure.push(CBOR_MAJOR_ARRAY | 3).unwrap();

    // "Encrypt0" text string
    enc_structure
        .push(CBOR_MAJOR_TEXT_STRING | encrypt0.len() as u8)
        .unwrap();
    enc_structure.extend_from_slice(encrypt0).unwrap();

    // protected field: zero-length byte string
    enc_structure.push(CBOR_MAJOR_BYTE_STRING | 0).unwrap();

    // external_aad field
    enc_structure.push(CBOR_BYTE_STRING).unwrap();
    enc_structure.push(external_aad.len() as u8).unwrap();
    enc_structure
        .extend_from_slice(external_aad.as_slice())
        .unwrap();

    let len = enc_structure.len();
    (enc_structure, len)
}

pub fn build_external_aad(
    th_3: &[u8],
    id_cred: Option<&[u8]>,
    cred_i: Option<&[u8]>,
    cred_r: Option<&[u8]>,
) -> (EdhocBuffer<MAX_BUFFER_LEN>, usize) {
    let mut buf = EdhocBuffer::<MAX_BUFFER_LEN>::new();

    if let (Some(id), Some(ci), Some(cr)) = (id_cred, cred_i, cred_r) {
        // PSK case: array of 4 items
        buf.push(CBOR_MAJOR_ARRAY | 4).unwrap();
        for item in [id, th_3, ci, cr] {
            buf.push(CBOR_MAJOR_BYTE_STRING | (item.len() as u8))
                .unwrap();
            buf.extend_from_slice(item).unwrap();
        }
    } else {
        // Non-PSK: array of 1 item (TH_3)
        buf.extend_from_slice(th_3).unwrap();
    }

    let len = buf.len(); // actual used length
    (buf, len)
}

fn compute_k_3_iv_3(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
) -> (BytesCcmKeyLen, BytesCcmIvLen) {
    // K_3 = EDHOC-KDF( PRK_3e2m, 3, TH_3,      key_length )
    let k_3: BytesCcmKeyLen = edhoc_kdf_owned(crypto, prk_3e2m, 3u8, th_3);

    // IV_3 = EDHOC-KDF( PRK_3e2m, 4, TH_3,      iv_length )
    let iv_3: BytesCcmIvLen = edhoc_kdf_owned(crypto, prk_3e2m, 4u8, th_3);

    (k_3, iv_3)
}

fn compute_k_4_iv_4(
    crypto: &mut impl CryptoTrait,
    prk_4e3m: &BytesHashLen,
    th_4: &BytesHashLen,
) -> (BytesCcmKeyLen, BytesCcmIvLen) {
    // K_4 = EDHOC-KDF( PRK_4e3m, ?? , TH_4,      key_length )
    let k_4: BytesCcmKeyLen = edhoc_kdf_owned(
        crypto, prk_4e3m, 8u8, // FIXME
        th_4,
    );

    // IV_3 = EDHOC-KDF( PRK_4e3m, ?? , TH_4,      iv_length )
    let iv_4: BytesCcmIvLen = edhoc_kdf_owned(crypto, prk_4e3m, 9u8, th_4);

    (k_4, iv_4)
}

// calculates ciphertext_3 wrapped in a cbor byte string
fn encrypt_message_3(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    plaintext_3: &BufferPlaintext3,
    id_cred: Option<&[u8]>,
    cred_i: Option<&[u8]>,
    cred_r: Option<&[u8]>,
) -> BufferMessage3 {
    let mut output: BufferMessage3 = BufferMessage3::new();
    let bytestring_length = plaintext_3.len() + AES_CCM_TAG_LEN;
    // FIXME: Reuse CBOR encoder
    if bytestring_length < 24 {
        output
            .push(CBOR_MAJOR_BYTE_STRING | (bytestring_length) as u8)
            .unwrap();
    } else {
        // FIXME: Assumes we don't exceed 256 bytes which is the current buffer size
        output.push(CBOR_MAJOR_BYTE_STRING | 24).unwrap();
        output.push(bytestring_length as _).unwrap();
    };

    // FIXME: Make the function fallible, especially with the prospect of algorithm agility
    assert!(
        output.len() + bytestring_length <= MAX_MESSAGE_SIZE_LEN,
        "Tried to encode a message that is too large."
    );

    // let enc_structure = encode_enc_structure(th_3);
    let (external_aad, _aad_len) = build_external_aad(th_3, id_cred, cred_i, cred_r);
    let (enc_structure, enc_len) = encode_enc_structure(&external_aad);
    let (k_3, iv_3) = compute_k_3_iv_3(crypto, prk_3e2m, th_3);

    let ciphertext_3: BufferCiphertext3 = crypto.aes_ccm_encrypt_tag_8(
        &k_3,
        &iv_3,
        &enc_structure.as_slice()[..enc_len],
        plaintext_3.as_slice(),
    );

    output.extend_from_slice(ciphertext_3.as_slice()).unwrap();

    output
}

fn decrypt_message_3(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    message_3: &BufferMessage3,
    id_cred: Option<&[u8]>,
    cred_i: Option<&[u8]>,
    cred_r: Option<&[u8]>,
) -> Result<BufferPlaintext3, EDHOCError> {
    // decode message_3
    // FIXME: Reuse CBOR decoder
    let (bytestring_length, prefix_length) =
        if (0..=23).contains(&(message_3[0] ^ CBOR_MAJOR_BYTE_STRING)) {
            (
                // buffer_length =
                (message_3[0] ^ CBOR_MAJOR_BYTE_STRING).into(),
                // prefix_length =
                1,
            )
        } else {
            // FIXME: Assumes we don't exceed 256 bytes which is the current buffer size
            (
                // buffer_length =
                message_3[1].into(),
                // prefix_length =
                2,
            )
        };

    let ciphertext_3: BufferCiphertext3 = BufferCiphertext3::new_from_slice(
        &message_3.as_slice()[prefix_length..][..bytestring_length],
    )
    .unwrap();

    let (k_3, iv_3) = compute_k_3_iv_3(crypto, prk_3e2m, th_3);

    // let enc_structure = encode_enc_structure(th_3);
    let (external_aad, _aad_len) = build_external_aad(th_3, id_cred, cred_i, cred_r);
    let (enc_structure, enc_len) = encode_enc_structure(&external_aad);

    crypto.aes_ccm_decrypt_tag_8(
        &k_3,
        &iv_3,
        &enc_structure.as_slice()[..enc_len],
        ciphertext_3.as_slice(),
    )
}

fn encrypt_message_4(
    crypto: &mut impl CryptoTrait,
    prk_4e3m: &BytesHashLen,
    th_4: &BytesHashLen,
    plaintext_4: &BufferPlaintext4,
) -> BufferMessage4 {
    let mut output: BufferMessage4 = BufferMessage4::new();
    let bytestring_length = plaintext_4.len() + AES_CCM_TAG_LEN;
    // FIXME: Reuse CBOR encoder
    if bytestring_length < 24 {
        output
            .push(CBOR_MAJOR_BYTE_STRING | (bytestring_length) as u8)
            .unwrap();
    } else {
        // FIXME: Assumes we don't exceed 256 bytes which is the current buffer size
        output.push(CBOR_MAJOR_BYTE_STRING | 24).unwrap();
        output.push(bytestring_length as _).unwrap();
    };
    // FIXME: Make the function fallible, especially with the prospect of algorithm agility

    // let enc_structure = encode_enc_structure(th_4);
    let (external_aad, _aad_len) = build_external_aad(th_4, None, None, None);
    let (enc_structure, enc_len) = encode_enc_structure(&external_aad);

    let (k_4, iv_4) = compute_k_4_iv_4(crypto, prk_4e3m, th_4);

    let ciphertext_4: BufferCiphertext4 = crypto.aes_ccm_encrypt_tag_8(
        &k_4,
        &iv_4,
        &enc_structure.as_slice()[..enc_len],
        plaintext_4.as_slice(),
    );

    output.extend_from_slice(ciphertext_4.as_slice()).unwrap();

    output
}

fn decrypt_message_4(
    crypto: &mut impl CryptoTrait,
    prk_4e3m: &BytesHashLen,
    th_4: &BytesHashLen,
    message_4: &BufferMessage4,
) -> Result<BufferPlaintext4, EDHOCError> {
    // decode message_4
    // FIXME: Reuse CBOR decoder
    let (bytestring_length, prefix_length) =
        if (0..=23).contains(&(message_4[0] ^ CBOR_MAJOR_BYTE_STRING)) {
            (
                // buffer_length =
                (message_4[0] ^ CBOR_MAJOR_BYTE_STRING).into(),
                // prefix_length =
                1,
            )
        } else {
            // FIXME: Assumes we don't exceed 256 bytes which is the current buffer size
            (
                // buffer_length =
                message_4[1].into(),
                // prefix_length =
                2,
            )
        };

    let ciphertext_4 = BufferCiphertext4::new_from_slice(
        &message_4.as_slice()[prefix_length..][..bytestring_length],
    )
    .unwrap();

    let (k_4, iv_4) = compute_k_4_iv_4(crypto, prk_4e3m, th_4);

    let (external_aad, _aad_len) = build_external_aad(th_4, None, None, None);
    let (enc_structure, enc_len) = encode_enc_structure(&external_aad);
    // let enc_structure = encode_enc_structure(th_4);

    crypto.aes_ccm_decrypt_tag_8(
        &k_4,
        &iv_4,
        &enc_structure.as_slice()[..enc_len],
        ciphertext_4.as_slice(),
    )
}
// output must hold id_cred.len() + cred.len()
fn encode_kdf_context(
    c_r: Option<ConnId>, // only present for MAC_2
    id_cred: &[u8],
    th: &BytesHashLen,
    cred: &[u8],
    ead: &EadItems,
) -> BufferContext {
    // encode context in line
    // assumes ID_CRED_R and CRED_R are already CBOR-encoded (and also EAD)
    let mut output = BufferContext::new();

    if let Some(c_r) = c_r {
        output.extend_from_slice(c_r.as_cbor()).unwrap();
    }
    output.extend_from_slice(&id_cred).unwrap();
    output.push(CBOR_BYTE_STRING).unwrap();
    output.push(SHA256_DIGEST_LEN as u8).unwrap();
    output.extend_from_slice(th).unwrap();
    output.extend_from_slice(cred).unwrap();

    // NOTE: this re-encoding could be avoided by passing just a reference to ead in the decrypted plaintext
    ead.encode(&mut output).unwrap();

    output
}

fn compute_mac_3(
    crypto: &mut impl CryptoTrait,
    prk_4e3m: &BytesHashLen,
    th_3: &BytesHashLen,
    id_cred_i: &[u8],
    cred_i: &[u8],
    ead_3: &EadItems,
) -> BytesMac3 {
    // MAC_3 = EDHOC-KDF( PRK_4e3m, 6, context_3, mac_length_3 )
    let context = encode_kdf_context(None, id_cred_i, th_3, cred_i, ead_3);

    // compute mac_3
    edhoc_kdf_owned(
        crypto,
        prk_4e3m,
        6u8, // registered label for "MAC_3"
        context.as_slice(),
    )
}

fn compute_mac_2(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    c_r: ConnId,
    id_cred_r: &[u8],
    cred_r: &[u8],
    th_2: &BytesHashLen,
    ead_2: &EadItems,
) -> BytesMac2 {
    // compute MAC_2
    let context = encode_kdf_context(Some(c_r), id_cred_r, th_2, cred_r, ead_2);

    // MAC_2 = EDHOC-KDF( PRK_3e2m, 2, context_2, mac_length_2 )
    edhoc_kdf_owned(crypto, prk_3e2m, 2_u8, context.as_slice())
}

fn encode_plaintext_2(
    c_r: ConnId,
    id_cred_r: Option<&[u8]>,
    mac_2: Option<&BytesMac2>,
    ead_2: &EadItems,
) -> Result<BufferPlaintext2, EDHOCError> {
    let mut plaintext_2: BufferPlaintext2 = BufferPlaintext2::new();
    let c_r = c_r.as_cbor();

    plaintext_2
        .extend_from_slice(c_r)
        .or(Err(EDHOCError::EncodingError))?;
    // id_cred_r.write_to_message(&mut plaintext_2)?;
    if let Some(id_cred) = id_cred_r {
        plaintext_2
            .extend_from_slice(id_cred)
            .or(Err(EDHOCError::EncodingError))?;
    };
    // let offset_cred = plaintext_2.len();
    if let Some(mac_2) = mac_2 {
        plaintext_2
            .push(CBOR_MAJOR_BYTE_STRING | MAC_LENGTH_2 as u8)
            .unwrap();
        plaintext_2.extend_from_slice(&mac_2[..]).unwrap();
    };
    // Encode optional EAD_2
    ead_2.encode(&mut plaintext_2)?;

    Ok(plaintext_2)
}

/// Apply the XOR base encryption for ciphertext_2 in place. This will decrypt (or decrypt) the bytes
/// in the ciphertext_2 argument (which may alternatively contain plaintext), returning the cipher
/// (or plain-)text.
fn encrypt_decrypt_ciphertext_2(
    crypto: &mut impl CryptoTrait,
    prk_2e: &BytesHashLen,
    th_2: &BytesHashLen,
    ciphertext_2: &BufferCiphertext2,
) -> BufferCiphertext2 {
    // KEYSTREAM_2 = EDHOC-KDF( PRK_2e,   0, TH_2,      plaintext_length )
    let mut keystream_2 = BufferCiphertext2::new();
    let range = keystream_2.extend_reserve(ciphertext_2.len()).unwrap();
    // FIXME can we do this w/o having a full message on the stack?
    #[allow(deprecated, reason = "using extend_reserve")]
    edhoc_kdf(crypto, prk_2e, 0u8, th_2, &mut keystream_2.content[range]);

    let mut result = BufferCiphertext2::default();
    for i in 0..ciphertext_2.len() {
        result.push(ciphertext_2[i] ^ keystream_2[i]).unwrap();
    }

    result
}

fn encrypt_decrypt_ciphertext_3a(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    ciphertext_3a: &BufferCiphertext2,
) -> BufferCiphertext2 {
    // convert the transcript hash th_2 to BytesMaxContextBuffer type
    // let mut th_3_context: BytesMaxContextBuffer = [0x00; MAX_KDF_CONTEXT_LEN];
    // th_3_context[..th_3.len()].copy_from_slice(&th_3[..]);

    // KEYSTREAM_3 = EDHOC-KDF( PRK_2e,   0, TH_2,      plaintext_length )
    let mut keystream_3 = BufferCiphertext3::new();
    let range = keystream_3.extend_reserve(ciphertext_3a.len()).unwrap();
    #[allow(deprecated, reason = "using extend_reserve")]
    edhoc_kdf(
        crypto,
        prk_3e2m,
        12u8,
        th_3,
        &mut keystream_3.content[range],
    );

    let mut result = BufferCiphertext2::default();
    for i in 0..ciphertext_3a.len() {
        result.push(ciphertext_3a[i] ^ keystream_3[i]).unwrap();
    }

    result
}

fn compute_salt_4e3m(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
) -> BytesHashLen {
    edhoc_kdf_owned(crypto, prk_3e2m, 5u8, th_3)
}

fn compute_prk_4e3m_psk(
    crypto: &mut impl CryptoTrait,
    salt_4e3m: &BytesHashLen,
    cred: &BytesKeyAES128, //TODO: what is the psk type? len?
) -> BytesHashLen {
    crypto.hkdf_extract_psk(salt_4e3m, &cred)
}

fn compute_prk_4e3m(
    crypto: &mut impl CryptoTrait,
    salt_4e3m: &BytesHashLen,
    i: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
) -> BytesHashLen {
    // compute g_rx from static R's public key and private ephemeral key
    let g_iy = crypto.p256_ecdh(i, g_y);

    crypto.hkdf_extract(salt_4e3m, &g_iy)
}

fn compute_salt_3e2m(
    crypto: &mut impl CryptoTrait,
    prk_2e: &BytesHashLen,
    th_2: &BytesHashLen,
) -> BytesHashLen {
    edhoc_kdf_owned(crypto, prk_2e, 1u8, th_2)
}

fn compute_prk_3e2m(
    crypto: &mut impl CryptoTrait,
    salt_3e2m: &BytesHashLen,
    x: &BytesP256ElemLen,
    g_r: &BytesP256ElemLen,
) -> BytesHashLen {
    // compute g_rx from static R's public key and private ephemeral key
    let g_rx = crypto.p256_ecdh(x, g_r);

    crypto.hkdf_extract(salt_3e2m, &g_rx)
}

fn compute_prk_2e(
    crypto: &mut impl CryptoTrait,
    x: &BytesP256ElemLen,
    g_y: &BytesP256ElemLen,
    th_2: &BytesHashLen,
) -> BytesHashLen {
    // compute the shared secret
    let g_xy = crypto.p256_ecdh(x, g_y);
    // compute prk_2e as PRK_2e = HMAC-SHA-256( salt, G_XY )

    crypto.hkdf_extract(th_2, &g_xy)
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use hexlit::hex;
    use lakers_crypto::default_crypto;
    // test vectors (TV)

    // EDHOC-PSK
    const METHOD_PSK_TV: EDHOCMethod = EDHOCMethod::PSK; //0x04;
    const SUITES_I_PSK_TV: EdhocBuffer<MAX_SUITES_LEN> = EdhocBuffer::new_from_array(&hex!("02"));
    // === Initiator ephemeral private key X ===
    const X_PSK_TV: BytesP256ElemLen =
        hex!("09972dfef1eaab926ec96e8005fed29f70ffbf4e361c3a061a7acdb5170c10e5");
    // === Initiator ephemeral public key G_X ===
    const G_X_PSK_TV: BytesP256ElemLen =
        hex!("7ec68102940602aab548539bf42a35992d957249eb7f1888406d178a04c912db");
    // === Connection identifier C_I ===
    #[allow(deprecated)]
    const C_I_PSK_TV: ConnId = ConnId::from_int_raw(0x0A);
    // === Message 1 ===
    const MESSAGE_1_PSK_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!(
        "040258207ec68102940602aab548539bf42a35992d957249eb7f1888406d178a04c912db0a"
    ));
    // === Responder ephemeral private key Y ===
    const Y_PSK_TV: BytesP256ElemLen =
        hex!("1e1c8f2df1aa7110b39f33ba5ea8dccf31411eb33d4f9a094cf65192d335a7a3");
    // === Responder ephemeral public key G_Y ===
    const G_Y_PSK_TV: BytesP256ElemLen =
        hex!("ed156a6243e0afec9efb-aabce8429d5ad5e4e1c432f76a6ede8f79247bb97d83");
    // === Connection identifier C_R ===
    #[allow(deprecated)]
    const C_R_PSK_TV: ConnId = ConnId::from_int_raw(0x05);
    // === H(message_1) raw ===
    const H_MESSAGE_1_PSK_TV: BytesHashLen =
        hex!("19cc2d2a957edd80109042fde6cc20c24b6a34bc21c6d49fea895d4c7592340e");
    // === H(message_1) CBOR (for completeness) ===
    const H_MESSAGE_1_CBOR_PSK_TV: EdhocBuffer<34> = EdhocBuffer::new_from_array(&hex!(
        "582019cc2d2a957edd80109042fde6cc20c24b6a34bc21c6d49fea895d4c7592340e"
    ));
    // === TH_2 raw ===
    const TH_2_PSK_TV: BytesHashLen =
        hex!("5b4834ae630a8a0ed0b0c6f36642604d016478c4bc8187bb764dd40f2bee3dde");
    // === TH_2 CBOR ===
    const TH_2_CBOR_PSK_TV: EdhocBuffer<34> = EdhocBuffer::new_from_array(&hex!(
        "58205b4834ae630a8a0ed0b0c6f36642604d016478c4bc8187bb764dd40f2bee3dde"
    ));
    // === G_XY (ECDH shared secret) ===
    const G_XY_PSK_TV: BytesP256ElemLen =
        hex!("2f4a799a5ab0c567220cb67208e6cf8f4ca5fe385d1b11fd9a573d4160f3b0b2");
    // === PRK_2e ===
    const PRK_2E_PSK_TV: BytesP256ElemLen =
        hex!("d039d6c3cf35eca0cdf819e32579c77e1f303efcc43620509948a9fd47fbd929");
    // === PRK_3e2m ===
    const PRK_3E2M_PSK_TV: BytesP256ElemLen =
        hex!("d039d6c3cf35eca0cdf819e32579c77e1f303efcc43620509948a9fd47fbd929");
    const CIPHERTEXT_2_LEN_PSK_TV: usize = MESSAGE_2_PSK_TV.len() - P256_ELEM_LEN - 2;
    const PLAINTEXT_2_LEN_PSK_TV: usize = CIPHERTEXT_2_LEN_PSK_TV;
    // === KEYSTREAM_2A ===
    const KEYSTREAM_2_PSK_TV: [u8; PLAINTEXT_2_LEN_PSK_TV] = hex!("ec");
    // === PLAINTEXT_2A ===
    const PLAINTEXT_2_PSK_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!("05"));
    // === CIPHERTEXT_2B ===
    const CIPHERTEXT_2_PSK_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!("e9"));
    // === message_2 ===
    const MESSAGE_2_PSK_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!(
        "5821ed156a6243e0afec9efbaabce8429d5ad5e4e1c432f76a6ede8f79247bb97d83e9"
    ));
    // === SALT_4e3m ===
    const SALT_4E3M_PSK_TV: BytesHashLen =
        hex!("ede07612148319eb725952712a542c2097610a139c4a141c8ec57a5f62e5e9dd");
    // === PSK (16 bytes) ===
    const PSK_TV: [u8; 16] = hex!("50930ff462a77a3540cf546325dea214");
    // === PRK_4e3m ===
    const PRK_4E3M_PSK_TV: BytesP256ElemLen =
        hex!("c62cc04f55d008cfeb8a681e8463fddd a2ff6c a84b9ed6116c865cd81e062460");
    // === TH_3 ===
    const TH_3_PSK_TV: BytesHashLen =
        hex!("386a9d052b255992eee5ffb594347d327418a2ea5183486c0c9e20426e0bca2f");
    // === ID_CRED_PSK ===
    const ID_CRED_PSK_TV: [u8; 1] = hex!("10");
    // === CRED_I ===
    const CRED_I_PSK_TV: [u8; 39] =
        hex!("a20269696e69746961746f7208a101A30104024110205050930ff462a77a3540cf546325dea214");
    // === CRED_R ===
    const CRED_R_PSK_TV: [u8; 39] =
        hex!("a20269726573706f6e64657208a101a30104024110205050930ff462a77a3540cf546325dea214");
    // === K_3 (16 bytes) ===
    const K_3_PSK_TV: BytesCcmKeyLen = hex!("966a579cea26ca3ceb442ac727eab232");
    // === IV_3 (13 bytes) ===
    const IV_3_PSK_TV: BytesCcmIvLen = hex!("5bf1ad0e4ffb9676d78df23f6e");
    const CIPHERTEXT_3A_LEN_PSK_TV: usize = MESSAGE_3_PSK_TV.len() - 1;
    const PLAINTEXT_3A_LEN_PSK_TV: usize = MESSAGE_3_PSK_TV.len() - 1;
    const PLAINTEXT_3B_PSK_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!(""));
    // === CIPHERTEXT_3B (9 bytes) ===
    // FIXME: Old value whit external_aad = th_3
    //const CIPHERTEXT_3B_PSK_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(
    //    &hex!("480488b7f2a666b629")
    //);
    const CIPHERTEXT_3B_PSK_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("482996d76b91ac456a"));
    // === KEYSTREAM_3A (10 bytes) ===
    const KEYSTREAM_3A_PSK_TV: [u8; PLAINTEXT_3A_LEN_PSK_TV] = hex!("03e5d1571bbc9332471b");
    // === PLAINTEXT_3A (10 bytes) ===
    const PLAINTEXT_3A_PSK_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("1048af865535abd96142"));
    // === CIPHERTEXT_3A (10 bytes) ===
    const CIPHERTEXT_3A_PSK_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("13ad7ed14e8938eb2659"));
    // === message_3 (11 bytes) ===
    const MESSAGE_3_PSK_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("4a13ad7ed14e8938eb2659"));
    // === TH_4 ===
    const TH_4_PSK_TV: BytesHashLen =
        hex!("11481b9afef95c679a52038217eedd0e0ce08faa865bdc825511ca6dc3919413");
    // === K_4 (16 bytes) ===
    const K_4_PSK_TV: BytesCcmKeyLen = hex!("bcab1df0138dc05c885fd371e950c67f");
    // === IV_4 (13 bytes) ===
    const IV_4_PSK_TV: BytesCcmIvLen = hex!("411134d0e0c508d95da7c3acdc");
    const PLAINTEXT_4_PSK_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!(""));
    // === message_4 (9 bytes) ===
    const MESSAGE_4_PSK_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("488add93db404859f9"));
    // === PRK_out ===
    const PRK_OUT_PSK_TV: BytesHashLen =
        hex!("bba6ded3b038d2323774d89214a513a24916f042296c7c729cd1a67b436fb414");
    // === PRK_exporter ===
    const PRK_EXPORTER_PSK_TV: BytesHashLen =
        hex!("2fcd08c0c01077c6d6486b9f9b677020e8d68f04bcdcce715dd277ed25931bef");
    const ENC_STRUCURE_MESSAGE_3: EdhocBuffer<MAX_BUFFER_LEN> = EdhocBuffer::new_from_array(&hex!(
        "8368456e6372797074304058748441106088bc5c5f84d253d204e480a1b980cbd
                    7825fd15a6fe8fc926500144e3f53de9767a20269696e69746961746f7208a1
                    01a30104024110205050930ff462a77a3540cf546325dea21467a2026972657
                    3706f6e64657208a101a30104024110205050930ff462a77a3540cf546325dea214"
    ));

    // STAT-STAT METHOD
    // message_1 (first_time)
    // const METHOD_TV_FIRST_TIME: u8 = 0x03;
    const METHOD_TV_FIRST_TIME: EDHOCMethod = EDHOCMethod::StatStat;
    const SUITES_I_TV_FIRST_TIME: EdhocBuffer<MAX_SUITES_LEN> =
        EdhocBuffer::new_from_array(&hex!("06"));
    const G_X_TV_FIRST_TIME: BytesP256ElemLen =
        hex!("741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9");
    #[allow(deprecated)]
    const C_I_TV_FIRST_TIME: ConnId = ConnId::from_int_raw(0x0e);
    const MESSAGE_1_TV_FIRST_TIME: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!(
        "03065820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e"
    ));

    // message_1 (second time)
    // const METHOD_TV: u8 = 0x03;
    const METHOD_TV: EDHOCMethod = EDHOCMethod::StatStat;
    // manually modified test vector to include a single supported cipher suite
    const SUITES_I_TV: EdhocBuffer<MAX_SUITES_LEN> = EdhocBuffer::new_from_array(&hex!("0602"));
    const G_X_TV: BytesP256ElemLen =
        hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
    #[allow(deprecated)]
    const C_I_TV: ConnId = ConnId::from_int_raw(0x37);
    const MESSAGE_1_TV: BufferMessage1 = EdhocBuffer::new_from_array(&hex!(
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637"
    ));
    // below are a few truncated messages for the purpose of testing cipher suites
    // message with one cipher suite (23..=255)
    const MESSAGE_1_TV_SUITE_ONLY_A: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("031818"));
    // message with an array having two cipher suites with small values (0..=23)
    const MESSAGE_1_TV_SUITE_ONLY_B: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("03820201"));
    // message with an array having two cipher suites, where one is a large value (23..=255)
    const MESSAGE_1_TV_SUITE_ONLY_C: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("0382021819"));
    // message with an array having too many cipher suites (more than 9)
    const MESSAGE_1_TV_SUITE_ONLY_ERR: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("038A02020202020202020202"));
    const EAD_DUMMY_LABEL_TV: u16 = 0x01;
    const EAD_DUMMY_VALUE_TV: &[u8] = &hex!("cccccc");
    const EAD_DUMMY_CRITICAL_TV: EdhocBuffer<MAX_EAD_LEN> =
        EdhocBuffer::new_from_array(&hex!("2043cccccc"));
    const MESSAGE_1_WITH_DUMMY_EAD_NO_VALUE_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(
        &hex!("0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b63701"),
    );
    const MESSAGE_1_WITH_DUMMY_EAD_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!(
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370143cccccc"
    ));
    const MESSAGE_1_WITH_DUMMY_CRITICAL_EAD_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!("0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6372043cccccc"));
    const MESSAGE_1_WITH_TWO_EADS: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!("0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6370143cccccc2043cccccc"));
    const G_Y_TV: BytesP256ElemLen =
        hex!("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
    #[allow(deprecated)]
    const C_R_TV: ConnId = ConnId::from_int_raw(0x27);
    const MESSAGE_2_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!("582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d59862a1eef9e0e7e1886fcd"));
    const CIPHERTEXT_2_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("9862a1eef9e0e7e1886fcd"));
    const H_MESSAGE_1_TV: BytesHashLen =
        hex!("ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c");
    const TH_2_TV: BytesHashLen =
        hex!("356efd53771425e008f3fe3a86c83ff4c6b16e57028ff39d5236c182b202084b");
    const TH_3_TV: BytesHashLen =
        hex!("adaf67a78a4bcc91e018f8882762a722000b2507039df0bc1bbf0c161bb3155c");
    const TH_4_TV: BytesHashLen =
        hex!("c902b1e3a4326c93c5551f5f3aa6c5ecc0246806765612e52b5d99e6059d6b6e");
    const PRK_2E_TV: BytesP256ElemLen =
        hex!("5aa0d69f3e3d1e0c479f0b8a486690c9802630c3466b1dc92371c982563170b5");
    const CIPHERTEXT_2_LEN_TV: usize = MESSAGE_2_TV.len() - P256_ELEM_LEN - 2;
    const PLAINTEXT_2_LEN_TV: usize = CIPHERTEXT_2_LEN_TV;
    const KEYSTREAM_2_TV: [u8; PLAINTEXT_2_LEN_TV] = hex!("bf50e9e7bad0bb68173399");
    const PRK_3E2M_TV: BytesP256ElemLen =
        hex!("0ca3d3398296b3c03900987620c11f6fce70781c1d1219720f9ec08c122d8434");
    const CONTEXT_INFO_MAC_2_TV: [u8; 134] = hex!("27a10441325820356efd53771425e008f3fe3a86c83ff4c6b16e57028ff39d5236c182b202084ba2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const MAC_2_TV: BytesMac2 = hex!("0943305c899f5c54");
    const ID_CRED_I_TV: [u8; 4] = hex!("a104412b");
    const MAC_3_TV: BytesMac3 = hex!("623c91df41e34c2f");
    const MESSAGE_3_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("52e562097bc417dd5919485ac7891ffd90a9fc"));
    const PRK_4E3M_TV: BytesP256ElemLen =
        hex!("81cc8a298e357044e3c466bb5c0a1e507e01d49238aeba138df94635407c0ff7");
    const MESSAGE_4_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("4828c966b7ca304f83"));
    const PLAINTEXT_4_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!(""));
    const K_4_TV: BytesCcmKeyLen = hex!("d3c77872b6eeb508911bdbd308b2e6a0");
    const IV_4_TV: BytesCcmIvLen = hex!("04ff0f44456e96e217853c3601");
    const CRED_I_TV : [u8; 107] = hex!("a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
    const ID_CRED_R_TV: [u8; 4] = hex!("a1044132");
    const CRED_R_TV : [u8; 95] = hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const PLAINTEXT_2_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("2732480943305c899f5c54"));
    const SK_I_TV: BytesP256ElemLen =
        hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const X_TV: BytesP256ElemLen =
        hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
    const G_R_TV: BytesP256ElemLen =
        hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const PLAINTEXT_3_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("2b48623c91df41e34c2f"));
    const SALT_3E2M_TV: BytesHashLen =
        hex!("af4e103a47cb3cf32570d5c25ad27732bd8d8178e9a69d061c31a27f8e3ca926");
    const SALT_4E3M_TV: BytesHashLen =
        hex!("cfddf9515a7e46e7b4dbff31cbd56cd04ba332250de9ea5de1caf9f6d13914a7");
    const G_XY_TV: BytesP256ElemLen =
        hex!("2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba");
    const PRK_OUT_TV: BytesHashLen =
        hex!("2c71afc1a9338a940bb3529ca734b886f30d1aba0b4dc51beeaeabdfea9ecbf8");
    const PRK_EXPORTER_TV: BytesHashLen =
        hex!("e14d06699cee248c5a04bf9227bbcd4ce394de7dcb56db43555474171e6446db");
    const OSCORE_MASTER_SECRET_TV: BytesCcmKeyLen = hex!("f9868f6a3aca78a05d1485b35030b162");
    const OSCORE_MASTER_SALT_TV: [u8; 8] = hex!("ada24c7dbfc85eeb");

    // invalid test vectors, should result in a parsing error
    const MESSAGE_1_INVALID_ARRAY_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!(
        "8403025820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e"
    ));
    // This is invalid because the h'0e' byte string is a text string instead
    const MESSAGE_1_INVALID_C_I_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!(
        "03025820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9610e"
    ));
    const MESSAGE_1_INVALID_CIPHERSUITE_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(
        &hex!("0381025820741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa90e"),
    );
    const MESSAGE_1_INVALID_TEXT_EPHEMERAL_KEY_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(
        &hex!("0302782020616972207370656564206F66206120756E6C6164656E207377616C6C6F77200e"),
    );
    const MESSAGE_2_INVALID_NUMBER_OF_CBOR_SEQUENCE_TV: EdhocMessageBuffer = EdhocBuffer::new_from_array(&hex!("5820419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d54B9862a11de42a95d785386a"));
    const PLAINTEXT_2_SURPLUS_MAP_ID_CRED_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("27a10442321048fa5efa2ebf920bf3"));
    const PLAINTEXT_2_SURPLUS_BSTR_ID_CRED_TV: EdhocMessageBuffer =
        EdhocBuffer::new_from_array(&hex!("27413248fa5efa2ebf920bf3"));

    #[test]
    fn test_ecdh() {
        let g_xy = default_crypto().p256_ecdh(&X_TV, &G_Y_TV);

        assert_eq!(g_xy, G_XY_TV);
    }
    #[test]
    fn test_ecdh_psk() {
        let g_xy = default_crypto().p256_ecdh(&X_PSK_TV, &G_Y_PSK_TV);

        assert_eq!(g_xy, G_XY_PSK_TV);
    }

    #[test]
    fn test_encode_message_1() {
        let message_1 =
            encode_message_1(METHOD_TV, &SUITES_I_TV, &G_X_TV, C_I_TV, &EadItems::new()).unwrap();

        assert_eq!(message_1.len(), 39);
        assert_eq!(message_1, MESSAGE_1_TV);
    }

    #[test]
    fn test_encode_message_1_psk() {
        let message_1 = encode_message_1(
            METHOD_PSK_TV,
            &SUITES_I_PSK_TV,
            &G_X_PSK_TV,
            C_I_PSK_TV,
            &EadItems::new(),
        )
        .unwrap();

        assert_eq!(message_1.len(), 37);
        assert_eq!(message_1, MESSAGE_1_PSK_TV);
    }

    #[test]
    fn test_parse_suites_i() {
        // skip the fist byte (method)
        let decoder = CBORDecoder::new(&MESSAGE_1_TV.as_slice()[1..]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, _decoder) = res.unwrap();
        assert_eq!(suites_i, SUITES_I_TV);

        // skip the fist byte (method)
        let decoder = CBORDecoder::new(&MESSAGE_1_TV_SUITE_ONLY_A.as_slice()[1..]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, _decoder) = res.unwrap();
        assert_eq!(suites_i[0], 0x18);

        // skip the fist byte (method)
        let decoder = CBORDecoder::new(&MESSAGE_1_TV_SUITE_ONLY_B.as_slice()[1..]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, _decoder) = res.unwrap();
        assert_eq!(suites_i.len(), 2);
        assert_eq!(suites_i[0], 0x02);
        assert_eq!(suites_i[1], 0x01);

        // skip the fist byte (method)
        let decoder = CBORDecoder::new(&MESSAGE_1_TV_SUITE_ONLY_C.as_slice()[1..]);
        let res = parse_suites_i(decoder);
        assert!(res.is_ok());
        let (suites_i, _decoder) = res.unwrap();
        assert_eq!(suites_i.len(), 2);
        assert_eq!(suites_i[0], 0x02);
        assert_eq!(suites_i[1], 0x19);

        // skip the fist byte (method)
        let decoder = CBORDecoder::new(&MESSAGE_1_TV_SUITE_ONLY_ERR.as_slice()[1..]);
        let res = parse_suites_i(decoder);
        assert_eq!(res.unwrap_err(), EDHOCError::ParsingError);
    }

    #[test]
    fn test_parse_message_1() {
        // first time message_1 parsing
        let res = parse_message_1(&MESSAGE_1_TV_FIRST_TIME);
        assert!(res.is_ok());
        let (method, suites_i, g_x, c_i, ead_1) = res.unwrap();

        assert_eq!(method, METHOD_TV_FIRST_TIME.into());
        assert_eq!(suites_i, SUITES_I_TV_FIRST_TIME);
        assert_eq!(g_x, G_X_TV_FIRST_TIME);
        assert_eq!(c_i, C_I_TV_FIRST_TIME);
        assert!(ead_1.is_empty());

        // second time message_1
        let res = parse_message_1(&MESSAGE_1_TV);
        assert!(res.is_ok());
        let (method, suites_i, g_x, c_i, ead_1) = res.unwrap();

        assert_eq!(method, METHOD_TV.into());
        assert_eq!(suites_i, SUITES_I_TV);
        assert_eq!(g_x, G_X_TV);
        assert_eq!(c_i, C_I_TV);
        assert!(ead_1.is_empty());
    }

    #[test]
    fn test_parse_message_1_psk() {
        // first time message_1 parsing
        let res = parse_message_1(&MESSAGE_1_PSK_TV);
        assert!(res.is_ok());
        let (method, suites_i, g_x, c_i, ead_1) = res.unwrap();

        assert_eq!(method, METHOD_PSK_TV.into());
        assert_eq!(suites_i, SUITES_I_PSK_TV);
        assert_eq!(g_x, G_X_PSK_TV);
        assert_eq!(c_i, C_I_PSK_TV);
        assert!(ead_1.is_empty());
    }

    #[test]
    fn test_parse_message_1_invalid_traces() {
        assert_eq!(
            parse_message_1(&MESSAGE_1_INVALID_ARRAY_TV).unwrap_err(),
            EDHOCError::ParsingError
        );

        assert_eq!(
            parse_message_1(&MESSAGE_1_INVALID_C_I_TV).unwrap_err(),
            EDHOCError::ParsingError
        );

        assert_eq!(
            parse_message_1(&MESSAGE_1_INVALID_CIPHERSUITE_TV).unwrap_err(),
            EDHOCError::ParsingError
        );

        assert_eq!(
            parse_message_1(&MESSAGE_1_INVALID_TEXT_EPHEMERAL_KEY_TV).unwrap_err(),
            EDHOCError::ParsingError
        );
    }

    #[test]
    fn test_parse_message_2_invalid_traces() {
        assert_eq!(
            parse_message_2(&MESSAGE_2_INVALID_NUMBER_OF_CBOR_SEQUENCE_TV).unwrap_err(),
            EDHOCError::ParsingError
        );
    }

    #[test]
    fn test_encode_message_2() {
        let message_2 = encode_message_2(&G_Y_TV, &CIPHERTEXT_2_TV);

        assert_eq!(message_2, MESSAGE_2_TV);
    }

    #[test]
    fn test_encode_message_2_psk() {
        let message_2 = encode_message_2(&G_Y_PSK_TV, &CIPHERTEXT_2_PSK_TV);

        assert_eq!(message_2, MESSAGE_2_PSK_TV);
    }

    #[test]
    fn test_parse_message_2() {
        let ret = parse_message_2(&MESSAGE_2_TV);
        assert!(ret.is_ok());
        let (g_y, ciphertext_2) = ret.unwrap();

        assert_eq!(g_y, G_Y_TV);
        assert_eq!(ciphertext_2, CIPHERTEXT_2_TV);
    }

    #[test]
    fn test_parse_message_2_psk() {
        let ret = parse_message_2(&MESSAGE_2_PSK_TV);
        assert!(ret.is_ok());
        let (g_y, ciphertext_2) = ret.unwrap();

        assert_eq!(g_y, G_Y_PSK_TV);
        assert_eq!(ciphertext_2, CIPHERTEXT_2_PSK_TV);
    }

    #[test]
    fn test_compute_th_2() {
        let th_2 = compute_th_2(&mut default_crypto(), &G_Y_TV, &H_MESSAGE_1_TV);
        assert_eq!(th_2, TH_2_TV);
    }

    #[test]
    fn test_compute_th_2_psk() {
        let th_2 = compute_th_2(&mut default_crypto(), &G_Y_PSK_TV, &H_MESSAGE_1_PSK_TV);
        assert_eq!(th_2, TH_2_PSK_TV);
    }

    #[test]
    fn test_compute_th_3() {
        let th_3 = compute_th_3(
            &mut default_crypto(),
            &TH_2_TV,
            &PLAINTEXT_2_TV,
            Some(&CRED_R_TV),
        );
        assert_eq!(th_3, TH_3_TV);
    }

    #[test]
    fn test_compute_th_3_psk() {
        let th_3 = compute_th_3(
            &mut default_crypto(),
            &TH_2_PSK_TV,
            &PLAINTEXT_2_PSK_TV,
            None,
        );
        assert_eq!(th_3, TH_3_PSK_TV);
    }

    #[test]
    fn test_compute_th_4() {
        let th_4 = compute_th_4(
            &mut default_crypto(),
            &TH_3_TV,
            &PLAINTEXT_3_TV,
            METHOD_TV.into(),
            None,
            None,
            &CRED_I_TV,
            None,
        );
        assert_eq!(th_4, TH_4_TV);
    }

    #[test]
    fn test_compute_th_4_psk() {
        let th_4 = compute_th_4(
            &mut default_crypto(),
            &TH_3_PSK_TV,
            &PLAINTEXT_3B_PSK_TV,
            METHOD_PSK_TV.into(),
            Some(&ID_CRED_PSK_TV),
            Some(&EadItems::new()),
            &CRED_I_PSK_TV,
            Some(&CRED_R_PSK_TV),
        );
        assert_eq!(th_4, TH_4_PSK_TV);
    }

    #[test]
    fn test_edhoc_kdf() {
        const LEN_TV: usize = PLAINTEXT_2_LEN_TV;

        let output: [u8; LEN_TV] =
            edhoc_kdf_owned(&mut default_crypto(), &PRK_2E_TV, 0u8, &TH_2_TV);
        for i in 0..KEYSTREAM_2_TV.len() {
            assert_eq!(KEYSTREAM_2_TV[i], output[i]);
        }

        let output_2: [u8; MAC_LENGTH_2] = edhoc_kdf_owned(
            &mut default_crypto(),
            &PRK_3E2M_TV,
            2u8,
            &CONTEXT_INFO_MAC_2_TV,
        );

        for i in 0..MAC_2_TV.len() {
            assert_eq!(MAC_2_TV[i], output_2[i]);
        }
    }

    #[test]
    fn test_encrypt_message_3() {
        let message_3 = encrypt_message_3(
            &mut default_crypto(),
            &PRK_3E2M_TV,
            &TH_3_TV,
            &PLAINTEXT_3_TV,
            None,
            None,
            None,
        );
        assert_eq!(message_3, MESSAGE_3_TV);
    }

    #[test]
    fn test_encrypt_message_3b_psk() {
        let ciphertext_3b = encrypt_message_3(
            &mut default_crypto(),
            &PRK_4E3M_PSK_TV,
            &TH_3_PSK_TV,
            &PLAINTEXT_3B_PSK_TV,
            Some(&ID_CRED_PSK_TV),
            Some(&CRED_I_PSK_TV),
            Some(&CRED_R_PSK_TV),
        );
        assert_eq!(ciphertext_3b, CIPHERTEXT_3B_PSK_TV);
    }

    #[test]
    fn test_encrypt_plaintext_3a_psk() {
        let ciphertext_3a = encrypt_decrypt_ciphertext_3a(
            &mut default_crypto(),
            &PRK_3E2M_PSK_TV,
            &TH_3_PSK_TV,
            &PLAINTEXT_3A_PSK_TV,
        );
        assert_eq!(ciphertext_3a, CIPHERTEXT_3A_PSK_TV);
    } //encrypt_decrypt_ciphertext_3a

    #[test]
    fn test_decrypt_ciphertext_3a_psk() {
        let plaintext_3a = encrypt_decrypt_ciphertext_3a(
            &mut default_crypto(),
            &PRK_3E2M_PSK_TV,
            &TH_3_PSK_TV,
            &CIPHERTEXT_3A_PSK_TV,
        );
        assert_eq!(plaintext_3a, PLAINTEXT_3A_PSK_TV);
    } //encrypt_decrypt_ciphertext_3a

    #[test]
    fn test_decrypt_message_3() {
        let plaintext_3 = decrypt_message_3(
            &mut default_crypto(),
            &PRK_3E2M_TV,
            &TH_3_TV,
            &MESSAGE_3_TV,
            None,
            None,
            None,
        );
        assert!(plaintext_3.is_ok());
        assert_eq!(plaintext_3.unwrap(), PLAINTEXT_3_TV);
    }

    #[test]
    fn test_decrypt_message_3b_psk() {
        let plaintext_3b = decrypt_message_3(
            &mut default_crypto(),
            &PRK_4E3M_PSK_TV,
            &TH_3_PSK_TV,
            &CIPHERTEXT_3B_PSK_TV,
            Some(&ID_CRED_PSK_TV),
            Some(&CRED_I_PSK_TV),
            Some(&CRED_R_PSK_TV),
        );
        assert_eq!(plaintext_3b.unwrap(), PLAINTEXT_3B_PSK_TV);
    }

    #[test]
    fn test_compute_mac_3() {
        let mac_3 = compute_mac_3(
            &mut default_crypto(),
            &PRK_4E3M_TV,
            &TH_3_TV,
            &ID_CRED_I_TV,
            &CRED_I_TV,
            &EadItems::new(),
        );
        assert_eq!(mac_3, MAC_3_TV);
    }

    #[test]
    fn test_compute_and_verify_mac_2() {
        let rcvd_mac_2 = compute_mac_2(
            &mut default_crypto(),
            &PRK_3E2M_TV,
            C_R_TV,
            &ID_CRED_R_TV,
            &CRED_R_TV,
            &TH_2_TV,
            &EadItems::new(),
        );

        assert_eq!(rcvd_mac_2, MAC_2_TV);
    }

    #[test]
    fn test_encode_plaintext_2() {
        let plaintext_2 = encode_plaintext_2(
            C_R_TV,
            Some(
                IdCred::from_full_value(&ID_CRED_R_TV[..])
                    .unwrap()
                    .as_encoded_value(),
            ),
            Some(&MAC_2_TV),
            &EadItems::new(),
        )
        .unwrap();

        assert_eq!(plaintext_2, PLAINTEXT_2_TV);
    }

    fn test_encode_plaintext_2_psk() {
        let plaintext_2 = encode_plaintext_2(C_R_PSK_TV, None, None, &EadItems::new()).unwrap();

        assert_eq!(plaintext_2, PLAINTEXT_2_PSK_TV);
    }

    #[test]
    fn test_parse_plaintext_2_invalid_traces() {
        let ret = decode_plaintext_2(METHOD_TV, &PLAINTEXT_2_SURPLUS_MAP_ID_CRED_TV);
        assert_eq!(ret.unwrap_err(), EDHOCError::ParsingError);

        let ret = decode_plaintext_2(METHOD_TV, &PLAINTEXT_2_SURPLUS_BSTR_ID_CRED_TV);
        assert_eq!(ret.unwrap_err(), EDHOCError::ParsingError);
    }

    #[test]
    fn test_decode_plaintext_2() {
        let plaintext_2 = decode_plaintext_2(METHOD_TV, &PLAINTEXT_2_TV);
        assert!(plaintext_2.is_ok());
        let (c_r, id_cred_r, mac_2, ead_2) = plaintext_2.unwrap();
        assert_eq!(c_r, C_R_TV);
        assert_eq!(id_cred_r.unwrap().as_full_value(), ID_CRED_R_TV);
        assert_eq!(mac_2, Some(MAC_2_TV));
        assert!(ead_2.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_ciphertext_2() {
        // test decryption
        let plaintext_2 = encrypt_decrypt_ciphertext_2(
            &mut default_crypto(),
            &PRK_2E_TV,
            &TH_2_TV,
            &CIPHERTEXT_2_TV,
        );

        assert_eq!(plaintext_2, PLAINTEXT_2_TV);

        // test encryption
        let ciphertext_2 =
            encrypt_decrypt_ciphertext_2(&mut default_crypto(), &PRK_2E_TV, &TH_2_TV, &plaintext_2);

        assert_eq!(ciphertext_2, CIPHERTEXT_2_TV);
    }

    #[test]
    fn test_encrypt_decrypt_ciphertext_2_psk() {
        // test decryption
        let plaintext_2 = encrypt_decrypt_ciphertext_2(
            &mut default_crypto(),
            &PRK_2E_PSK_TV,
            &TH_2_PSK_TV,
            &CIPHERTEXT_2_PSK_TV,
        );

        assert_eq!(plaintext_2, PLAINTEXT_2_PSK_TV);

        // test encryption
        let ciphertext_2 = encrypt_decrypt_ciphertext_2(
            &mut default_crypto(),
            &PRK_2E_PSK_TV,
            &TH_2_PSK_TV,
            &plaintext_2,
        );

        assert_eq!(ciphertext_2, CIPHERTEXT_2_PSK_TV);
    }

    #[test]
    fn test_decode_plaintext_4() {
        let plaintext_4 = decode_plaintext_4(&PLAINTEXT_4_TV);
        assert!(plaintext_4.is_ok());
        let ead_4 = plaintext_4.unwrap();
        assert!(ead_4.is_empty());
    }

    #[test]
    fn test_encrypt_message_4() {
        let message_4 = encrypt_message_4(
            &mut default_crypto(),
            &PRK_4E3M_TV,
            &TH_4_TV,
            &PLAINTEXT_4_TV,
        );
        assert_eq!(message_4, MESSAGE_4_TV);
    }

    #[test]
    fn test_encrypt_message_4_psk() {
        let message_4 = encrypt_message_4(
            &mut default_crypto(),
            &PRK_4E3M_PSK_TV,
            &TH_4_PSK_TV,
            &PLAINTEXT_4_PSK_TV,
        );
        assert_eq!(message_4, MESSAGE_4_PSK_TV);
    }

    #[test]
    fn test_decrypt_message_4() {
        let plaintext_4 =
            decrypt_message_4(&mut default_crypto(), &PRK_4E3M_TV, &TH_4_TV, &MESSAGE_4_TV);
        assert!(plaintext_4.is_ok());
        assert_eq!(plaintext_4.unwrap(), PLAINTEXT_4_TV);
    }

    #[test]
    fn test_decrypt_message_4_psk() {
        let plaintext_4 = decrypt_message_4(
            &mut default_crypto(),
            &PRK_4E3M_PSK_TV,
            &TH_4_PSK_TV,
            &MESSAGE_4_PSK_TV,
        );
        assert!(plaintext_4.is_ok());
        assert_eq!(plaintext_4.unwrap(), PLAINTEXT_4_PSK_TV);
    }

    #[test]
    fn test_compute_k_4_iv_4() {
        let (k_4, iv_4) = compute_k_4_iv_4(&mut default_crypto(), &PRK_4E3M_TV, &TH_4_TV);
        assert_eq!(k_4, K_4_TV);
        assert_eq!(iv_4, IV_4_TV);
    }

    #[test]
    fn test_compute_prk_4e3m() {
        let prk_4e3m = compute_prk_4e3m(&mut default_crypto(), &SALT_4E3M_TV, &SK_I_TV, &G_Y_TV);
        assert_eq!(prk_4e3m, PRK_4E3M_TV);
    }

    #[test]
    fn test_compute_prk_4e3m_psk() {
        let prk_4e3m = compute_prk_4e3m_psk(&mut default_crypto(), &SALT_4E3M_PSK_TV, &PSK_TV);
        assert_eq!(prk_4e3m, PRK_4E3M_PSK_TV);
    }

    #[test]
    fn test_compute_prk_3e2m() {
        let prk_3e2m = compute_prk_3e2m(&mut default_crypto(), &SALT_3E2M_TV, &X_TV, &G_R_TV);
        assert_eq!(prk_3e2m, PRK_3E2M_TV);
    }

    #[test]
    fn test_compute_prk_2e() {
        let prk_2e = compute_prk_2e(&mut default_crypto(), &X_TV, &G_Y_TV, &TH_2_TV);
        assert_eq!(prk_2e, PRK_2E_TV);
    }

    #[test]
    fn test_encode_plaintext_3() {
        let plaintext_3 = encode_plaintext_3(
            Some(
                IdCred::from_full_value(&ID_CRED_I_TV[..])
                    .unwrap()
                    .as_encoded_value(),
            ),
            Some(&MAC_3_TV),
            &EadItems::new(),
        )
        .unwrap();
        assert_eq!(plaintext_3, PLAINTEXT_3_TV);
    }

    #[test]
    fn test_decode_plaintext_3() {
        let (id_cred_i, mac_3, ead_3) =
            decode_plaintext_3(METHOD_TV.into(), &PLAINTEXT_3_TV).unwrap();

        assert_eq!(mac_3, Some(MAC_3_TV));
        assert_eq!(id_cred_i.unwrap().as_full_value(), ID_CRED_I_TV);
        assert!(ead_3.is_empty());
    }

    #[test]
    fn test_encode_ead_item() {
        let ead_item =
            EADItem::new_full(EAD_DUMMY_LABEL_TV, true, Some(EAD_DUMMY_VALUE_TV)).unwrap();

        let res = ead_item.encode();
        assert!(res.is_ok());
        let ead_buffer = res.unwrap();
        assert_eq!(ead_buffer, EAD_DUMMY_CRITICAL_TV);
    }

    #[test]
    fn test_encode_message_with_ead_item() {
        let method_tv = METHOD_TV;
        let c_i_tv = C_I_TV;
        let ead_item =
            EADItem::new_full(EAD_DUMMY_LABEL_TV, true, Some(EAD_DUMMY_VALUE_TV)).unwrap();

        let mut ead = EadItems::new();
        ead.try_push(ead_item).unwrap();

        let res = encode_message_1(method_tv, &SUITES_I_TV, &G_X_TV, c_i_tv, &ead);
        assert!(res.is_ok());
        let message_1 = res.unwrap();

        assert_eq!(message_1, MESSAGE_1_WITH_DUMMY_CRITICAL_EAD_TV);
    }

    #[test]
    fn test_encode_message_with_large_ead_item() {
        // FIXME: This only works with the default parameters, where 4 EAD items can be had that
        // together exceed the maximum size.

        let method_tv = METHOD_TV;
        let c_i_tv = C_I_TV;

        let ead_item = EADItem::new_full(
            EAD_DUMMY_LABEL_TV,
            true,
            // Enough for the pre-buffer encoding, but still large
            Some(&[0; MAX_EAD_LEN - 3]),
        )
        .unwrap();

        let mut ead = EadItems::new();
        ead.try_push(ead_item.clone()).unwrap();
        ead.try_push(ead_item.clone()).unwrap();
        ead.try_push(ead_item.clone()).unwrap();
        ead.try_push(ead_item).unwrap();

        let res = encode_message_1(method_tv, &SUITES_I_TV, &G_X_TV, c_i_tv, &ead);
        assert_eq!(res.unwrap_err(), EDHOCError::EadTooLongError);
    }

    #[test]
    fn test_parse_ead_item() {
        let message_tv_offset = MESSAGE_1_TV.len();

        let ead = parse_eads(&MESSAGE_1_WITH_DUMMY_EAD_TV.as_slice()[message_tv_offset..]).unwrap();

        let mut ead = ead.iter();
        let ead_item = ead.next().unwrap();
        assert!(!ead_item.is_critical());
        assert_eq!(ead_item.label(), EAD_DUMMY_LABEL_TV);
        assert_eq!(ead_item.value_bytes(), Some(EAD_DUMMY_VALUE_TV));
        // only 1 ead
        assert!(ead.next().is_none());

        let ead = parse_eads(&MESSAGE_1_WITH_DUMMY_CRITICAL_EAD_TV.as_slice()[message_tv_offset..])
            .unwrap();

        let mut ead = ead.iter();
        let ead_item = ead.next().unwrap();
        assert!(ead_item.is_critical());
        assert_eq!(ead_item.label(), EAD_DUMMY_LABEL_TV);
        assert_eq!(ead_item.value_bytes(), Some(EAD_DUMMY_VALUE_TV));
        // only 1 ead
        assert!(ead.next().is_none());

        let ead = parse_eads(&MESSAGE_1_WITH_DUMMY_EAD_NO_VALUE_TV.as_slice()[message_tv_offset..])
            .unwrap();
        let ead = &ead.iter().next().unwrap();
        assert!(!ead.is_critical());
        assert_eq!(ead.label(), EAD_DUMMY_LABEL_TV);
        assert!(ead.value_bytes().is_none());

        let ead = parse_eads(&MESSAGE_1_WITH_TWO_EADS.as_slice()[message_tv_offset..]).unwrap();

        let mut ead = ead.iter();
        let fst_ead = ead.next().unwrap();
        assert!(!fst_ead.is_critical());
        assert_eq!(fst_ead.label(), EAD_DUMMY_LABEL_TV);
        assert_eq!(fst_ead.value_bytes(), Some(EAD_DUMMY_VALUE_TV));
        let snd_ead = ead.next().unwrap();
        assert!(snd_ead.is_critical());
        assert_eq!(snd_ead.label(), EAD_DUMMY_LABEL_TV);
        assert_eq!(snd_ead.value_bytes(), Some(EAD_DUMMY_VALUE_TV));
        assert!(ead.next().is_none());
    }

    #[test]
    fn test_parse_message_with_ead_item() {
        let res = parse_message_1(&MESSAGE_1_WITH_DUMMY_CRITICAL_EAD_TV);
        assert!(res.is_ok());
        let (_method, _suites_i, _g_x, _c_i, ead_1) = res.unwrap();

        let ead_1 = &ead_1.iter().next().unwrap();
        assert!(ead_1.is_critical());
        assert_eq!(ead_1.label(), EAD_DUMMY_LABEL_TV);
        assert_eq!(ead_1.value_bytes(), Some(EAD_DUMMY_VALUE_TV));
    }

    #[test]
    fn test_compute_prk_out() {
        let prk_out: BytesHashLen =
            edhoc_kdf_owned(&mut default_crypto(), &PRK_4E3M_TV, 7u8, &TH_4_TV);

        assert_eq!(prk_out, PRK_OUT_TV);
    }

    #[test]
    fn test_compute_prk_exporter() {
        let prk_exporter = edhoc_kdf_owned(&mut default_crypto(), &PRK_OUT_TV, 10u8, &[]);

        assert_eq!(prk_exporter, PRK_EXPORTER_TV);
    }

    #[test]
    fn test_compute_oscore_master_secret_salt() {
        let mut oscore_master_secret_buf = Vec::new();
        oscore_master_secret_buf.resize(OSCORE_MASTER_SECRET_TV.len(), 0xff);
        edhoc_kdf(
            &mut default_crypto(),
            &PRK_EXPORTER_TV,
            0u8,
            &[],
            &mut oscore_master_secret_buf,
        );
        assert_eq!(oscore_master_secret_buf, &OSCORE_MASTER_SECRET_TV[..]);

        let mut oscore_master_salt_buf = Vec::new();
        oscore_master_salt_buf.resize(OSCORE_MASTER_SALT_TV.len(), 0x00);
        edhoc_kdf(
            &mut default_crypto(),
            &PRK_EXPORTER_TV,
            1u8,
            &[],
            &mut oscore_master_salt_buf,
        );

        assert_eq!(oscore_master_salt_buf, &OSCORE_MASTER_SALT_TV[..]);
    }
}

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
    let plaintext_2 = encode_plaintext_2_psk(c_r, &ead_2)?;

    // step is actually from processing of message_3
    // but we do it here to avoid storing plaintext_2 in State
    let th_3 = compute_th_3_psk(crypto, &th_2, &plaintext_2);

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
    state: &mut WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
) -> Result<(ProcessingM3, IdCred, EadItems), EDHOCError> {
    r_parse_message_3_psk_with_cred_resolver(
        state,
        crypto,
        message_3,
        recover_cred_i_from_id_cred_psk,
    )
}

pub fn r_parse_message_3_psk_with_cred_resolver<F>(
    state: &mut WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
    resolve_cred_i: F,
) -> Result<(ProcessingM3, IdCred, EadItems), EDHOCError>
where
    F: Fn(&IdCred) -> Result<Credential, EDHOCError>,
{
    let res = parse_message_3(message_3)?;
    let plaintext_3a = encrypt_decrypt_ciphertext_3a(crypto, &state.prk_3e2m, &state.th_3, &res);
    let id_cred_psk = IdCred::from_encoded_value(&[plaintext_3a.as_slice()[0]])?;

    let cred_r = match &state.method_specifics {
        WaitM3MethodSpecifics::Psk { cred_r } => cred_r,
        _ => return Err(EDHOCError::UnsupportedMethod),
    };
    let cred_i = resolve_cred_i(&id_cred_psk)?;

    let mut ciphertext_3b = BufferCiphertext3::new();
    let _ = ciphertext_3b.fill_with_slice(&plaintext_3a.as_slice()[1..]);

    let plaintext_3b = decrypt_message_3_psk(
        crypto,
        &state.prk_3e2m,
        &state.th_3,
        &ciphertext_3b,
        id_cred_psk.as_encoded_value(),
        cred_i.bytes.as_slice(),
        cred_r.bytes.as_slice(),
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
) -> Result<(ProcessedM3, BytesHashLen), EDHOCError> {
    // compute salt_4e3m
    let salt_4e3m = compute_salt_4e3m(crypto, &state.prk_3e2m, &state.th_3);

    let prk_4e3m = match valid_cred_i.key {
        CredentialKey::EC2Compact(public_key) => {
            compute_prk_4e3m(crypto, &salt_4e3m, &state.y, &public_key)
        }
        CredentialKey::Symmetric(psk) => compute_prk_4e3m_psk(crypto, &salt_4e3m, &psk),
    };

    let (id_cred_psk, cred_r) = match &state.method_specifics {
        ProcessingM3MethodSpecifics::Psk {
            id_cred_psk,
            cred_r,
        } => (id_cred_psk, cred_r),
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let th_4 = compute_th_4_psk(
        crypto,
        &state.th_3,
        id_cred_psk.as_encoded_value(),
        &state.ead_3,
        valid_cred_i.bytes.as_slice(),
        cred_r.bytes.as_slice(),
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
) -> Result<(ProcessingM2, ConnId, ParsedMessage2Details), EDHOCError> {
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
                plaintext_2: plaintext_2,
                c_r: c_r_2,
                ead_2: ead_2.clone(), // needed for compute_mac_2
            };

            Ok((state, c_r_2, ParsedMessage2Details::Psk { ead_2 }))
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

    let th_3 = compute_th_3_psk(crypto, &state.th_2, &state.plaintext_2);
    // message 3 processing
    let salt_4e3m = compute_salt_4e3m(crypto, &prk_3e2m, &th_3);

    let psk = match valid_cred_r.key {
        CredentialKey::Symmetric(psk) => psk,
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let prk_4e3m = compute_prk_4e3m_psk(crypto, &salt_4e3m, &psk);

    let state = ProcessedM2 {
        method: EDHOCMethod::PSK,
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
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let mut message_3: BufferMessage3 = BufferMessage3::new();

    let plaintext_3 = encode_plaintext_3_psk(&ead_3)?;
    let ciphertext_3b = encrypt_message_3_psk(
        crypto,
        &state.prk_3e2m,
        &state.th_3,
        &plaintext_3,
        id_cred_psk.as_encoded_value(),
        cred_i.bytes.as_slice(),
        cred_r.bytes.as_slice(),
    );
    // compute ciphertext_3a
    let pt_3a = id_cred_psk.as_encoded_value();
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
    let th_4 = compute_th_4_psk(
        crypto,
        &state.th_3,
        id_cred_psk.as_encoded_value(),
        ead_3,
        cred_i.bytes.as_slice(),
        cred_r.bytes.as_slice(),
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

// calculates ciphertext_3 wrapped in a cbor byte string
fn encrypt_message_3_psk(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    plaintext_3: &BufferPlaintext3,
    id_cred: &[u8],
    cred_i: &[u8],
    cred_r: &[u8],
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
    let (external_aad, _aad_len) = build_external_aad_psk(th_3, id_cred, cred_i, cred_r);
    let (enc_structure, enc_len) = encode_enc_structure_psk(&external_aad);
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

fn decrypt_message_3_psk(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    th_3: &BytesHashLen,
    message_3: &BufferMessage3,
    id_cred: &[u8],
    cred_i: &[u8],
    cred_r: &[u8],
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
    let (external_aad, _aad_len) = build_external_aad_psk(th_3, id_cred, cred_i, cred_r);
    let (enc_structure, enc_len) = encode_enc_structure_psk(&external_aad);

    crypto.aes_ccm_decrypt_tag_8(
        &k_3,
        &iv_3,
        &enc_structure.as_slice()[..enc_len],
        ciphertext_3.as_slice(),
    )
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

pub fn build_external_aad_psk(
    th_3: &[u8],
    id_cred: &[u8],
    cred_i: &[u8],
    cred_r: &[u8],
) -> (EdhocBuffer<MAX_BUFFER_LEN>, usize) {
    let mut buf = EdhocBuffer::<MAX_BUFFER_LEN>::new();

    // PSK case: array of 4 items
    //buf.push(CBOR_MAJOR_ARRAY | 4).unwrap();

    // id_cred_psk is considered as a CBOR encoded int
    buf.extend_from_slice(id_cred).unwrap();
    // th_3
    buf.push(CBOR_BYTE_STRING).unwrap();
    buf.push(th_3.len() as u8).unwrap();
    buf.extend_from_slice(th_3).unwrap();
    // cred_i, cred_r are already CBOR Web Token
    buf.extend_from_slice(cred_i).unwrap();
    buf.extend_from_slice(cred_r).unwrap();

    let len = buf.len(); // actual used length
    (buf, len)
}

pub fn encode_enc_structure_psk(
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

fn compute_th_3_psk(
    crypto: &mut impl CryptoTrait,
    th_2: &BytesHashLen,
    plaintext_2: &BufferPlaintext2,
) -> BytesHashLen {
    let mut hash = crypto.sha256_start();

    hash.update([CBOR_BYTE_STRING, th_2.len() as u8]);
    hash.update(th_2);

    hash.update(plaintext_2.as_slice());

    hash.finalize().into()
}

fn compute_th_4_psk(
    crypto: &mut impl CryptoTrait,
    th_3: &BytesHashLen,
    id_cred: &[u8],
    ead_3: &EadItems,
    cred_i: &[u8],
    cred_r: &[u8],
) -> BytesHashLen {
    let mut hash = crypto.sha256_start();

    hash.update([CBOR_BYTE_STRING, th_3.len() as u8]);
    hash.update(th_3);

    // PSK order: TH_3 || ID_CRED_PSK || EAD_3 || CRED_I || CRED_R
    let mut ead_buf = EdhocBuffer::<MAX_EAD_LEN>::new();
    ead_3.encode(&mut ead_buf).unwrap(); // or propagate error
    hash.update(id_cred);
    hash.update(ead_buf.as_slice());
    hash.update(cred_i);
    hash.update(cred_r);

    hash.finalize().into()
}

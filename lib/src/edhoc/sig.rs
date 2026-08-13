use lakers_shared::{decode_plaintext_2_sig, decode_plaintext_3_sig, BytesMacSig, BytesSignature};

use crate::edhoc::encode_sig_structure;

use super::{
    compute_mac_2, compute_mac_3, compute_th_3, compute_th_4, decrypt_message_3,
    encode_plaintext_2, encode_plaintext_3, encrypt_message_3, BufferMessage3, BufferPlaintext2,
    BytesHashLen, BytesP256ElemLen, ConnId, Credential, CredentialKey, CredentialTransfer,
    Crypto as CryptoTrait, DecodedMessage2, EDHOCError, EadItems, IdCred, ParsedMessage2Details,
    ParsedMessage3, PreparedMessage2, PreparedMessage3, ProcessedM2, ProcessedM2MethodSpecifics,
    ProcessingM2, ProcessingM2MethodSpecifics, ProcessingM3, ProcessingM3MethodSpecifics, Th4Input,
    VerifiedMessage2, VerifiedMessage3, WaitM3, WaitM3MethodSpecifics,
};

pub(crate) fn r_prepare_message_2_sig(
    crypto: &mut impl CryptoTrait,
    cred_r: Credential,
    r: &BytesP256ElemLen,
    c_r: ConnId,
    cred_transfer: CredentialTransfer,
    ead_2: &EadItems,
    th_2: &BytesHashLen,
    prk_2e: &BytesHashLen,
) -> Result<PreparedMessage2, EDHOCError> {
    // no static ECDH: PRK_3e2m is PRK_2e directly
    let prk_3e2m = *prk_2e;

    let id_cred_r = match cred_transfer {
        CredentialTransfer::ByValue => cred_r.by_value()?,
        CredentialTransfer::ByReference => cred_r.by_kid()?,
    };

    // compute MAC_2 (hash-length, to be signed rather than sent directly)
    let mac_2: BytesMacSig = compute_mac_2(
        crypto,
        &prk_3e2m,
        c_r,
        id_cred_r.as_full_value(),
        cred_r.bytes.as_slice(),
        th_2,
        ead_2,
    );

    let sig_structure = encode_sig_structure(
        id_cred_r.as_full_value(),
        th_2,
        cred_r.bytes.as_slice(),
        ead_2,
        &mac_2,
    )?;

    let signature_2 = crypto.p256_ecdsa_sign(r, sig_structure.as_slice())?;

    // compute ciphertext_2
    let plaintext_2 = encode_plaintext_2(
        c_r,
        Some((id_cred_r.as_encoded_value(), &signature_2.into())),
        ead_2,
    )?;

    let th_3 = compute_th_3(crypto, th_2, &plaintext_2, Some(cred_r.bytes.as_slice()));

    Ok(PreparedMessage2 {
        plaintext_2,
        prk_3e2m,
        th_3,
        method_specifics: WaitM3MethodSpecifics::Signature {},
    })
}

pub(crate) fn r_parse_message_3_sig(
    state: &WaitM3,
    crypto: &mut impl CryptoTrait,
    message_3: &BufferMessage3,
) -> Result<ParsedMessage3, EDHOCError> {
    let plaintext_3 = decrypt_message_3(crypto, &state.prk_3e2m, &state.th_3, message_3, None)?;

    let (id_cred_i, signature_3, ead_3) = decode_plaintext_3_sig(&plaintext_3)?;
    Ok(ParsedMessage3 {
        method_specifics: ProcessingM3MethodSpecifics::Signature {
            signature_3,
            id_cred_i: id_cred_i.clone(),
        },
        id_cred: id_cred_i,
        plaintext_3,
        ead_3,
    })
}

pub(crate) fn r_verify_message_3_sig(
    state: &ProcessingM3,
    crypto: &mut impl CryptoTrait,
    valid_cred_i: Credential,
    signature_3: &BytesSignature,
    id_cred_i: &IdCred,
) -> Result<VerifiedMessage3, EDHOCError> {
    let public_key = match valid_cred_i.key {
        CredentialKey::EC2Compact(public_key) => public_key,
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let prk_4e3m = state.prk_3e2m;

    let mac_3: BytesMacSig = compute_mac_3(
        crypto,
        &prk_4e3m,
        &state.th_3,
        id_cred_i.as_full_value(),
        valid_cred_i.bytes.as_slice(),
        &state.ead_3,
    );

    let sig_structure = encode_sig_structure(
        id_cred_i.as_full_value(),
        &state.th_3,
        valid_cred_i.bytes.as_slice(),
        &state.ead_3,
        &mac_3,
    )?;

    let verified = crypto
        .p256_ecdsa_verify(&public_key, sig_structure.as_slice(), signature_3)
        .unwrap_or(false);

    if verified {
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

pub(crate) fn i_parse_message_2_sig(
    plaintext_2: &BufferPlaintext2,
) -> Result<DecodedMessage2, EDHOCError> {
    let (c_r, id_cred_r, signature_2, ead_2) = decode_plaintext_2_sig(plaintext_2)?;
    Ok(DecodedMessage2 {
        method_specifics: ProcessingM2MethodSpecifics::Signature {
            signature_2,
            id_cred_r: id_cred_r.clone(),
        },
        c_r,
        parsed_details: ParsedMessage2Details::Signature { id_cred_r },
        ead_2,
    })
}

pub(crate) fn i_verify_message_2_sig(
    state: &ProcessingM2,
    crypto: &mut impl CryptoTrait,
    valid_cred_r: Credential,
    i: BytesP256ElemLen,
) -> Result<VerifiedMessage2, EDHOCError> {
    let public_key = match valid_cred_r.key {
        CredentialKey::EC2Compact(public_key) => public_key,
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    let (id_cred_r, signature_2) = match &state.method_specifics {
        ProcessingM2MethodSpecifics::Signature {
            id_cred_r,
            signature_2,
        } => (id_cred_r, signature_2),
        // FIXME: the error is not accurate. It is a lack of agreement between peers.
        _ => return Err(EDHOCError::UnsupportedMethod),
    };

    // no static ECDH: PRK_3e2m is PRK_2e directly
    let prk_3e2m = state.prk_2e;

    let mac_2: BytesMacSig = compute_mac_2(
        crypto,
        &prk_3e2m,
        state.c_r,
        id_cred_r.as_full_value(),
        valid_cred_r.bytes.as_slice(),
        &state.th_2,
        &state.ead_2,
    );

    let sig_structure = encode_sig_structure(
        id_cred_r.as_full_value(),
        &state.th_2,
        valid_cred_r.bytes.as_slice(),
        &state.ead_2,
        &mac_2,
    )?;

    let verified = crypto
        .p256_ecdsa_verify(&public_key, sig_structure.as_slice(), signature_2)
        .unwrap_or(false);

    if verified {
        let th_3 = compute_th_3(
            crypto,
            &state.th_2,
            &state.plaintext_2,
            Some(valid_cred_r.bytes.as_slice()),
        );
        // no static ECDH: PRK_4e3m is PRK_3e2m directly
        let prk_4e3m = prk_3e2m;

        Ok(VerifiedMessage2 {
            // the initiator's signing key is needed again when producing Signature_or_MAC_3
            method_specifics: ProcessedM2MethodSpecifics::Signature { i },
            // method_specifics: ProcessedM2MethodSpecifics::SigSig { i: i.clone() },
            prk_3e2m,
            prk_4e3m,
            th_3,
        })
    } else {
        Err(EDHOCError::MacVerificationFailed)
    }
}

pub(crate) fn i_prepare_message_3_sig(
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

    let ProcessedM2MethodSpecifics::Signature { i } = &state.method_specifics else {
        return Err(EDHOCError::UnsupportedMethod);
    };

    let mac_3: BytesMacSig = compute_mac_3(
        crypto,
        &state.prk_4e3m,
        &state.th_3,
        id_cred_i.as_full_value(),
        cred_i.bytes.as_slice(),
        ead_3,
    );

    let sig_structure = encode_sig_structure(
        id_cred_i.as_full_value(),
        &state.th_3,
        cred_i.bytes.as_slice(),
        ead_3,
        &mac_3,
    )?;
    let signature_3 = crypto.p256_ecdsa_sign(i, sig_structure.as_slice())?;

    let plaintext_3 = encode_plaintext_3(
        Some((id_cred_i.as_encoded_value(), &signature_3.into())),
        ead_3,
    )?;
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

use super::*;

pub type BufferCred = EdhocBuffer<192>; // arbitrary size
pub type BufferKid = EdhocBuffer<16>; // variable size, up to 16 bytes
pub type BufferIdCred = EdhocBuffer<192>; // variable size, can contain either the contents of a BufferCred or a BufferKid
pub type BytesKeyAES128 = [u8; 16];

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct BytesKeyEC2(BytesP256ElemLen);

impl TryFrom<BytesP256ElemLen> for BytesKeyEC2 {
    type Error = EDHOCError;

    fn try_from(value: BytesP256ElemLen) -> Result<Self, Self::Error> {
        // Not performing any validation yet
        Ok(Self(value))
    }
}

// This is convenient in particular while transitioning away from `pub type BytesKeyEC2 = [u8;
// 32]`, because try_into was a common way to get it.
impl TryFrom<&[u8]> for BytesKeyEC2 {
    type Error = EDHOCError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let slice: BytesP256ElemLen = value.try_into().map_err(|_| EDHOCError::ParsingError)?;
        slice.try_into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum CredentialKey {
    Symmetric(BytesKeyAES128),
    EC2Compact(BytesKeyEC2),
    // Add other key types as needed
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum CredentialType {
    CCS,
    #[allow(non_camel_case_types)]
    CCS_PSK,
    // Add other credential types as needed
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IdCredType {
    KID = 4,
    KCCS = 14,
}

impl From<u8> for IdCredType {
    fn from(value: u8) -> Self {
        match value {
            4 => IdCredType::KID,
            14 => IdCredType::KCCS,
            _ => panic!("Invalid IdCredType"),
        }
    }
}

/// A value of ID_CRED_x: a credential identifier.
///
/// Possible values include key IDs, credentials by value and others.
///
/// ```rust
/// # use hexlit::hex;
/// # use lakers_shared::IdCred;
/// let short_kid = IdCred::from_encoded_value(&hex!("17")).unwrap(); // 23
/// assert_eq!(short_kid.as_full_value(), &hex!("a1044117")); // {4: h'17'}
/// let long_kid = IdCred::from_encoded_value(&hex!("43616263")).unwrap(); // 'abc'
/// assert_eq!(long_kid.as_full_value(), &hex!("a10443616263")); // {4: 'abc'}
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct IdCred {
    /// The value is always stored in the ID_CRED_x form as a serialized one-element dictionary;
    /// while this technically wastes two bytes, it has the convenient property of having the full
    /// value available as a slice.
    pub bytes: BufferIdCred, // variable size, can contain either the contents of a BufferCred or a BufferKid
}

impl IdCred {
    pub fn new() -> Self {
        Self {
            bytes: BufferIdCred::new(),
        }
    }

    pub fn from_full_value(value: &[u8]) -> Result<Self, EDHOCError> {
        Ok(Self {
            bytes: BufferIdCred::new_from_slice(value)
                .map_err(|_| EDHOCError::CredentialTooLongError)?,
        })
    }

    /// Instantiate an IdCred from an encoded value.
    pub fn from_encoded_value(value: &[u8]) -> Result<Self, EDHOCError> {
        // This would be idiomatic as a match statement.
        // Workaround-For: https://github.com/hacspec/hax/issues/804

        let bytes = if value.len() == 1 && Self::bstr_representable_as_int(value[0]) {
            // kid that has been encoded as CBOR integer
            BufferIdCred::new_from_slice(&[0xa1, KID_LABEL, 0x41, value[0]])
                .map_err(|_| EDHOCError::CredentialTooLongError)? // TODO: how to avoid map_err overuse?
        } else if value.len() >= 1 && value[0] >= 0x40 && value[0] <= 0x57 {
            // kid that has been encoded as CBOR byte string; supporting up to 23 long because
            // those are easy
            let tail = &value[1..];
            if tail.len() == 1 && Self::bstr_representable_as_int(tail[0]) {
                // We require precise encoding
                return Err(EDHOCError::ParsingError);
            }
            if usize::from(value[0] - 0x40) != tail.len() {
                // Missing or trailing bytes. This is impossible when called from within Lakers
                // where the value is a `.any_as_encoded()`.
                return Err(EDHOCError::ParsingError);
            }
            let mut bytes = BufferIdCred::new_from_slice(&[0xa1, KID_LABEL])
                .map_err(|_| EDHOCError::CredentialTooLongError)?;
            bytes
                .extend_from_slice(value)
                .map_err(|_| EDHOCError::CredentialTooLongError)?;
            bytes
        } else if value.len() > 2 && value[..2] == [0xa1, KCCS_LABEL] {
            // CCS by value
            BufferIdCred::new_from_slice(value).map_err(|_| EDHOCError::CredentialTooLongError)?
        } else {
            return Err(EDHOCError::ParsingError);
        };

        Ok(Self { bytes })
    }

    /// View the full value of the ID_CRED_x: the CBOR encoding of a 1-element CBOR map
    ///
    /// This is the value that is used when ID_CRED_x has no impact on message size, see RFC 9528 Section 3.5.3.2.
    pub fn as_full_value(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// View the value as encoded in the ID_CRED_x position of plaintext_2 and plaintext_3.
    ///
    /// Note that this is NOT doing CBOR encoding, it is rather performing (when applicable)
    /// the compact encoding of ID_CRED fields.
    /// This style of encoding is used when ID_CRED_x has an impact on message size.
    pub fn as_encoded_value(&self) -> &[u8] {
        // This would be idiomatic as a match statement.
        // Workaround-For: https://github.com/hacspec/hax/issues/804
        if self.bytes.len() == 4
            && self.bytes.as_slice()[..3] == [0xa1, KID_LABEL, 0x41]
            && (self.bytes[3] >> 5) < 2
            && (self.bytes[3] & 0x1f) < 24
        {
            &self.bytes.as_slice()[3..]
        } else if self.bytes.len() > 2 && self.bytes.as_slice()[..2] == [0xa1, KID_LABEL] {
            &self.bytes.as_slice()[2..]
        } else {
            self.bytes.as_slice()
        }
    }

    pub fn reference_only(&self) -> bool {
        [IdCredType::KID].contains(&self.item_type())
    }

    pub fn item_type(&self) -> IdCredType {
        self.bytes.as_slice()[1].into()
    }

    pub fn get_ccs(&self) -> Option<Credential> {
        if self.item_type() == IdCredType::KCCS {
            Credential::parse_ccs(&self.bytes.as_slice()[2..]).ok()
        } else {
            None
        }
    }

    fn bstr_representable_as_int(value: u8) -> bool {
        (0x0..=0x17).contains(&value) || (0x20..=0x37).contains(&value)
    }
}

/// A credential for use in EDHOC.
///
/// For now supports CCS credentials only.
/// Experimental support for CCS_PSK credentials is also available.
// TODO: add back support for C and Python bindings
#[cfg_attr(feature = "python-bindings", pyclass)]
#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct Credential {
    /// Original bytes of the credential, CBOR-encoded
    ///
    /// If the credential is a CCS, it contains an encoded CBOR map containnig
    /// a COSE_Key in a cnf claim, see RFC 9528 Section 3.5.2.
    pub bytes: BufferCred,
    pub key: CredentialKey,
    pub kid: Option<BufferKid>, // other types of identifiers can be added, such as `pub x5t: Option<BytesX5T>`
    pub cred_type: CredentialType,
}

impl Credential {
    /// Creates a new CCS credential with the given bytes and public key
    pub fn new_ccs(bytes: BufferCred, public_key: BytesKeyEC2) -> Self {
        Self {
            bytes,
            key: CredentialKey::EC2Compact(public_key),
            kid: None,
            cred_type: CredentialType::CCS,
        }
    }

    /// Creates a new CCS credential with the given bytes and a pre-shared key
    ///
    /// NOTE: For now this is only useful for the experimental PSK method.
    pub fn new_ccs_symmetric(bytes: BufferCred, symmetric_key: BytesKeyAES128) -> Self {
        Self {
            bytes,
            key: CredentialKey::Symmetric(symmetric_key),
            kid: None,
            cred_type: CredentialType::CCS_PSK,
        }
    }

    pub fn with_kid(self, kid: BufferKid) -> Self {
        Self {
            kid: Some(kid),
            ..self
        }
    }

    pub fn public_key(&self) -> Option<BytesKeyEC2> {
        match self.key {
            CredentialKey::EC2Compact(key) => Some(key),
            _ => None,
        }
    }

    /// Parse a CCS style credential.
    ///
    /// If the given value matches the shape lakers expects of a CCS, i.e. credentials from RFC9529,
    /// its public key and key ID are extracted into a full credential.
    pub fn parse_ccs(value: &[u8]) -> Result<Self, EDHOCError> {
        let mut decoder = CBORDecoder::new(value);
        let mut x_kid = None;
        for _ in 0..decoder.map()? {
            match decoder.u8()? {
                // subject: ignored
                2 => {
                    let _subject = decoder.str()?;
                }
                // cnf
                8 => {
                    if decoder.map()? != 1 {
                        // cnf is always single-item'd
                        return Err(EDHOCError::ParsingError);
                    }

                    if decoder.u8()? != 1 {
                        // Unexpected cnf
                        return Err(EDHOCError::ParsingError);
                    }

                    x_kid = Some(Self::parse_cosekey(&mut decoder)?);
                }
                _ => {
                    return Err(EDHOCError::ParsingError);
                }
            }
        }

        let Some((x, kid)) = x_kid else {
            // Missing critical component
            return Err(EDHOCError::ParsingError);
        };

        if !decoder.finished() {
            return Err(EDHOCError::ParsingError);
        }

        Ok(Self {
            bytes: BufferCred::new_from_slice(value).map_err(|_| EDHOCError::ParsingError)?,
            key: x,
            kid,
            cred_type: CredentialType::CCS,
        })
    }

    /// Parse a CCS style credential, but the key is a symmetric key.
    ///
    /// NOTE: For now this is only useful for the experimental PSK method.
    pub fn parse_ccs_symmetric(value: &[u8]) -> Result<Self, EDHOCError> {
        const CCS_PREFIX_LEN: usize = 3;
        const CNF_AND_COSE_KEY_PREFIX_LEN: usize = 8;
        const COSE_KEY_FIRST_ITEMS_LEN: usize = 3; //COSE for symmetric key
        const SYMMETRIC_KEY_LEN: usize = 16; // Assuming a 128-bit symmetric key

        if value.len()
            < CCS_PREFIX_LEN
                + 1
                + CNF_AND_COSE_KEY_PREFIX_LEN
                + COSE_KEY_FIRST_ITEMS_LEN
                + SYMMETRIC_KEY_LEN
        {
            Err(EDHOCError::ParsingError)
        } else {
            let subject_len = CBORDecoder::info_of(value[2]) as usize;

            let id_cred_offset: usize = CCS_PREFIX_LEN
                .checked_add(subject_len)
                .and_then(|x| x.checked_add(CNF_AND_COSE_KEY_PREFIX_LEN))
                .ok_or(EDHOCError::ParsingError)?;

            let symmetric_key_offset: usize = id_cred_offset
                .checked_add(COSE_KEY_FIRST_ITEMS_LEN)
                .ok_or(EDHOCError::ParsingError)?;

            if symmetric_key_offset
                .checked_add(SYMMETRIC_KEY_LEN)
                .map_or(false, |end| end <= value.len())
            {
                let symmetric_key: [u8; SYMMETRIC_KEY_LEN] = value
                    [symmetric_key_offset..symmetric_key_offset + SYMMETRIC_KEY_LEN]
                    .try_into()
                    .map_err(|_| EDHOCError::ParsingError)?;

                let kid = value[id_cred_offset];

                Ok(Self {
                    bytes: BufferCred::new_from_slice(value)
                        .map_err(|_| EDHOCError::ParsingError)?,
                    key: CredentialKey::Symmetric(symmetric_key),
                    kid: Some(BufferKid::new_from_slice(&[kid]).unwrap()),
                    cred_type: CredentialType::CCS_PSK,
                })
            } else {
                Err(EDHOCError::ParsingError)
            }
        }
    }

    /// Parse a COSE Key, accepting only understood fields.
    ///
    /// This takes a decoder rather than a slice because this enables a naked decoder to assert that
    /// the decoder is done, and others to continue.
    ///
    /// This function does not try to require deterministic encoding, as that is not exposed by the
    /// decoder. (Adding it would be possible, but would not just mean asserting monotony, but also
    /// requiring it integer encodings etc).
    fn parse_cosekey<'data>(
        decoder: &mut CBORDecoder<'data>,
    ) -> Result<(CredentialKey, Option<BufferKid>), EDHOCError> {
        let items = decoder.map()?;
        let mut x = None;
        let mut kid = None;
        for _ in 0..items {
            match decoder.i8()? {
                // kty: EC2
                1 => {
                    if decoder.u8()? != 2 {
                        return Err(EDHOCError::ParsingError);
                    }
                }
                // kid: bytes. Note that this is always a byte string, even if in other places it's used
                // with integer compression.
                2 => {
                    kid = Some(
                        BufferKid::new_from_slice(decoder.bytes()?)
                            // Could be too long
                            .map_err(|_| EDHOCError::ParsingError)?,
                    );
                }
                // crv: p-256
                -1 => {
                    if decoder.u8()? != 1 {
                        return Err(EDHOCError::ParsingError);
                    }
                }
                // x
                -2 => {
                    x = Some(CredentialKey::EC2Compact(
                        decoder
                            .bytes()?
                            // Wrong length
                            .try_into()
                            .map_err(|_| EDHOCError::ParsingError)?,
                    ));
                }
                // y
                -3 => {
                    let _ = decoder.bytes()?;
                }
                _ => {
                    return Err(EDHOCError::ParsingError);
                }
            }
        }
        Ok((x.ok_or(EDHOCError::ParsingError)?, kid))
    }

    /// Dress a naked COSE_Key as a CCS by prepending 0xA108A101 as specified in Section 3.5.2 of
    /// RFC9528
    ///
    ///
    /// # Usage example
    ///
    /// ```
    /// # use hexlit::hex;
    /// let key = hex!("a301022001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff");
    /// let ccs = lakers_shared::Credential::parse_and_dress_naked_cosekey(&key).unwrap();
    /// // The key bytes that are part of the input
    /// assert!(ccs.public_key().unwrap().as_slice().starts_with(&hex!("bac5b1")));
    /// // This particular key does not contain a KID
    /// assert!(ccs.kid.is_none());
    /// // This is true for all dressed naked COSE keys
    /// assert!(ccs.bytes.as_slice().starts_with(&hex!("a108a101")));
    /// ```
    pub fn parse_and_dress_naked_cosekey(cosekey: &[u8]) -> Result<Self, EDHOCError> {
        let mut decoder = CBORDecoder::new(cosekey);
        let (key, kid) = Self::parse_cosekey(&mut decoder)?;
        if !decoder.finished() {
            return Err(EDHOCError::ParsingError);
        }
        let mut bytes = BufferCred::new();
        bytes
            .extend_from_slice(&[0xa1, 0x08, 0xa1, 0x01])
            .expect("Minimal size fits in the buffer");
        bytes
            .extend_from_slice(cosekey)
            .map_err(|_| EDHOCError::CredentialTooLongError)?;
        Ok(Self {
            bytes,
            key,
            kid,
            cred_type: CredentialType::CCS,
        })
    }

    /// Returns a COSE_Header map with a single entry representing a credential by value.
    ///
    /// For example, if the credential is a CCS:
    ///   { /kccs/ 14: bytes }
    pub fn by_value(&self) -> Result<IdCred, EDHOCError> {
        match self.cred_type {
            CredentialType::CCS => {
                let mut id_cred = IdCred::new();
                id_cred
                    .bytes
                    .extend_from_slice(&[CBOR_MAJOR_MAP + 1, KCCS_LABEL])
                    .map_err(|_| EDHOCError::CredentialTooLongError)?;
                id_cred
                    .bytes
                    .extend_from_slice(self.bytes.as_slice())
                    .unwrap();
                Ok(id_cred)
            }
            // if we could encode a message along the error below,
            // it would be this: "Symmetric keys cannot be sent by value"
            CredentialType::CCS_PSK => Err(EDHOCError::UnexpectedCredential),
        }
    }

    /// Returns a COSE_Header map with a single entry representing a credential by reference.
    ///
    /// For example, if the reference is a kid:
    ///   { /kid/ 4: kid }
    ///
    /// TODO: accept a parameter to specify the type of reference, e.g. kid, x5t, etc.
    pub fn by_kid(&self) -> Result<IdCred, EDHOCError> {
        let Some(kid) = self.kid.as_ref() else {
            return Err(EDHOCError::MissingIdentity);
        };
        let mut id_cred = IdCred::new();
        id_cred
            .bytes
            .extend_from_slice(&[
                CBOR_MAJOR_MAP + 1,
                KID_LABEL,
                CBOR_MAJOR_BYTE_STRING | kid.len() as u8,
            ])
            .map_err(|_| EDHOCError::CredentialTooLongError)?;
        id_cred.bytes.extend_from_slice(kid.as_slice()).unwrap();
        Ok(id_cred)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hexlit::hex;
    use rstest::rstest;

    const CRED_TV: &[u8] = &hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const G_A_TV: &[u8] = &hex!("BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F0");
    const ID_CRED_BY_REF_TV: &[u8] = &hex!("a1044132");
    const ID_CRED_BY_VALUE_TV: &[u8] = &hex!("A10EA2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
    const KID_VALUE_TV: &[u8] = &hex!("32");

    #[test]
    fn test_new_cred_ccs() {
        let cred = Credential::new_ccs(CRED_TV.try_into().unwrap(), G_A_TV.try_into().unwrap());
        assert_eq!(cred.bytes.as_slice(), CRED_TV);
    }

    #[test]
    fn test_cred_ccs_by_value_or_reference() {
        let cred = Credential::new_ccs(CRED_TV.try_into().unwrap(), G_A_TV.try_into().unwrap())
            .with_kid(KID_VALUE_TV.try_into().unwrap());
        let id_cred = cred.by_value().unwrap();
        assert_eq!(id_cred.bytes.as_slice(), ID_CRED_BY_VALUE_TV);
        assert_eq!(id_cred.item_type(), IdCredType::KCCS);
        let id_cred = cred.by_kid().unwrap();
        assert_eq!(id_cred.bytes.as_slice(), ID_CRED_BY_REF_TV);
        assert_eq!(id_cred.item_type(), IdCredType::KID);
    }

    #[test]
    fn test_parse_ccs() {
        let cred = Credential::parse_ccs(CRED_TV).unwrap();
        assert_eq!(cred.bytes.as_slice(), CRED_TV);
        assert_eq!(
            cred.key,
            CredentialKey::EC2Compact(G_A_TV.try_into().unwrap())
        );
        assert_eq!(cred.kid.unwrap().as_slice(), KID_VALUE_TV);
        assert_eq!(cred.cred_type, CredentialType::CCS);

        // A CCS without a subject.
        let cred_no_sub = hex!("a108a101a401022001215820f5aeba08b599754ba16f5db80feafdf91e90a5a7ccb2e83178adb51b8c68ea9522582097e7a3fdd70a3a7c0a5f9578c6e4e96d8bc55f6edd0ff64f1caeaac19d37b67d");
        // A CCS without a KID.
        let cred_no_kid = hex!("a20263666f6f08a101a401022001215820f5aeba08b599754ba16f5db80feafdf91e90a5a7ccb2e83178adb51b8c68ea9522582097e7a3fdd70a3a7c0a5f9578c6e4e96d8bc55f6edd0ff64f1caeaac19d37b67d");
        for cred in [cred_no_sub.as_slice(), cred_no_kid.as_slice()] {
            let CredentialKey::EC2Compact(key) = Credential::parse_ccs(&cred).unwrap().key else {
                panic!("CCS contains unexpected key type.");
            };
            assert!(key.as_slice().starts_with(&hex!("f5aeba08b59975")));
        }

        // A CCS with an issuer.
        // It's OK if this starts working in future, but then its public key needs to start with
        // F5AEBA08B599754 (it'd be clearly wrong if this produced an Ok value with a different
        // public key).
        let cred_exotic = hex!("a2016008a101a401022001215820f5aeba08b599754ba16f5db80feafdf91e90a5a7ccb2e83178adb51b8c68ea9522582097e7a3fdd70a3a7c0a5f9578c6e4e96d8bc55f6edd0ff64f1caeaac19d37b67d");
        Credential::parse_ccs(&cred_exotic).unwrap_err();
    }

    #[rstest]
    #[case(&[0x0D], &[0xa1, 0x04, 0x41, 0x0D])] // two optimizations: omit kid label and encode as CBOR integer
    #[case(&[0x41, 0x18], &[0xa1, 0x04, 0x41, 0x18])] // one optimization: omit kid label
    #[case(ID_CRED_BY_VALUE_TV, ID_CRED_BY_VALUE_TV)] // regular credential by value
    fn test_id_cred_from_encoded_plaintext(#[case] input: &[u8], #[case] expected: &[u8]) {
        assert_eq!(
            IdCred::from_encoded_value(input).unwrap().as_full_value(),
            expected
        );
    }
}

#[cfg(test)]
mod test_experimental {
    use super::*;
    use hexlit::hex;

    const CRED_PSK: &[u8] =
        &hex!("A202686D79646F74626F7408A101A30104024132205050930FF462A77A3540CF546325DEA214");
    const K: &[u8] = &hex!("50930FF462A77A3540CF546325DEA214");
    const KID_VALUE_PSK: &[u8] = &hex!("32");

    #[test]
    fn test_cred_ccs_symmetric_by_value_or_reference() {
        // TODO
    }

    #[test]
    fn test_new_cred_ccs_symmetric() {
        let cred =
            Credential::new_ccs_symmetric(CRED_PSK.try_into().unwrap(), K.try_into().unwrap());
        assert_eq!(cred.bytes.as_slice(), CRED_PSK);
    }

    #[test]
    fn test_parse_ccs_symmetric() {
        let cred = Credential::parse_ccs_symmetric(CRED_PSK).unwrap();
        assert_eq!(cred.bytes.as_slice(), CRED_PSK);
        assert_eq!(cred.key, CredentialKey::Symmetric(K.try_into().unwrap()));
        assert_eq!(cred.kid.unwrap().as_slice(), KID_VALUE_PSK);
        assert_eq!(cred.cred_type, CredentialType::CCS_PSK);
    }
}

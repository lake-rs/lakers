#![no_std]

pub use cbor::*;
pub use cbor_decoder::*;
pub use edhoc_parser::*;
pub use helpers::*;

// ---- constants and types

// TODO: find a way to configure the buffer size
// need 128 to handle EAD fields, and 192 for the EAD_1 voucher
pub const MAX_MESSAGE_SIZE_LEN: usize = 128 + 64;

pub const ID_CRED_LEN: usize = 4;
pub const SUITES_LEN: usize = 9;
pub const SUPPORTED_SUITES_LEN: usize = 1;
pub const EDHOC_METHOD: u8 = 3u8; // stat-stat is the only supported method
pub const P256_ELEM_LEN: usize = 32;
pub const SHA256_DIGEST_LEN: usize = 32;
pub const AES_CCM_KEY_LEN: usize = 16;
pub const AES_CCM_IV_LEN: usize = 13;
pub const AES_CCM_TAG_LEN: usize = 8;
pub const MAC_LENGTH: usize = 8; // used for EAD Zeroconf
pub const MAC_LENGTH_2: usize = MAC_LENGTH;
pub const MAC_LENGTH_3: usize = MAC_LENGTH_2;
pub const ENCODED_VOUCHER_LEN: usize = 1 + MAC_LENGTH; // 1 byte for the length of the bstr-encoded voucher

// maximum supported length of connection identifier for R
pub const MAX_KDF_CONTEXT_LEN: usize = 150;
pub const MAX_KDF_LABEL_LEN: usize = 15; // for "KEYSTREAM_2"
pub const MAX_BUFFER_LEN: usize = 256;
pub const CBOR_BYTE_STRING: u8 = 0x58u8;
pub const CBOR_TEXT_STRING: u8 = 0x78u8;
pub const CBOR_UINT_1BYTE: u8 = 0x18u8;
pub const CBOR_NEG_INT_1BYTE_START: u8 = 0x20u8;
pub const CBOR_NEG_INT_1BYTE_END: u8 = 0x37u8;
pub const CBOR_UINT_1BYTE_START: u8 = 0x0u8;
pub const CBOR_UINT_1BYTE_END: u8 = 0x17u8;
pub const CBOR_MAJOR_TEXT_STRING: u8 = 0x60u8;
pub const CBOR_MAJOR_BYTE_STRING: u8 = 0x40u8;
pub const CBOR_MAJOR_BYTE_STRING_MAX: u8 = 0x57u8;
pub const CBOR_MAJOR_ARRAY: u8 = 0x80u8;
pub const CBOR_MAJOR_ARRAY_MAX: u8 = 0x97u8;
pub const MAX_INFO_LEN: usize = 2 + SHA256_DIGEST_LEN + // 32-byte digest as bstr
				            1 + MAX_KDF_LABEL_LEN +     // label <24 bytes as tstr
						    1 + MAX_KDF_CONTEXT_LEN +   // context <24 bytes as bstr
						    1; // length as u8

pub const ENC_STRUCTURE_LEN: usize = 8 + 5 + SHA256_DIGEST_LEN; // 8 for ENCRYPT0

pub const MAX_EAD_SIZE_LEN: usize = 64;
pub const EAD_ZEROCONF_LABEL: u8 = 0x1; // NOTE: in lake-authz-draft-02 it is still TBD1
pub const EAD_ZEROCONF_INFO_K_1_LABEL: u8 = 0x0;
pub const EAD_ZEROCONF_INFO_IV_1_LABEL: u8 = 0x1;
pub const EAD_ZEROCONF_ENC_STRUCTURE_LEN: usize = 2 + 8 + 3;

pub type BytesEad2 = [u8; 0];
pub type BytesIdCred = [u8; ID_CRED_LEN];

pub type BytesSuites = [u8; SUITES_LEN];
pub type BytesSupportedSuites = [u8; SUPPORTED_SUITES_LEN];
pub const EDHOC_SUITES: BytesSuites = [0, 1, 2, 3, 4, 5, 6, 24, 25]; // all but private cipher suites
pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites = [0x2u8];

pub type Bytes8 = [u8; 8];
pub type BytesCcmKeyLen = [u8; AES_CCM_KEY_LEN];
pub type BytesCcmIvLen = [u8; AES_CCM_IV_LEN];
pub type BufferPlaintext2 = EdhocMessageBuffer;
pub type BufferPlaintext3 = EdhocMessageBuffer;
pub type BytesMac2 = [u8; MAC_LENGTH_2];
pub type BytesMac3 = [u8; MAC_LENGTH_3];
pub type BufferMessage1 = EdhocMessageBuffer;
pub type BufferMessage3 = EdhocMessageBuffer;
pub type BufferCiphertext2 = EdhocMessageBuffer;
pub type BufferCiphertext3 = EdhocMessageBuffer;
pub type BytesHashLen = [u8; SHA256_DIGEST_LEN];
pub type BytesP256ElemLen = [u8; P256_ELEM_LEN];
pub type BufferMessage2 = EdhocMessageBuffer;
pub type BytesMaxBuffer = [u8; MAX_BUFFER_LEN];
pub type BytesMaxContextBuffer = [u8; MAX_KDF_CONTEXT_LEN];
pub type BytesMaxInfoBuffer = [u8; MAX_INFO_LEN];
pub type BytesMaxLabelBuffeer = [u8; MAX_KDF_LABEL_LEN];
pub type BytesEncStructureLen = [u8; ENC_STRUCTURE_LEN];

pub type BytesMac = [u8; MAC_LENGTH];
pub type BytesEncodedVoucher = [u8; ENCODED_VOUCHER_LEN];
pub type EADMessageBuffer = EdhocMessageBuffer; // TODO: make it of size MAX_EAD_SIZE_LEN

#[repr(C)]
#[derive(Default, PartialEq, Copy, Clone, Debug)]
pub enum EDHOCState {
    #[default]
    Start = 0, // initiator and responder
    WaitMessage2 = 1,      // initiator
    ProcessedMessage2 = 2, // initiator
    ProcessedMessage1 = 3, // responder
    WaitMessage3 = 4,      // responder
    Completed = 5,         // initiator and responder
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum EDHOCError {
    Success = 0,
    UnknownPeer = 1,
    MacVerificationFailed = 2,
    UnsupportedMethod = 3,
    UnsupportedCipherSuite = 4,
    ParsingError = 5,
    WrongState = 6,
    EADError = 7,
    UnknownError = 8,
}

#[repr(C)]
#[derive(Default, Copy, Clone, Debug)]
pub struct State(
    pub EDHOCState,
    pub BytesP256ElemLen, // x or y, ephemeral private key of myself
    pub u8,               // c_i, connection identifier chosen by the initiator
    pub BytesP256ElemLen, // g_y or g_x, ephemeral public key of the peer
    pub BytesHashLen,     // prk_3e2m
    pub BytesHashLen,     // prk_4e3m
    pub BytesHashLen,     // prk_out
    pub BytesHashLen,     // prk_exporter
    pub BytesHashLen,     // h_message_1
    pub BytesHashLen,     // th_3
);

#[repr(C)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct EdhocMessageBuffer {
    pub content: [u8; MAX_MESSAGE_SIZE_LEN],
    pub len: usize,
}

impl Default for EdhocMessageBuffer {
    fn default() -> Self {
        EdhocMessageBuffer {
            content: [0; MAX_MESSAGE_SIZE_LEN],
            len: 0,
        }
    }
}

pub trait MessageBufferTrait {
    fn new() -> Self;
    fn as_slice<'a>(&'a self) -> &'a [u8];
    fn from_hex(hex: &str) -> Self;
}

impl MessageBufferTrait for EdhocMessageBuffer {
    fn new() -> Self {
        EdhocMessageBuffer {
            content: [0u8; MAX_MESSAGE_SIZE_LEN],
            len: 0,
        }
    }

    fn as_slice<'a>(&'a self) -> &'a [u8] {
        &self.content[0..self.len]
    }

    fn from_hex(hex: &str) -> Self {
        let mut buffer = EdhocMessageBuffer::new();
        buffer.len = hex.len() / 2;
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let chunk_str = core::str::from_utf8(chunk).unwrap();
            buffer.content[i] = u8::from_str_radix(chunk_str, 16).unwrap();
        }
        buffer
    }
}

impl TryInto<EdhocMessageBuffer> for &[u8] {
    type Error = ();

    fn try_into(self) -> Result<EdhocMessageBuffer, Self::Error> {
        if self.len() <= MAX_MESSAGE_SIZE_LEN {
            let mut buffer = [0u8; MAX_MESSAGE_SIZE_LEN];
            for i in 0..self.len() {
                buffer[i] = self[i];
            }

            Ok(EdhocMessageBuffer {
                content: buffer,
                len: self.len(),
            })
        } else {
            Err(())
        }
    }
}

#[derive(Debug)]
pub struct EADItem {
    pub label: u8,
    pub is_critical: bool,
    // TODO[ead]: have adjustable (smaller) length for this buffer
    pub value: Option<EdhocMessageBuffer>,
}

pub trait EADTrait {
    fn new() -> Self;
}

impl EADTrait for EADItem {
    fn new() -> Self {
        EADItem {
            label: 0,
            is_critical: false,
            value: None,
        }
    }
}

#[derive(Debug)]
pub enum IdCred<'a> {
    CompactKid(u8),
    FullCredential(&'a [u8]),
}

// ---- common functions

mod cbor {
    use super::*;

    /// Check for: an unsigned integer encoded as a single byte
    #[inline(always)]
    pub fn is_cbor_uint_1byte(byte: u8) -> bool {
        return byte >= CBOR_UINT_1BYTE_START && byte <= CBOR_UINT_1BYTE_END;
    }

    /// Check for: an unsigned integer encoded as two bytes
    #[inline(always)]
    pub fn is_cbor_uint_2bytes(byte: u8) -> bool {
        return byte == CBOR_UINT_1BYTE;
    }

    /// Check for: a negative integer encoded as a single byte
    #[inline(always)]
    pub fn is_cbor_neg_int_1byte(byte: u8) -> bool {
        return byte >= CBOR_NEG_INT_1BYTE_START && byte <= CBOR_NEG_INT_1BYTE_END;
    }

    /// Check for: a bstr denoted by a single byte which encodes both type and content length
    #[inline(always)]
    pub fn is_cbor_bstr_1byte_prefix(byte: u8) -> bool {
        return byte >= CBOR_MAJOR_BYTE_STRING && byte <= CBOR_MAJOR_BYTE_STRING_MAX;
    }

    /// Check for: a bstr denoted by two bytes, one for type the other for content length
    #[inline(always)]
    pub fn is_cbor_bstr_2bytes_prefix(byte: u8) -> bool {
        return byte == CBOR_BYTE_STRING;
    }

    /// Check for: a tstr denoted by two bytes, one for type the other for content length
    #[inline(always)]
    pub fn is_cbor_tstr_2bytes_prefix(byte: u8) -> bool {
        return byte == CBOR_TEXT_STRING;
    }

    /// Check for: an array denoted by a single byte which encodes both type and content length
    #[inline(always)]
    pub fn is_cbor_array_1byte_prefix(byte: u8) -> bool {
        return byte >= CBOR_MAJOR_ARRAY && byte <= CBOR_MAJOR_ARRAY_MAX;
    }
}

mod helpers {
    use super::*;

    pub fn encode_info(
        label: u8,
        context: &BytesMaxContextBuffer,
        context_len: usize,
        length: usize,
    ) -> (BytesMaxInfoBuffer, usize) {
        let mut info: BytesMaxInfoBuffer = [0x00; MAX_INFO_LEN];

        // construct info with inline cbor encoding
        info[0] = label;
        let mut info_len = if context_len < 24 {
            info[1] = context_len as u8 | CBOR_MAJOR_BYTE_STRING;
            info[2..2 + context_len].copy_from_slice(&context[..context_len]);
            2 + context_len
        } else {
            info[1] = CBOR_BYTE_STRING;
            info[2] = context_len as u8;
            info[3..3 + context_len].copy_from_slice(&context[..context_len]);
            3 + context_len
        };

        info_len = if length < 24 {
            info[info_len] = length as u8;
            info_len + 1
        } else {
            info[info_len] = CBOR_UINT_1BYTE;
            info[info_len + 1] = length as u8;
            info_len + 2
        };

        (info, info_len)
    }

    pub fn parse_cred<'a>(cred: &'a [u8]) -> Result<(BytesP256ElemLen, u8), EDHOCError> {
        // NOTE: this routine is only guaranteed to work with credentials from lake-traces
        const CCS_PREFIX_LEN: usize = 3;
        const CNF_AND_COSE_KEY_PREFIX_LEN: usize = 8;
        const COSE_KEY_FIRST_ITEMS_LEN: usize = 6;

        if cred.len()
            < 3 + CCS_PREFIX_LEN
                + 1
                + CNF_AND_COSE_KEY_PREFIX_LEN
                + COSE_KEY_FIRST_ITEMS_LEN
                + P256_ELEM_LEN
        {
            return Err(EDHOCError::ParsingError);
        }

        let subject_len = (cred[2] - CBOR_MAJOR_TEXT_STRING) as usize;
        let id_cred_offset: usize = CCS_PREFIX_LEN + subject_len + CNF_AND_COSE_KEY_PREFIX_LEN;
        let g_a_x_offset: usize = id_cred_offset + COSE_KEY_FIRST_ITEMS_LEN;

        Ok((
            cred[g_a_x_offset..g_a_x_offset + P256_ELEM_LEN]
                .try_into()
                .expect("Wrong key length"),
            cred[id_cred_offset],
        ))
    }

    pub fn get_id_cred<'a>(cred: &'a [u8]) -> BytesIdCred {
        let (_g, kid) = parse_cred(cred).unwrap();
        [0xa1, 0x04, 0x41, kid]
    }
}

#[cfg(test)]
mod test {
    use super::helpers::*;
    use hexlit::hex;

    const CRED_TV: &[u8] = &hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const G_A_TV: &[u8] = &hex!("BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F0");
    const ID_CRED_TV: &[u8] = &hex!("a1044132");

    #[test]
    fn test_parse_cred() {
        let res = parse_cred(CRED_TV);
        assert!(res.is_ok());
        let (g_a, kid) = res.unwrap();
        assert_eq!(g_a, G_A_TV);
        assert_eq!(kid, ID_CRED_TV[3]);
        assert_eq!(get_id_cred(CRED_TV), ID_CRED_TV);
    }
}

// TODO: move to own file (or even to the main crate, once EAD is extracted as an external dependency)
mod edhoc_parser {
    use super::*;

    pub fn parse_ead(buffer: &[u8]) -> Result<Option<EADItem>, EDHOCError> {
        let ead_item;
        let mut ead_value = None::<EdhocMessageBuffer>;

        // assuming label is a single byte integer (negative or positive)
        let label = match buffer.get(0) {
            Some(b) => *b,
            _ => return Err(EDHOCError::ParsingError),
        };

        let (label, is_critical) = if CBORDecoder::is_u8(label) {
            // CBOR unsigned integer (0..=23)
            (label as u8, false)
        } else if CBORDecoder::is_i8(label) {
            // CBOR negative integer (-1..=-24)
            (label - (CBOR_NEG_INT_1BYTE_START - 1), true)
        } else {
            return Err(EDHOCError::ParsingError);
        };

        if buffer.len() > 1 {
            // EAD value is present
            let slice = match buffer.get(1..buffer.len()) {
                Some(slice) => slice,
                _ => return Err(EDHOCError::ParsingError),
            };

            let mut buffer = EdhocMessageBuffer::new();
            buffer.content[..slice.len()].copy_from_slice(slice);
            buffer.len = slice.len();
            ead_value = Some(buffer);
        }
        ead_item = Some(EADItem {
            label,
            is_critical,
            value: ead_value,
        });
        Ok(ead_item)
    }

    pub fn parse_suites_i(
        mut decoder: CBORDecoder,
    ) -> Result<(BytesSuites, usize, CBORDecoder), EDHOCError> {
        let mut suites_i: BytesSuites = Default::default();
        let suites_i_len: usize;
        if let Ok(curr) = decoder.current() {
            if CBOR_UINT_1BYTE_START == CBORDecoder::type_of(curr) {
                suites_i[0] = decoder.u8()?;
                suites_i_len = 1;
                Ok((suites_i, suites_i_len, decoder))
            } else if CBOR_MAJOR_ARRAY == CBORDecoder::type_of(curr)
                && CBORDecoder::info_of(curr) >= 2
            {
                // NOTE: arrays must be at least 2 items long, otherwise the compact encoding (int) must be used
                suites_i_len = decoder.array()?;
                if suites_i_len <= suites_i.len() {
                    for i in 0..suites_i_len {
                        suites_i[i] = decoder.u8()?;
                    }
                    Ok((suites_i, suites_i_len, decoder))
                } else {
                    Err(EDHOCError::ParsingError)
                }
            } else {
                Err(EDHOCError::ParsingError)
            }
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    pub fn parse_message_1(
        rcvd_message_1: &BufferMessage1,
    ) -> Result<
        (
            u8,
            BytesSuites,
            usize,
            BytesP256ElemLen,
            u8,
            Option<EADItem>,
        ),
        EDHOCError,
    > {
        let suites_i: BytesSuites;
        let suites_i_len: usize;
        let mut g_x: BytesP256ElemLen = [0x00; P256_ELEM_LEN];

        let mut decoder = CBORDecoder::new(rcvd_message_1.as_slice());

        let method = decoder.u8()?;

        if let Ok(res) = parse_suites_i(decoder) {
            (suites_i, suites_i_len, decoder) = res;
        } else {
            return Err(EDHOCError::ParsingError);
        }

        g_x.copy_from_slice(decoder.bytes_sized(P256_ELEM_LEN)?);

        // consume c_i encoded as single-byte int (we still do not support bstr encoding)
        let c_i = decoder.int_raw()?;

        // if there is still more to parse, the rest will be the EAD_1
        if rcvd_message_1.len > decoder.position() {
            // NOTE: since the current implementation only supports one EAD handler,
            // we assume only one EAD item
            let ead_res = parse_ead(decoder.remaining_buffer()?);
            if ead_res.is_ok() {
                let ead_1 = ead_res.unwrap();
                Ok((method, suites_i, suites_i_len, g_x, c_i, ead_1))
            } else {
                Err(ead_res.unwrap_err())
            }
        } else {
            decoder.ensure_finished()?;
            Ok((method, suites_i, suites_i_len, g_x, c_i, None))
        }
    }

    pub fn parse_message_2(
        rcvd_message_2: &BufferMessage2,
    ) -> Result<(BytesP256ElemLen, BufferCiphertext2), EDHOCError> {
        // FIXME decode negative integers as well
        let mut ciphertext_2: BufferCiphertext2 = BufferCiphertext2::new();

        let mut decoder = CBORDecoder::new(rcvd_message_2.as_slice());

        // message_2 consists of 1 bstr element; this element in turn contains the concatenation of g_y and ciphertext_2
        let decoded = decoder.bytes()?;
        decoder.ensure_finished()?;

        if let Some(key) = decoded.get(0..P256_ELEM_LEN) {
            let mut g_y: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
            g_y.copy_from_slice(key);
            if let Some(c2) = decoded.get(P256_ELEM_LEN..) {
                ciphertext_2.len = c2.len(); // len - gy_len - 2
                ciphertext_2.content[..ciphertext_2.len].copy_from_slice(c2);
                Ok((g_y, ciphertext_2))
            } else {
                Err(EDHOCError::ParsingError)
            }
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    pub fn decode_plaintext_2(
        plaintext_2: &BytesMaxBuffer,
        plaintext_2_len: usize,
    ) -> Result<(u8, IdCred, BytesMac2, Option<EADItem>), EDHOCError> {
        let id_cred_r: IdCred;
        let mut mac_2: BytesMac2 = [0x00; MAC_LENGTH_2];

        let mut decoder = CBORDecoder::new(&plaintext_2[..plaintext_2_len]);

        let c_r = decoder.int_raw()?;

        // NOTE: if len of bstr is 1, it is a compact kid and therefore should have been encoded as int
        if CBOR_MAJOR_BYTE_STRING == CBORDecoder::type_of(decoder.current()?)
            && CBORDecoder::info_of(decoder.current()?) > 1
        {
            id_cred_r = IdCred::FullCredential(decoder.bytes()?);
        } else {
            id_cred_r = IdCred::CompactKid(decoder.int_raw()?);
        }

        mac_2[..].copy_from_slice(decoder.bytes_sized(MAC_LENGTH_2)?);

        // if there is still more to parse, the rest will be the EAD_2
        if plaintext_2_len > decoder.position() {
            // assume only one EAD item
            let ead_res = parse_ead(decoder.remaining_buffer()?);
            if ead_res.is_ok() {
                let ead_2 = ead_res.unwrap();
                Ok((c_r, id_cred_r, mac_2, ead_2))
            } else {
                Err(ead_res.unwrap_err())
            }
        } else {
            decoder.ensure_finished()?;
            Ok((c_r, id_cred_r, mac_2, None))
        }
    }

    pub fn decode_plaintext_3(
        plaintext_3: &BufferPlaintext3,
    ) -> Result<(IdCred, BytesMac3, Option<EADItem>), EDHOCError> {
        let mut mac_3: BytesMac3 = [0x00; MAC_LENGTH_3];
        let id_cred_i: IdCred;

        let mut decoder = CBORDecoder::new(plaintext_3.as_slice());

        // NOTE: if len of bstr is 1, then it is a compact kid and therefore should have been encoded as int
        if CBOR_MAJOR_BYTE_STRING == CBORDecoder::type_of(decoder.current()?)
            && CBORDecoder::info_of(decoder.current()?) > 1
        {
            id_cred_i = IdCred::FullCredential(decoder.bytes()?);
        } else {
            id_cred_i = IdCred::CompactKid(decoder.int_raw()?);
        }

        mac_3[..].copy_from_slice(decoder.bytes_sized(MAC_LENGTH_3)?);

        // if there is still more to parse, the rest will be the EAD_3
        if plaintext_3.len > decoder.position() {
            // assume only one EAD item
            let ead_res = parse_ead(decoder.remaining_buffer()?);
            if ead_res.is_ok() {
                let ead_3 = ead_res.unwrap();
                Ok((id_cred_i, mac_3, ead_3))
            } else {
                Err(ead_res.unwrap_err())
            }
        } else {
            decoder.ensure_finished()?;
            Ok((id_cred_i, mac_3, None))
        }
    }
}

mod cbor_decoder {
    /// Decoder inspired by the [minicbor](https://crates.io/crates/minicbor) crate.
    use super::*;

    #[derive(Debug)]
    pub enum CBORError {
        DecodingError,
    }

    impl From<CBORError> for EDHOCError {
        fn from(error: CBORError) -> Self {
            match error {
                CBORError::DecodingError => EDHOCError::ParsingError,
            }
        }
    }

    #[derive(Debug)]
    pub struct CBORDecoder<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> CBORDecoder<'a> {
        pub fn new(bytes: &'a [u8]) -> Self {
            CBORDecoder { buf: bytes, pos: 0 }
        }

        fn read(&mut self) -> Result<u8, CBORError> {
            if let Some(b) = self.buf.get(self.pos) {
                self.pos += 1;
                return Ok(*b);
            }
            Err(CBORError::DecodingError)
        }

        /// Consume and return *n* bytes starting at the current position.
        fn read_slice(&mut self, n: usize) -> Result<&'a [u8], CBORError> {
            if let Some(b) = self
                .pos
                .checked_add(n)
                .and_then(|end| self.buf.get(self.pos..end))
            {
                self.pos += n;
                return Ok(b);
            }
            Err(CBORError::DecodingError)
        }

        pub fn position(&self) -> usize {
            self.pos
        }

        pub fn finished(&self) -> bool {
            self.pos == self.buf.len()
        }

        pub fn ensure_finished(&self) -> Result<(), CBORError> {
            if self.finished() {
                Ok(())
            } else {
                Err(CBORError::DecodingError)
            }
        }

        pub fn remaining_buffer(&self) -> Result<&[u8], CBORError> {
            if let Some(buffer) = self.buf.get(self.pos..) {
                Ok(buffer)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Get the byte at the current position.
        pub fn current(&self) -> Result<u8, CBORError> {
            if let Some(b) = self.buf.get(self.pos) {
                return Ok(*b);
            }
            Err(CBORError::DecodingError)
        }

        /// Decode a `u8` value.
        pub fn u8(&mut self) -> Result<u8, CBORError> {
            match self.read()? {
                n @ 0..=0x17 => Ok(n),
                0x18 => self.read(),
                _ => Err(CBORError::DecodingError),
            }
        }

        /// Decode an `i8` value.
        pub fn i8(&mut self) -> Result<i8, CBORError> {
            match self.read()? {
                n @ 0x00..=0x17 => Ok(n as i8),
                n @ 0x20..=0x37 => Ok(-1 - (n - 0x20) as i8),
                _b => Err(CBORError::DecodingError),
            }
        }

        /// Get the raw `i8` or `u8` value.
        pub fn int_raw(&mut self) -> Result<u8, CBORError> {
            match self.read()? {
                n @ 0x00..=0x17 => Ok(n),
                n @ 0x20..=0x37 => Ok(n),
                _b => Err(CBORError::DecodingError),
            }
        }

        /// Decode a string slice.
        pub fn str(&mut self) -> Result<&'a [u8], CBORError> {
            let p = self.pos;
            let b = self.read()?;
            if CBOR_MAJOR_TEXT_STRING != Self::type_of(b) || Self::info_of(b) == 31 {
                return Err(CBORError::DecodingError);
            }
            let n = self.as_usize(Self::info_of(b))?;
            self.read_slice(n)
        }

        /// Decode a byte slice.
        pub fn bytes(&mut self) -> Result<&'a [u8], CBORError> {
            let p = self.pos;
            let b = self.read()?;
            if CBOR_MAJOR_BYTE_STRING != Self::type_of(b) || Self::info_of(b) == 31 {
                return Err(CBORError::DecodingError);
            }
            let n = self.as_usize(Self::info_of(b))?;
            self.read_slice(n)
        }

        /// Decode a byte slice of an expected size.
        pub fn bytes_sized(&mut self, expected_size: usize) -> Result<&'a [u8], CBORError> {
            let res = self.bytes()?;
            if res.len() == expected_size {
                Ok(res)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Begin decoding an array.
        pub fn array(&mut self) -> Result<usize, CBORError> {
            let p = self.pos;
            let b = self.read()?;
            if CBOR_MAJOR_ARRAY != Self::type_of(b) {
                return Err(CBORError::DecodingError);
            }
            match Self::info_of(b) {
                31 => Err(CBORError::DecodingError), // no support for unknown size arrays
                n => Ok(self.as_usize(n)?),
            }
        }

        /// Decode a `u8` value into usize.
        pub fn as_usize(&mut self, b: u8) -> Result<usize, CBORError> {
            match b {
                n @ 0..=0x17 => Ok(usize::from(n)),
                0x18 => self.read().map(usize::from),
                _ => Err(CBORError::DecodingError),
            }
        }

        /// Get the major type info of the given byte (highest 3 bits).
        pub fn type_of(b: u8) -> u8 {
            b & 0b111_00000
        }

        /// Get the additionl type info of the given byte (lowest 5 bits).
        pub fn info_of(b: u8) -> u8 {
            b & 0b000_11111
        }

        /// Check for: an unsigned integer encoded as a single byte
        pub fn is_u8(byte: u8) -> bool {
            return byte >= CBOR_UINT_1BYTE_START && byte <= CBOR_UINT_1BYTE_END;
        }

        /// Check for: a negative integer encoded as a single byte
        pub fn is_i8(byte: u8) -> bool {
            return byte >= CBOR_NEG_INT_1BYTE_START && byte <= CBOR_NEG_INT_1BYTE_END;
        }
    }
}

#[cfg(test)]
mod test_cbor_decoder {
    use super::cbor_decoder::*;

    #[test]
    fn test_cbor_decoder() {
        // CBOR sequence: 1, -1, "hi", h'fefe'
        let input = [0x01, 0x20, 0x62, 0x68, 0x69, 0x42, 0xFE, 0xFE];
        let mut decoder = CBORDecoder::new(&input);

        assert_eq!(1, decoder.u8().unwrap());
        assert_eq!(-1, decoder.i8().unwrap());
        assert_eq!([0x68, 0x69], decoder.str().unwrap()); // "hi"
        assert_eq!([0xFE, 0xFE], decoder.bytes().unwrap());
    }
}

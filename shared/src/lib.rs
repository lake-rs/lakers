//! Common data structures used by [lakers] and its dependent crates
//!
//! This crate is separate from lakers to avoid circular dependencies that would otherwise arise
//! from the pattern in which [lakers-ead] combined the main crate with variations of the
//! protocol's EAD handling. As its types will then likely move over into the main lakers crate, it
//! is recommended to use them through the public re-export there wherever possible.
//!
//! [lakers]: https://docs.rs/lakers/
//! [lakers-ead]: https://docs.rs/lakers-ead/latest/lakers_ead/
// NOTE: if there is no python-bindings feature, which will be the case for embedded builds,
//       then the crate will be no_std
#![cfg_attr(not(feature = "python-bindings"), no_std)]

pub use cbor_decoder::*;
pub use edhoc_parser::*;
pub use helpers::*;

use defmt_or_log::trace;

mod crypto;
pub use crypto::*;

mod cred;
pub use cred::*;

mod buffer;
pub use buffer::*;

pub mod consts;
pub use consts::*;

mod error;
pub use error::{EDHOCError, ErrCode};

#[cfg(feature = "python-bindings")]
use pyo3::prelude::*;
#[cfg(feature = "python-bindings")]
mod python_bindings;

/// Maximum length of a [`ConnId`] (`C_x`).
///
/// This length includes the leading CBOR encoding byte(s).
// Note that when implementing larger sizes than 24, the encoding will need to use actual CBOR
// rather than masking a known short length into a byte.
//
// When changing this, beware that it is re-implemented in cbindgen.toml
const MAX_CONNID_ENCODED_LEN: usize = if cfg!(feature = "max_connid_encoded_len_24") {
    24
} else {
    8
};

pub type BytesSuites = [u8; SUITES_LEN];
pub type BytesSupportedSuites = [u8; SUPPORTED_SUITES_LEN];
pub const EDHOC_SUITES: BytesSuites = [0, 1, 2, 3, 4, 5, 6, 24, 25]; // all but private cipher suites
pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites = [0x2u8];

pub type BytesCcmKeyLen = [u8; AES_CCM_KEY_LEN];
pub type BytesCcmIvLen = [u8; AES_CCM_IV_LEN];
pub type BufferPlaintext2 = EdhocMessageBuffer;
pub type BufferPlaintext3 = EdhocMessageBuffer;
pub type BufferPlaintext4 = EdhocMessageBuffer;
pub type BytesMac2 = [u8; MAC_LENGTH_2];
pub type BytesMac3 = [u8; MAC_LENGTH_3];
pub type BufferMessage1 = EdhocMessageBuffer;
pub type BufferMessage3 = EdhocMessageBuffer;
pub type BufferMessage4 = EdhocMessageBuffer;
pub type BufferCiphertext2 = EdhocMessageBuffer;
pub type BufferCiphertext3 = EdhocMessageBuffer;
pub type BufferCiphertext4 = EdhocMessageBuffer;
pub type BytesHashLen = [u8; SHA256_DIGEST_LEN];
pub type BytesP256ElemLen = [u8; P256_ELEM_LEN];
pub type BytesElemLenPSK = [u8; ELEM_LEN_PSK];
pub type BufferMessage2 = EdhocMessageBuffer;
/// Generic buffer type (soft-deprecated).
///
/// The use of this type is discouraged, because it contributes to this library's excessive stack
/// usage, but will need some work to get rid of, for it is used in two places:
///
/// * In functions that compute transcript hashes (eg. [`compute_th_3`]): There, it builds data up
///   to be fed into the cryptography module's SHA256 computation. That computation is streamable
///   in the underlying APIs (i.e. there is no need to build a buffer, they could be fed
///   incrementally), but the cryptography abstraction doesn't expose that.
/// * <del>As the return value of `edhoc_kdf_expand`. There, the data is taken up into some other buffer
///   or type by the caller, so the caller could provide the place to expand into as a `&mut [u8]`,
///   but likewise, our crypto API doesn't work that way.</del>
pub type BytesMaxBuffer = [u8; MAX_BUFFER_LEN];
pub type BufferContext = EdhocBuffer<MAX_KDF_CONTEXT_LEN>;
/// Buffer returned by [`encode_info`]
pub type BufferInfo = EdhocBuffer<MAX_INFO_LEN>;
/// A buffer holding a serialized COSE_Encrypt0 structure.
///
/// This is an array and not an [`EdhocBuffer`] because it always has a fixed length.
pub type BytesEncStructureLen = [u8; ENC_STRUCTURE_LEN];

pub type BytesMac = [u8; MAC_LENGTH];
pub type BytesVoucher = [u8; VOUCHER_LEN];
pub type EADBuffer = EdhocBuffer<MAX_EAD_LEN>;

/// Value of C_R or C_I, as chosen by ourself or the peer.
///
/// Semantically, this is a byte string of some length.
///
/// Its legal values are constrained to only contain a single CBOR item that is either a byte
/// string or a number in -24..=23, all in preferred encoding.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct ConnId([u8; MAX_CONNID_ENCODED_LEN]);

/// Classifier for the content of [`ConnId`]; used internally in its implementation.
enum ConnIdType {
    /// The ID contains a single positive or negative number, expressed in its first byte.
    SingleByte,
    /// The ID contains a byte string, and the first byte of the ID indicates its length.
    ///
    /// It is expected that if longer connection IDs than 1+0+n are ever supported, this will be
    /// renamed to ByteString10n, and longer variants get their own class.
    ByteString(u8),
}

impl ConnIdType {
    const _IMPL_CONSTRAINTS: () = assert!(
        MAX_CONNID_ENCODED_LEN <= 1 + 23,
        "Longer connection IDs require more elaborate decoding here"
    );

    /// Returns a classifier based on an initial byte.
    ///
    /// Its signature will need to change if ever connection IDs longer than 1+0+n are supported.
    const fn classify(byte: u8) -> Option<Self> {
        if byte >> 5 <= 1 && byte & 0x1f < 24 {
            return Some(ConnIdType::SingleByte);
        } else if byte >> 5 == 2 && byte & 0x1f < 24 {
            return Some(ConnIdType::ByteString(byte & 0x1f));
        }
        None
    }

    /// Returns the number of bytes in the [`ConnId`]'s buffer.
    fn length(&self) -> usize {
        match self {
            ConnIdType::SingleByte => 1,
            ConnIdType::ByteString(n) => 1 + *n as usize,
        }
    }
}

#[hax_lib::attributes]
impl ConnId {
    /// Construct a ConnId from the result of [`cbor_decoder::int_raw`], which is a
    /// byte that represents a single positive or negative CBOR integer encoded in the 5 bits minor
    /// type.
    ///
    /// Evolving from u8-only values, this could later interact with the decoder directly.
    #[deprecated(
        note = "This API is only capable of generating a limited sub-set of the supported identifiers."
    )]
    #[hax_lib::requires(raw >> 5 <= 1 && raw & 0x1f < 24)]
    pub const fn from_int_raw(raw: u8) -> Self {
        debug_assert!(raw >> 5 <= 1, "Major type is not an integer");
        debug_assert!(raw & 0x1f < 24, "Value is not immediate");
        // We might allow '' (the empty bytes tring, byte 40) as well, but the again, this API is
        // already deprecated.
        let mut s = [0; MAX_CONNID_ENCODED_LEN];
        s[0] = raw;
        Self(s)
    }

    /// The connection ID classification of this connection ID
    ///
    /// Due to the invariants of this type, this classification infallible.
    #[hax_lib::requires(ConnIdType::classify(self.0[0]).is_some())]
    fn classify(&self) -> ConnIdType {
        ConnIdType::classify(self.0[0]).expect("type invariant requires valid classification")
    }

    /// Read a connection identifier from a given decoder.
    ///
    /// It is an error for the decoder to read anything but a small integer or a byte string, to
    /// exceed the maximum allowed ConnId length, or to contain a byte string that should have been
    /// encoded as a small integer.
    pub fn from_decoder(decoder: &mut CBORDecoder<'_>) -> Result<Self, CBORError> {
        let mut s = [0; MAX_CONNID_ENCODED_LEN];
        let len = ConnIdType::classify(decoder.current()?)
            .ok_or(CBORError::DecodingError)?
            .length();
        if len > MAX_CONNID_ENCODED_LEN {
            return Err(CBORError::DecodingError);
        }
        s[..len].copy_from_slice(decoder.read_slice(len)?);
        Ok(Self(s))
    }

    /// The bytes that form the identifier (an arbitrary byte string)
    #[hax_lib::requires(ConnIdType::classify(self.0[0]).is_some() && self.classify().length() <= MAX_CONNID_ENCODED_LEN)]
    pub fn as_slice(&self) -> &[u8] {
        match self.classify() {
            ConnIdType::SingleByte => &self.0[..1],
            ConnIdType::ByteString(n) => &self.0[1..1 + usize::from(n)],
        }
    }

    /// The CBOR encoding of the identifier.
    ///
    /// For the 48 compact connection identifiers -24..=23, this is identical to the slice
    /// representation:
    ///
    /// ```
    /// # use lakers_shared::ConnId;
    /// let c_i = ConnId::from_slice(&[0x04]).unwrap();
    /// assert_eq!(c_i.as_cbor(), &[0x04]);
    /// ```
    ///
    /// For other IDs, this contains an extra byte header:
    ///
    /// ```
    /// # use lakers_shared::ConnId;
    /// let c_i = ConnId::from_slice(&[0xff]).unwrap();
    /// assert_eq!(c_i.as_cbor(), &[0x41, 0xff]);
    /// ```
    #[hax_lib::requires(ConnIdType::classify(self.0[0]).is_some() && self.classify().length() <= MAX_CONNID_ENCODED_LEN)]
    pub fn as_cbor(&self) -> &[u8] {
        &self.0[..self.classify().length()]
    }

    /// Try to construct a [`ConnId`] from a slice that represents its string value.
    ///
    /// This is the inverse of [Self::as_slice], and returns None if the identifier is too long
    /// (or, if only the compact 48 values are supported, outside of that range).
    ///
    /// ```
    /// # use lakers_shared::ConnId;
    /// let c_i = &[0x04];
    /// let c_i = ConnId::from_slice(c_i).unwrap();
    /// assert!(c_i.as_slice() == &[0x04]);
    ///
    /// let c_i = ConnId::from_slice(&[0x12, 0x34]).unwrap();
    /// assert!(c_i.as_slice() == &[0x12, 0x34]);
    /// ```
    pub const fn from_slice(input: &[u8]) -> Option<Self> {
        if input.len() > MAX_CONNID_ENCODED_LEN - 1 {
            None
        } else {
            let mut s = [0; MAX_CONNID_ENCODED_LEN];
            if input.len() == 1
                && matches!(ConnIdType::classify(input[0]), Some(ConnIdType::SingleByte))
            {
                s[0] = input[0];
            } else {
                // This could be split_at_mut (eg. `let (first, tail) = s.split_at_mut(1);` if not
                // for hax
                s[0] = input.len() as u8 | 0x40;
                // This could be a [input.len..].copy_from_slice() if not for const, and a
                // split_at_mut if not for hax.
                let mut i = 0;
                while i < input.len() {
                    hax_lib::loop_decreases!(input.len() - i);
                    // i <= input.len() lets F* prove loop_decreases! doesn't underflow;
                    // i < MAX_CONNID_ENCODED_LEN combined with i < input.len() <= MAX-1
                    // lets F* prove 1+i < MAX_CONNID_ENCODED_LEN for s[1+i].
                    hax_lib::loop_invariant!(i <= input.len() && i < MAX_CONNID_ENCODED_LEN);
                    s[1 + i] = input[i];
                    i = i + 1;
                }
            }
            Some(Self(s))
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
#[repr(C)]
#[non_exhaustive]
pub enum EDHOCMethod {
    StatStat = 3,
    PSK = 4,
}

impl TryFrom<u8> for EDHOCMethod {
    type Error = EDHOCError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            3 => Ok(EDHOCMethod::StatStat),
            4 => Ok(EDHOCMethod::PSK),
            _ => Err(EDHOCError::UnsupportedMethod),
        }
    }
}

impl From<EDHOCMethod> for u8 {
    fn from(method: EDHOCMethod) -> u8 {
        method as u8
    }
}

#[derive(PartialEq, Debug)]
pub enum EDHOCSuite {
    CipherSuite2 = 2,
    // add others, such as:
    // CiherSuite3 = 3,
}

impl From<EDHOCSuite> for u8 {
    fn from(suite: EDHOCSuite) -> u8 {
        suite as u8
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct InitiatorStart {
    pub suites_i: EdhocBuffer<MAX_SUITES_LEN>,
    pub method: EDHOCMethod,
    pub x: BytesP256ElemLen,   // ephemeral private key of myself
    pub g_x: BytesP256ElemLen, // ephemeral public key of myself
}

#[derive(Debug)]
pub struct ResponderStart {
    pub y: BytesP256ElemLen,   // ephemeral private key of myself
    pub g_y: BytesP256ElemLen, // ephemeral public key of myself
}

#[derive(Debug)]
pub struct ProcessingM1 {
    pub method: EDHOCMethod,
    pub y: BytesP256ElemLen,
    pub g_y: BytesP256ElemLen,
    pub c_i: ConnId,
    pub g_x: BytesP256ElemLen, // ephemeral public key of the initiator
    pub h_message_1: BytesHashLen,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct WaitM2 {
    pub method: EDHOCMethod,
    pub x: BytesP256ElemLen, // ephemeral private key of the initiator
    pub h_message_1: BytesHashLen,
}
#[derive(Debug)]
pub enum WaitM3MethodSpecifics {
    StatStat {},
    Psk { cred_r: Credential },
}
#[derive(Debug)]
pub struct WaitM3 {
    pub method_specifics: WaitM3MethodSpecifics,
    pub y: BytesP256ElemLen, // ephemeral private key of the responder
    pub prk_3e2m: BytesHashLen,
    pub th_3: BytesHashLen,
}

/// Method-specific details required to prepare EDHOC message_2.
#[derive(Copy, Clone, Debug)]
pub enum PrepareMessage2Details<'a> {
    StatStat {
        r: &'a BytesP256ElemLen,
        cred_transfer: CredentialTransfer,
    },
    Psk,
}

#[derive(Debug)]
#[repr(C)]
pub enum ProcessingM2MethodSpecifics {
    StatStat { mac_2: BytesMac2, id_cred_r: IdCred },
    Psk {},
}
#[derive(Debug)]
#[repr(C)]
pub struct ProcessingM2 {
    pub method_specifics: ProcessingM2MethodSpecifics,
    pub prk_2e: BytesHashLen,
    pub th_2: BytesHashLen,
    pub x: BytesP256ElemLen,
    pub g_y: BytesP256ElemLen,
    pub plaintext_2: BufferPlaintext2,
    pub c_r: ConnId,
    pub ead_2: EadItems,
}

#[derive(Debug)]
pub enum ParsedMessage2Details {
    StatStat { id_cred_r: IdCred },
    Psk {},
}

#[derive(Debug)]
#[repr(C)]
pub enum ProcessedM2MethodSpecifics {
    StatStat {},
    Psk { cred_r: Credential },
}

#[derive(Debug)]
#[repr(C)]
pub struct ProcessedM2 {
    pub method_specifics: ProcessedM2MethodSpecifics,
    pub prk_3e2m: BytesHashLen,
    pub prk_4e3m: BytesHashLen,
    pub th_3: BytesHashLen,
}
#[derive(Debug)]
pub enum ProcessingM3MethodSpecifics {
    StatStat {
        mac_3: BytesMac3,
        id_cred_i: IdCred,
    },
    Psk {
        id_cred_psk: IdCred,
        cred_r: Credential,
    },
}
#[derive(Debug)]
pub struct ProcessingM3 {
    pub method_specifics: ProcessingM3MethodSpecifics,
    pub y: BytesP256ElemLen, // ephemeral private key of the responder
    pub prk_3e2m: BytesHashLen,
    pub th_3: BytesHashLen,
    pub plaintext_3: BufferPlaintext3,
    pub ead_3: EadItems,
}

#[derive(Debug)]
pub struct ProcessedM3 {
    pub prk_4e3m: BytesHashLen,
    pub th_4: BytesHashLen,
    pub prk_out: BytesHashLen,
    pub prk_exporter: BytesHashLen,
}

#[derive(Debug)]
#[repr(C)]
pub struct WaitM4 {
    pub prk_4e3m: BytesHashLen,
    pub th_4: BytesHashLen,
    pub prk_out: BytesHashLen,
    pub prk_exporter: BytesHashLen,
}

#[derive(Debug)]
#[repr(C)]
pub struct Completed {
    pub prk_out: BytesHashLen,
    pub prk_exporter: BytesHashLen,
}

/// An enum describing options how to send credentials.
#[cfg_attr(feature = "python-bindings", pyclass(eq, eq_int, from_py_object))]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum CredentialTransfer {
    /// This sends a short reference (key ID) of the credential.
    ///
    /// In order to complete the protocol, the peer needs to either know the full credential, or
    /// load it from an external source, or extract it from (possibly protected) EAD data such as
    /// a CWT.
    ByReference,
    /// This sends a credential by value.
    ///
    /// The peer can complete the protocol without additional information, although in most cases
    /// the peer will still need to inspect the value.
    ByValue,
}

#[deprecated]
pub type MessageBufferError = buffer::EdhocBufferError;

/// An [`EdhocBuffer`] used for messages.
pub type EdhocMessageBuffer = EdhocBuffer<MAX_MESSAGE_SIZE_LEN>;

/// An owned EAD item.
#[cfg_attr(feature = "python-bindings", pyclass(from_py_object))]
#[derive(Clone, Debug)]
pub struct EADItem {
    /// EAD label of the item
    label: u16,
    is_critical: bool,
    /// Beware that the buffer contains a *CBOR encoded* byte string.
    ///
    /// It is a type invariant that any data in here is either empty or contains exactly one CBOR
    /// item.
    value: EADBuffer,
}

#[hax_lib::attributes]
impl EADItem {
    pub fn new() -> Self {
        EADItem {
            label: 0,
            is_critical: false,
            value: EADBuffer::new(),
        }
    }

    pub fn new_full(
        label: u16,
        is_critical: bool,
        value_bytes: Option<&[u8]>,
    ) -> Result<Self, EdhocBufferError> {
        let mut value = EdhocBuffer::new();
        if let Some(value_bytes) = value_bytes {
            let mut head = CBOR_MAJOR_BYTE_STRING;
            if value_bytes.len() <= 23 {
                head |= value_bytes.len() as u8;
                value.push(head).unwrap();
            } else if value_bytes.len() <= u8::MAX.into() {
                head |= 24;
                value.push(head).unwrap();
                value.push(value_bytes.len() as u8).unwrap();
            } else if value_bytes.len() <= u16::MAX.into() {
                head |= 24;
                value.push(head).unwrap();
                value
                    .extend_from_slice(&(value_bytes.len() as u16).to_be_bytes())
                    .unwrap();
            } else {
                // EAD items do not grow beyond 64k
                return Err(EdhocBufferError::SliceTooLong);
            }
            value.extend_from_slice(value_bytes)?;
        };

        Ok(EADItem {
            label,
            is_critical,
            value,
        })
    }

    /// The content of the CBOR byte string that is the EAD item's value, if any.
    #[track_caller]
    #[hax_lib::requires(self.value.len() <= MAX_EAD_LEN)]
    pub fn value_bytes(&self) -> Option<&[u8]> {
        let slice = self.value.as_slice();
        if slice.is_empty() {
            // This is a weird ambiguity case in the current storage format of EADItem, allowing
            // "no data" to be either None or Some([])
            return None;
        }
        let mut decoder = CBORDecoder::new(slice);
        // This was the code before
        // ```rust
        // let bytes = decoder
        //     .bytes()
        //     .expect("The value being CBOR bytes is an implicit invariant of the type");
        // debug_assert!(decoder.finished());
        // Some(bytes)
        // ```
        // before we had sure that after this part, it would give a Some(_)
        // But hax/fstar cannot prove it. so the code now has weaker guarantees
        // FIXME: improve EADItem attributes to make this invariant explicit
        decoder.bytes().ok()
    }

    /// The encoded CBOR byte string that represents the value (or empty)
    ///
    /// This API may easily go away after a transition period if `EADItem` stops storing the
    /// encoded value.
    #[track_caller]
    #[hax_lib::requires(self.value.len() <= MAX_EAD_LEN)]
    fn value_encoded(&self) -> &[u8] {
        // Compute the value just to check the type invariant
        #[cfg(debug_assertions)]
        self.value_bytes();
        self.value.as_slice()
    }

    #[hax_lib::requires(self.value.len() <= MAX_EAD_LEN)]
    pub fn encode(&self) -> Result<EADBuffer, EDHOCError> {
        let mut output = EdhocBuffer::new();

        let argument_value = if self.is_critical {
            // We can express "critical padding" in the type, but that'll be just normal padding.
            self.label.saturating_sub(1)
        } else {
            self.label
        };
        let head = if self.is_critical {
            CBOR_MAJOR_NEGATIVE
        } else {
            CBOR_MAJOR_UNSIGNED
        };
        if argument_value <= 23 {
            output
                .push(head | argument_value as u8)
                .map_err(|_| EDHOCError::EadTooLongError)?;
        } else if argument_value <= u8::MAX as _ {
            output
                .push(head | 24)
                .map_err(|_| EDHOCError::EadTooLongError)?;
            output
                .push(argument_value as u8)
                .map_err(|_| EDHOCError::EadTooLongError)?;
        } else {
            output
                .push(head | 25)
                .map_err(|_| EDHOCError::EadTooLongError)?;
            output
                .extend_from_slice(&argument_value.to_be_bytes())
                .map_err(|_| EDHOCError::EadTooLongError)?;
        }

        // encode value (may be empty slice)
        let ead_1_value = &self.value_encoded();
        output
            .extend_from_slice(ead_1_value)
            .map_err(|_| EDHOCError::EadTooLongError)?;

        Ok(output)
    }
}

#[cfg_attr(feature = "python-bindings", pymethods)]
impl EADItem {
    pub fn label(&self) -> u16 {
        self.label
    }

    pub fn is_critical(&self) -> bool {
        self.is_critical
    }

    #[cfg(feature = "python-bindings")]
    #[new]
    #[pyo3(signature = (label, is_critical, value=None))]
    fn new_py(label: u16, is_critical: bool, value: Option<Vec<u8>>) -> Self {
        Self::new_full(
            label,
            is_critical,
            value.as_ref().map(|value| value.as_slice()),
        )
        .expect("EAD item too long to store")
    }

    #[cfg(feature = "python-bindings")]
    #[pyo3(name = "value")]
    fn value_py<'a>(&self, py: Python<'a>) -> Option<Bound<'a, pyo3::types::PyBytes>> {
        self.value_bytes()
            .as_ref()
            .map(|v| pyo3::types::PyBytes::new(py, v))
    }

    #[cfg(feature = "python-bindings")]
    pub fn __repr__(&self) -> String {
        let crit = if self.is_critical {
            "critical"
        } else {
            "not critical"
        };
        if let Some(value) = self.value_bytes().as_ref() {
            if value.len() > 5 {
                format!(
                    "<EADItem label={}, {}, value {:?}… ({} byte)>",
                    self.label,
                    crit,
                    &value[..5],
                    value.len()
                )
            } else {
                format!(
                    "<EADItem label={}, {}, value {:?}>",
                    self.label, crit, value
                )
            }
        } else {
            format!("<EADItem label={}, {}, no value>", self.label, crit)
        }
    }
}

/// An owned list of External Authorization Data.
///
/// Internally, this is stored as an array of options. This eases the typical operations of one
/// application "taking" out an option until all critical options are gone. This makes pushing an
/// O(n) operation, but that doesn't matter a lot when N is typically 4.
#[derive(Clone, Debug)]
pub struct EadItems {
    items: [Option<EADItem>; MAX_EAD_ITEMS],
}

pub struct EadItemsIter<'a> {
    items: &'a [Option<EADItem>; MAX_EAD_ITEMS],
    pos: usize,
}

impl<'a> Iterator for EadItemsIter<'a> {
    type Item = &'a EADItem;
    fn next(&mut self) -> Option<Self::Item> {
        let mut result: Option<&'a EADItem> = None;
        // Cannot use self.pos.min(MAX_EAD_ITEMS): hax does not support f_min (Core_models.Cmp).
        let mut i = if self.pos > MAX_EAD_ITEMS {
            MAX_EAD_ITEMS
        } else {
            self.pos
        };
        while i < MAX_EAD_ITEMS && result.is_none() {
            hax_lib::loop_decreases!(MAX_EAD_ITEMS - i);
            hax_lib::loop_invariant!(i <= MAX_EAD_ITEMS);
            result = self.items[i].as_ref();
            i += 1;
        }
        self.pos = i;
        result
    }
}

#[hax_lib::attributes]
impl EadItems {
    pub fn new() -> Self {
        Self {
            items: core::array::from_fn(|_| None),
        }
    }

    pub fn try_push(&mut self, item: EADItem) -> Result<(), EADItem> {
        // Not using iter_mut because hax wouldn't like that.
        for i in 0..MAX_EAD_ITEMS {
            if self.items[i].is_none() {
                self.items[i] = Some(item);
                return Ok(());
            }
        }
        Err(item)
    }

    pub fn iter(&self) -> EadItemsIter<'_> {
        EadItemsIter {
            items: &self.items,
            pos: 0,
        }
    }

    /// Checks whether there are critical items remaining; if so, it returns the corresponding
    /// error.
    ///
    /// Call this whenever processing EAD items after all processable items have been removed.
    pub fn processed_critical_items(&self) -> Result<(), EDHOCError> {
        for i in 0..MAX_EAD_ITEMS {
            if let Some(item) = &self.items[i] {
                if item.is_critical {
                    return Err(EDHOCError::EADUnprocessable);
                }
            }
        }
        Ok(())
    }

    pub fn pop_by_label(&mut self, label: u16) -> Option<EADItem> {
        // Not using iter_mut because hax wouldn't like that.
        for i in 0..MAX_EAD_ITEMS {
            if self.items[i].as_ref().is_some_and(|i| i.label == label) {
                return self.items[i].take();
            }
        }
        None
    }

    // This is frequently tested for, but maybe shouldn't wind up in the final API, because outside
    // of tests that's not a meanginful question.
    pub fn len(&self) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i < MAX_EAD_ITEMS {
            hax_lib::loop_decreases!(MAX_EAD_ITEMS - i);
            // count <= i: at most one increment per iteration; combined with i < MAX_EAD_ITEMS
            // this gives count + 1 <= MAX_EAD_ITEMS <= usize::MAX, proving count + 1 safe.
            hax_lib::loop_invariant!(count <= i && i <= MAX_EAD_ITEMS);
            if self.items[i].is_some() {
                count += 1;
            }
            i += 1;
        }
        count
    }

    // This is frequently tested for, but maybe shouldn't wind up in the final API, because outside
    // of tests that's not a meanginful question.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Encodes all items of self into a buffer.
    ///
    /// If this errs, some EADs may already have been encoded.
    // Workaround for hax issue #899: EdhocBuffer<N> lacks a type-level len<=N refinement,
    // so we must state the per-item value-length invariant explicitly for each slot.
    #[hax_lib::requires(
        self.items[0].as_ref().map_or(true, |e| e.value.len() <= MAX_EAD_LEN) &&
        self.items[1].as_ref().map_or(true, |e| e.value.len() <= MAX_EAD_LEN) &&
        self.items[2].as_ref().map_or(true, |e| e.value.len() <= MAX_EAD_LEN) &&
        self.items[3].as_ref().map_or(true, |e| e.value.len() <= MAX_EAD_LEN)
    )]
    pub fn encode<const N: usize>(&self, output: &mut EdhocBuffer<N>) -> Result<(), EDHOCError> {
        for i in 0..MAX_EAD_ITEMS {
            if let Some(ead_item) = &self.items[i] {
                let encoded = ead_item.encode()?;
                output
                    .extend_from_slice(encoded.as_slice())
                    .map_err(|_| EDHOCError::EadTooLongError)?;
            }
        }
        Ok(())
    }
}

mod helpers {
    use super::*;

    #[track_caller]
    #[hax_lib::requires(context.len() <= MAX_KDF_CONTEXT_LEN && length < 256)]
    #[hax_lib::ensures(|result| result.len() <= MAX_INFO_LEN)]
    pub fn encode_info(label: u8, context: &[u8], length: usize) -> BufferInfo {
        let mut info = BufferInfo::new();

        // This should help the compiler see that this won't panic.
        assert!(
            context.len() <= MAX_KDF_CONTEXT_LEN,
            "Context found to be {} (expected only up to {})",
            context.len(),
            SHA256_DIGEST_LEN
        );

        // construct info with inline cbor encoding
        info.push(label).unwrap();
        if context.len() < 24 {
            info.push(context.len() as u8 | CBOR_MAJOR_BYTE_STRING)
                .unwrap();
        } else {
            info.push(CBOR_BYTE_STRING).unwrap();
            info.push(context.len() as u8).unwrap();
        };
        info.extend_from_slice(context).unwrap();

        if length < 24 {
            info.push(length as u8).unwrap();
        } else {
            info.push(CBOR_UINT_1BYTE).unwrap();
            info.push(length as u8).unwrap();
        };

        info
    }
}

// TODO: move to own file (or even to the main crate, once EAD is extracted as an external dependency)
mod edhoc_parser {
    use super::*;

    pub fn parse_eads(buffer: &[u8]) -> Result<EadItems, EDHOCError> {
        let mut count = 0;
        let mut cursor = 0;
        let mut eads = EadItems::new();

        let mut i = 0;
        // Accumulate parse errors without `?` so the loop has no early return, which forces
        // hax to generate `while_loop` (not `while_loop_return`). Only `while_loop` passes the
        // invariant to the body, which is needed to prove `cursor <= buffer.len()`.
        let mut parse_error: Option<EDHOCError> = None;

        while i < MAX_EAD_ITEMS && parse_error.is_none() {
            hax_lib::loop_decreases!(MAX_EAD_ITEMS - i);
            hax_lib::loop_invariant!(count <= i && i <= MAX_EAD_ITEMS && cursor <= buffer.len());
            if !buffer[cursor..].is_empty() {
                match parse_single_ead(&buffer[cursor..]) {
                    Ok((item, consumed)) => {
                        eads.items[count] = Some(item);
                        count += 1;
                        cursor += consumed;
                    }
                    Err(e) => parse_error = Some(e),
                }
            }
            i += 1;
        }

        if let Some(e) = parse_error {
            return Err(e);
        }

        Ok(eads)
    }

    #[hax_lib::ensures(|result| result.as_ref().map_or(true, |(_, consumed)| *consumed <= input.len()))]
    fn parse_single_ead(input: &[u8]) -> Result<(EADItem, usize), EDHOCError> {
        let mut decoder = CBORDecoder::new(input);
        let label = decoder
            .i32_limited()
            .map_err(|_| EDHOCError::ParsingError)?;

        let is_critical = label < 0;

        // label.abs() panics/overflow on i32::MIN
        let label = if label >= 0 {
            label
        } else if label > i32::MIN {
            -label // label in (-2^31, 0), so -label in (0, 2^31-1]: fits in i32
        } else {
            return Err(EDHOCError::ParsingError);
        };

        let position_after_label = decoder.position();
        let (ead_value, position) = if let Ok(_slice) = decoder.bytes() {
            // It's not just from `slice`, because EADItem::value is an *encoded* value. (FIXME: It
            // shouldn't be).
            (
                EdhocBuffer::new_from_slice(&input[position_after_label..decoder.position()])
                    .map_err(|_| EDHOCError::ParsingError)?,
                decoder.position(),
            )
        } else {
            // If it's not just at the end but a different type, that's an error, but that error is
            // not for us to raise: Instead, the next item being parsed will trip over its label
            // not being an integer.
            (EdhocBuffer::new(), position_after_label)
        };

        // TryInto<u16> for i32 has no F* model in hax's proof-libs;
        // Core_models.Convert.t_TryInto Rust_primitives.Integers.i32 Rust_primitives.Integers.u16
        // use an explicit range check instead.
        // The guard ensures label is in [0, 65535], so `label as u16` is a lossless truncation
        if label < 0 || label > u16::MAX as i32 {
            return Err(EDHOCError::ParsingError);
        }

        let item = EADItem {
            label: label as u16,
            is_critical,
            value: ead_value,
        };

        Ok((item, position))
    }

    #[hax_lib::ensures(|result| result.as_ref().map_or(true, |(suites, _)| suites.len() <= MAX_SUITES_LEN))]
    pub fn parse_suites_i(
        mut decoder: CBORDecoder,
    ) -> Result<(EdhocBuffer<MAX_SUITES_LEN>, CBORDecoder), EDHOCError> {
        trace!("Enter parse_suites_i");
        let mut suites_i: EdhocBuffer<MAX_SUITES_LEN> = Default::default();
        if let Ok(curr) = decoder.current() {
            if CBOR_UINT_1BYTE_START == CBORDecoder::type_of(curr) {
                let Ok(_) = suites_i.push(decoder.u8()?) else {
                    return Err(EDHOCError::ParsingError);
                };
                Ok((suites_i, decoder))
            } else if CBOR_MAJOR_ARRAY == CBORDecoder::type_of(curr)
                && CBORDecoder::info_of(curr) >= 2
            {
                // NOTE: arrays must be at least 2 items long, otherwise the compact encoding (int) must be used
                let received_suites_i_len = decoder.array()?;
                let write_range = suites_i
                    .extend_reserve(received_suites_i_len)
                    .or(Err(EDHOCError::ParsingError))?;
                let mut i = write_range.start;
                let mut parse_error: Option<EDHOCError> = None;
                #[allow(deprecated, reason = "hax complains about mutable references in loops")]
                while i < write_range.end && parse_error.is_none() {
                    hax_lib::loop_decreases!(write_range.end - i);
                    hax_lib::loop_invariant!(
                        i <= write_range.end
                            && write_range.end <= MAX_SUITES_LEN
                            && suites_i.len() <= MAX_SUITES_LEN
                    );
                    match decoder.u8() {
                        Ok(byte) => {
                            suites_i.content[i] = byte;
                        }
                        Err(_) => {
                            parse_error = Some(EDHOCError::ParsingError);
                        }
                    }
                    i += 1;
                }
                if let Some(e) = parse_error {
                    return Err(e);
                }
                Ok((suites_i, decoder))
            } else {
                Err(EDHOCError::ParsingError)
            }
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    #[hax_lib::requires(rcvd_message_1.len() <= MAX_MESSAGE_SIZE_LEN)]
    pub fn parse_message_1(
        rcvd_message_1: &BufferMessage1,
    ) -> Result<
        (
            u8,
            EdhocBuffer<MAX_SUITES_LEN>,
            BytesP256ElemLen,
            ConnId,
            EadItems,
        ),
        EDHOCError,
    > {
        trace!("Enter parse_message_1");
        let mut decoder = CBORDecoder::new(rcvd_message_1.as_slice());
        let method = decoder.u8()?;

        if let Ok((suites_i, mut decoder)) = parse_suites_i(decoder) {
            let mut g_x: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
            g_x.copy_from_slice(decoder.bytes_sized(P256_ELEM_LEN)?);

            // consume c_i encoded as single-byte int (we still do not support bstr encoding)
            let c_i = ConnId::from_decoder(&mut decoder)?;

            // if there is still more to parse, the rest will be the EADs
            if rcvd_message_1.len() > decoder.position() {
                let ead_res = parse_eads(decoder.remaining_buffer()?);
                if let Ok(ead_buffer) = ead_res {
                    Ok((method, suites_i, g_x, c_i, ead_buffer))
                } else {
                    Err(ead_res.unwrap_err())
                }
            } else if decoder.finished() {
                Ok((method, suites_i, g_x, c_i, EadItems::new()))
            } else {
                Err(EDHOCError::ParsingError)
            }
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    #[hax_lib::requires(rcvd_message_2.len() <= MAX_MESSAGE_SIZE_LEN)]
    pub fn parse_message_2(
        rcvd_message_2: &BufferMessage2,
    ) -> Result<(BytesP256ElemLen, BufferCiphertext2), EDHOCError> {
        trace!("Enter parse_message_2");
        // FIXME decode negative integers as well
        let mut ciphertext_2: BufferCiphertext2 = BufferCiphertext2::new();

        let mut decoder = CBORDecoder::new(rcvd_message_2.as_slice());

        // message_2 consists of 1 bstr element; this element in turn contains the concatenation of g_y and ciphertext_2
        let decoded = decoder.bytes()?;
        if decoder.finished() {
            if let Some(key) = decoded.get(0..P256_ELEM_LEN) {
                let mut g_y: BytesP256ElemLen = [0x00; P256_ELEM_LEN];
                g_y.copy_from_slice(key);
                if let Some(c2) = decoded.get(P256_ELEM_LEN..) {
                    if ciphertext_2.fill_with_slice(c2).is_ok() {
                        Ok((g_y, ciphertext_2))
                    } else {
                        Err(EDHOCError::ParsingError)
                    }
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

    pub fn parse_message_3(
        rcvd_message_3: &BufferMessage3,
    ) -> Result<BufferCiphertext3, EDHOCError> {
        trace!("Enter parse_message_3");
        let mut decoder = CBORDecoder::new(rcvd_message_3.as_slice());
        let ciphertext_3a_slice = decoder.bytes()?;
        if !decoder.finished() {
            return Err(EDHOCError::ParsingError);
        }

        let mut ciphertext_3a = BufferCiphertext3::new();
        ciphertext_3a
            .fill_with_slice(ciphertext_3a_slice)
            .map_err(|_| EDHOCError::ParsingError)?;

        Ok(ciphertext_3a)
    }

    #[hax_lib::requires(plaintext_2.len() <= MAX_MESSAGE_SIZE_LEN)]
    pub fn decode_plaintext_2(
        plaintext_2: &BufferCiphertext2,
    ) -> Result<(ConnId, IdCred, BytesMac2, EadItems), EDHOCError> {
        trace!("Enter decode_plaintext_2");
        let mut mac_2: BytesMac2 = [0x00; MAC_LENGTH_2];

        let mut decoder = CBORDecoder::new(plaintext_2.as_slice());

        let c_r = ConnId::from_decoder(&mut decoder)?;

        // the id_cred may have been encoded as a single int, a byte string, or a map
        let id_cred_r = IdCred::from_encoded_value(decoder.any_as_encoded()?)?;

        mac_2[..].copy_from_slice(decoder.bytes_sized(MAC_LENGTH_2)?);

        // if there is still more to parse, the rest will be the EADs
        if plaintext_2.len() > decoder.position() {
            let ead_res = parse_eads(decoder.remaining_buffer()?);
            if let Ok(ead2_buffer) = ead_res {
                Ok((c_r, id_cred_r, mac_2, ead2_buffer))
            } else {
                Err(ead_res.unwrap_err())
            }
        } else if decoder.finished() {
            Ok((c_r, id_cred_r, mac_2, EadItems::new()))
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    pub fn decode_plaintext_2_psk(
        plaintext_2: &BufferCiphertext2,
    ) -> Result<(ConnId, EadItems), EDHOCError> {
        trace!("Enter decode_plaintext_2");
        let mut decoder = CBORDecoder::new(plaintext_2.as_slice());

        let c_r = ConnId::from_decoder(&mut decoder)?;

        // if there is still more to parse, the rest will be the EADs
        if plaintext_2.len() > decoder.position() {
            let ead_res = parse_eads(decoder.remaining_buffer()?);
            if let Ok(ead2_buffer) = ead_res {
                Ok((c_r, ead2_buffer))
            } else {
                Err(ead_res.unwrap_err())
            }
        } else if decoder.finished() {
            Ok((c_r, EadItems::new()))
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    #[hax_lib::requires(plaintext_3.len() <= MAX_MESSAGE_SIZE_LEN)]
    pub fn decode_plaintext_3(
        plaintext_3: &BufferPlaintext3,
    ) -> Result<(IdCred, BytesMac3, EadItems), EDHOCError> {
        trace!("Enter decode_plaintext_3");
        let mut mac_3: BytesMac3 = [0x00; MAC_LENGTH_3];

        let mut decoder = CBORDecoder::new(plaintext_3.as_slice());

        // the id_cred may have been encoded as a single int, a byte string, or a map
        let id_cred_i = IdCred::from_encoded_value(decoder.any_as_encoded()?)?;

        mac_3[..].copy_from_slice(decoder.bytes_sized(MAC_LENGTH_3)?);

        // if there is still more to parse, the rest will be the EADs
        if plaintext_3.len() > decoder.position() {
            let ead_res = parse_eads(decoder.remaining_buffer()?);
            if let Ok(ead3_buffer) = ead_res {
                Ok((id_cred_i, mac_3, ead3_buffer))
            } else {
                Err(ead_res.unwrap_err())
            }
        } else if decoder.finished() {
            Ok((id_cred_i, mac_3, EadItems::new()))
        } else {
            Err(EDHOCError::ParsingError)
        }
    }

    pub fn decode_plaintext_3_psk(plaintext_3: &BufferPlaintext3) -> Result<EadItems, EDHOCError> {
        trace!("Enter decode_plaintext_3");
        let decoder = CBORDecoder::new(plaintext_3.as_slice());

        // if there is still more to parse, the rest will be the EADs
        if plaintext_3.len() > decoder.position() {
            let ead_res = parse_eads(decoder.remaining_buffer()?);
            if let Ok(ead3_buffer) = ead_res {
                Ok(ead3_buffer)
            } else {
                Err(ead_res.unwrap_err())
            }
        } else if decoder.finished() {
            Ok(EadItems::new())
        } else {
            Err(EDHOCError::ParsingError)
        }
    }
    pub fn decode_plaintext_3a(plaintext_3: &BufferPlaintext3) -> Result<&[u8], EDHOCError> {
        trace!("Enter decode_plaintext_3");
        let mut decoder = CBORDecoder::new(plaintext_3.as_slice());
        // the id_cred may have been encoded as a single int, a byte string, or a map
        let id_cred = decoder.bytes()?;
        Ok(id_cred)
    }

    #[hax_lib::requires(plaintext_4.len() <= MAX_MESSAGE_SIZE_LEN)]
    pub fn decode_plaintext_4(plaintext_4: &BufferPlaintext4) -> Result<EadItems, EDHOCError> {
        trace!("Enter decode_plaintext_4");
        let decoder = CBORDecoder::new(plaintext_4.as_slice());

        if plaintext_4.len() > decoder.position() {
            let ead_res = parse_eads(decoder.remaining_buffer()?);
            if let Ok(ead_4_buffer) = ead_res {
                Ok(ead_4_buffer)
            } else {
                Err(ead_res.unwrap_err())
            }
        } else if decoder.finished() {
            Ok(EadItems::new())
        } else {
            Err(EDHOCError::ParsingError)
        }
    }
}

mod cbor_decoder {
    //! Decoder inspired by the [minicbor](https://crates.io/crates/minicbor) crate.
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

    /// Decoder of a slice of CBOR.
    ///
    /// Currently, this advances itself when decoding erroneous data. This means that any tentative
    /// decoding needs to fall back to a previously cloned version.
    #[derive(Debug, Clone)]
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
                Ok(*b)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Consume and return *n* bytes starting at the current position.
        pub fn read_slice(&mut self, n: usize) -> Result<&'a [u8], CBORError> {
            if let Some(b) = self
                .pos
                .checked_add(n)
                .and_then(|end| self.buf.get(self.pos..end))
            {
                self.pos += n;
                Ok(b)
            } else {
                Err(CBORError::DecodingError)
            }
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
                Ok(*b)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Decode a `u8` value.
        pub fn u8(&mut self) -> Result<u8, CBORError> {
            let n = self.read()?;
            if n <= 0x17 {
                Ok(n)
            } else if 0x18 == n {
                self.read()
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Decode an `i8` value.
        pub fn i8(&mut self) -> Result<i8, CBORError> {
            let n = self.read()?;
            if n <= 0x17 {
                Ok(n as i8)
            } else if n >= 0x20 && n <= 0x37 {
                Ok(-1 - (n - 0x20) as i8)
            } else if 0x18 == n {
                Ok(self.read()? as i8)
            } else if 0x38 == n {
                let b = self.read()?;
                // -1 - b fits in i8 only when b <= 127 (result -128..-1)
                if b <= 127 {
                    Ok(-1 - b as i8)
                } else {
                    Err(CBORError::DecodingError)
                }
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Decode up to 16 bit (1+2 byte) of an unsigned or negative integer into an i32
        pub fn i32_limited(&mut self) -> Result<i32, CBORError> {
            let (major, argument) = self.read_major_argument16()?;
            match major {
                // u16 always fits in i32
                CBOR_MAJOR_UNSIGNED => Ok(argument as i32),
                // Can not underflow
                // argument as i32 is in 0..=65535, so -1 - argument is in -65536..=-1,
                // so the subtraction never underflows for i32
                CBOR_MAJOR_NEGATIVE => Ok(-1 - argument as i32),
                _ => Err(CBORError::DecodingError),
            }
        }

        /// Decodes a major type and up to 16 bit of argument.
        ///
        /// When this function is needed here for larget arguments (and unconditionally emitted in
        /// code), it may make sense to implement this function interms of `read_major_argument32`
        /// and just map Ok((_, x if x > u16::MAX)) to Err.
        fn read_major_argument16(&mut self) -> Result<(u8, u16), CBORError> {
            let head = self.read()?;
            let info = Self::info_of(head);
            let value = match info {
                // Workaround-For: https://github.com/cryspen/hax/issues/925
                0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17
                | 18 | 19 | 20 | 21 | 22 | 23 => info as u16,
                24 => self.read()? as u16,
                25 => u16::from_be_bytes([self.read()?, self.read()?]),
                // We do not support those in this function.
                26 | 27 => return Err(CBORError::DecodingError),
                // Reserved, not well-formed
                28 | 29 | 30 => return Err(CBORError::DecodingError),
                // Indefinite length markers are forbidden in deterministic CBOR (or it's one
                // of the major types where this is just not well-formed)
                31 => return Err(CBORError::DecodingError),
                _ => unreachable!("Value was masked to 5 bits"),
            };

            Ok((Self::type_of(head), value))
        }

        /// Get the raw `i8` or `u8` value.
        pub fn int_raw(&mut self) -> Result<u8, CBORError> {
            let n = self.read()?;
            if n <= 0x17 || n >= 0x20 && n <= 0x37 {
                Ok(n)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Decode a string slice.
        pub fn str(&mut self) -> Result<&'a [u8], CBORError> {
            let b = self.read()?;
            if CBOR_MAJOR_TEXT_STRING != Self::type_of(b) || Self::info_of(b) == 31 {
                Err(CBORError::DecodingError)
            } else {
                let n = self.as_usize(Self::info_of(b))?;
                self.read_slice(n)
            }
        }

        /// Decode a byte slice.
        pub fn bytes(&mut self) -> Result<&'a [u8], CBORError> {
            let b = self.read()?;
            if CBOR_MAJOR_BYTE_STRING != Self::type_of(b) || Self::info_of(b) == 31 {
                Err(CBORError::DecodingError)
            } else {
                let n = self.as_usize(Self::info_of(b))?;
                self.read_slice(n)
            }
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
            let b = self.read()?;
            if CBOR_MAJOR_ARRAY != Self::type_of(b) {
                Err(CBORError::DecodingError)
            } else {
                match Self::info_of(b) {
                    31 => Err(CBORError::DecodingError), // no support for unknown size arrays
                    n => Ok(self.as_usize(n)?),
                }
            }
        }

        /// Begin decoding a map.
        pub fn map(&mut self) -> Result<usize, CBORError> {
            let b = self.read()?;
            if CBOR_MAJOR_MAP != Self::type_of(b) {
                Err(CBORError::DecodingError)
            } else {
                match Self::info_of(b) {
                    n if n < 24 => Ok(self.as_usize(n)?),
                    _ => Err(CBORError::DecodingError), // no support for long or indeterminate size
                }
            }
        }

        /// Decode a `u8` value into usize.
        pub fn as_usize(&mut self, b: u8) -> Result<usize, CBORError> {
            if b <= 0x17 {
                Ok(b as usize)
            } else if 0x18 == b {
                Ok(self.read()? as usize)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Get the major type info of the given byte (highest 3 bits).
        pub fn type_of(b: u8) -> u8 {
            b & 0b111_00000
        }

        /// Get the additionl type info of the given byte (lowest 5 bits).
        pub fn info_of(b: u8) -> u8 {
            b % 32
        }

        /// Check for: an unsigned integer encoded as a single byte
        pub fn is_u8(byte: u8) -> bool {
            byte >= CBOR_UINT_1BYTE_START && byte <= CBOR_UINT_1BYTE_END
        }

        /// Check for: a negative integer encoded as a single byte
        pub fn is_i8(byte: u8) -> bool {
            byte >= CBOR_NEG_INT_1BYTE_START && byte <= CBOR_NEG_INT_1BYTE_END
        }

        /// Decode any (supported) CBOR item, but ignore its internal structure and just return the
        /// encoded data.
        ///
        /// To have bound memory requirements, this depends on the encoded data to be in
        /// deterministic encoding, thus not having any indeterminate length items.
        pub fn any_as_encoded(&mut self) -> Result<&'a [u8], CBORError> {
            let mut remaining_items: u16 = 1;
            let start = self.position();

            // Instead of `while remaining_items > 0`, this loop helps hax to see that the loop
            // terminates. As every loop iteration advances the cursor by at least 1, the iteration
            // bound introduced by the for loop will never be reached, and the loop only terminates
            // through the remaining_items condition or a failure to read.
            //
            // I trust (but did not verify) that the Rust compiler can make something sensible out
            // of this (especially not keep looping needlessly) and doesn't do anything worse than
            // keep a limited loop counter.
            for _ in self.buf.iter() {
                if remaining_items > 0 {
                    remaining_items -= 1;
                    // Reading 16 is already overkill but deduplicates well with other places in
                    // the code. We' don't expect to have even more than 256 items of any kind in
                    // any buffer, but reasonably could -- but no need to decode 32 of 64 bit
                    // values; still, it's probably cheaper to go wiwht any read_major{bignumber}
                    // than to have an extra implementation here that skips decoding those large
                    // numbers.
                    let (major, argument) = self.read_major_argument16()?;
                    match major {
                        CBOR_MAJOR_UNSIGNED | CBOR_MAJOR_NEGATIVE | CBOR_MAJOR_FLOATSIMPLE => (), // Argument consumed, remaining items were already decremented
                        CBOR_MAJOR_TAG => {
                            remaining_items = remaining_items
                                .checked_add(1)
                                .ok_or(CBORError::DecodingError)?;
                        }
                        CBOR_MAJOR_BYTE_STRING | CBOR_MAJOR_TEXT_STRING => {
                            self.read_slice(argument as usize)?;
                        }
                        CBOR_MAJOR_ARRAY => {
                            remaining_items = remaining_items
                                .checked_add(argument)
                                .ok_or(CBORError::DecodingError)?;
                        }
                        CBOR_MAJOR_MAP => {
                            remaining_items = argument
                                .checked_mul(2)
                                .and_then(|argarg| remaining_items.checked_add(argarg))
                                .ok_or(CBORError::DecodingError)?;
                        }
                        _ => unreachable!("Value is result of a right shift trimming it to 3 bits"),
                    }
                }
            }

            // FIXME: we can remove this .ok_or() if we add hax::attributes
            // that guarantee that self.pos <= self.buf.len()
            self.buf
                .get(start..self.position())
                .ok_or(CBORError::DecodingError)
        }
    }
}

#[cfg(test)]
mod test_cbor_decoder {
    use super::cbor_decoder::*;
    use hexlit::hex;

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

    #[test]
    fn test_cbor_decoder_any_as_decoded() {
        // {"bytes": 'val', "n": 123, "tagged": 255(["a", -1]), "deep": [[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]], {1: {2: {3: {4: [simple(0), true, null, simple(128)]}}}}]}
        // Note we can't have floats b/c we don't skip long arguments yet (and all floats have
        // minor 25 or longer).
        let input = hex!("A46562797465734376616C616E187B66746167676564D8FF82616120646465657082818181818181818181818181818181818181818180A101A102A103A10484E0F5F6F880");
        let mut decoder = CBORDecoder::new(&input);

        assert_eq!(input, decoder.any_as_encoded().unwrap());
        assert!(decoder.finished())
    }
}

#[cfg(test)]
mod test_ead_items {
    use super::*;
    use hexlit::hex;

    #[test]
    fn test_ead_items() {
        let mut items = EadItems::new();
        assert_eq!(items.len(), 0);

        for shift in 0..MAX_EAD_ITEMS {
            items
                .try_push(
                    EADItem::new_full(
                        // Covers all 3 possible CBOR lengths
                        1 << (3 * shift),
                        shift == 0,
                        if shift == 2 { Some(b"....") } else { None },
                    )
                    .unwrap(),
                )
                .unwrap();
        }

        items
            .try_push(EADItem::new_full(1234, false, None).unwrap())
            .unwrap_err();

        let mut output_buffer = EdhocMessageBuffer::new();
        items.encode(&mut output_buffer).unwrap();
        assert_eq!(output_buffer.as_slice(), hex!("20081840442e2e2e2e190200")); // -1, 8, 64, '....', 512

        assert_eq!(items.len(), MAX_EAD_ITEMS);

        // Check round-tripping
        let decoded = edhoc_parser::parse_eads(output_buffer.as_slice()).unwrap();
        assert_eq!(
            make_comparable(&decoded),
            make_comparable(&items),
            "EAD items did not round-trip through encoding"
        );

        // This *should* be an error: the first item is critical.
        items.processed_critical_items().unwrap_err();

        let ead1 = items.pop_by_label(1).unwrap();
        assert_eq!(ead1.label, 1);

        items.processed_critical_items().unwrap();
    }

    // Not introducing PartialEq/Eq just for this test, but if it's introduced later for other
    // reasons, this could all be way easier.
    fn make_comparable(items: &EadItems) -> impl core::fmt::Debug + PartialEq {
        extern crate alloc;
        use alloc::vec::Vec;
        items
            .iter()
            .map(|i| (i.label(), i.is_critical(), Vec::from(i.value.as_slice())))
            .collect::<Vec<_>>()
    }
}

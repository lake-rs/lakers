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

use core::num::NonZeroI16;
use defmt_or_log::trace;

mod crypto;
pub use crypto::*;

mod cred;
pub use cred::*;

mod buffer;
pub use buffer::*;

#[cfg(feature = "python-bindings")]
use pyo3::prelude::*;
#[cfg(feature = "python-bindings")]
mod python_bindings;

// When changing this, beware that it is re-implemented in cbindgen.toml
pub const MAX_MESSAGE_SIZE_LEN: usize = if cfg!(feature = "max_message_size_len_1024") {
    1024
} else if cfg!(feature = "max_message_size_len_512") {
    512
} else if cfg!(feature = "max_message_size_len_448") {
    448
} else if cfg!(feature = "max_message_size_len_384") {
    384
} else if cfg!(feature = "max_message_size_len_320") {
    320
} else if cfg!(feature = "max_message_size_len_256") {
    256
} else {
    // need 128 to handle EAD fields, and 192 for the EAD_1 voucher
    128 + 64
};

pub const ID_CRED_LEN: usize = 4;
pub const SUITES_LEN: usize = 9;
pub const SUPPORTED_SUITES_LEN: usize = 1;
pub const EDHOC_METHOD: u8 = 4u8; // stat-stat: 3u8, psk:4u8
pub const P256_ELEM_LEN: usize = 32;
pub const P256_ELEM_LEN_PSK: usize = 16;
pub const SHA256_DIGEST_LEN: usize = 32;
pub const AES_CCM_KEY_LEN: usize = 16;
pub const AES_CCM_IV_LEN: usize = 13;
pub const AES_CCM_TAG_LEN: usize = 8;
pub const MAC_LENGTH: usize = 8; // used for EAD Zeroconf
pub const MAC_LENGTH_2: usize = MAC_LENGTH;
pub const MAC_LENGTH_3: usize = MAC_LENGTH_2;
pub const VOUCHER_LEN: usize = MAC_LENGTH;
pub const MAX_EAD_ITEMS: usize = 4;

// maximum supported length of connection identifier for R
//
// When changing this, beware that it is re-implemented in cbindgen.toml
pub const MAX_KDF_CONTEXT_LEN: usize = if cfg!(feature = "max_kdf_content_len_1024") {
    1024
} else if cfg!(feature = "max_kdf_content_len_512") {
    512
} else if cfg!(feature = "max_kdf_content_len_448") {
    448
} else if cfg!(feature = "max_kdf_content_len_384") {
    384
} else if cfg!(feature = "max_kdf_content_len_320") {
    320
} else {
    256
};
pub const MAX_KDF_LABEL_LEN: usize = 15; // for "KEYSTREAM_2"

// When changing this, beware that it is re-implemented in cbindgen.toml
pub const MAX_BUFFER_LEN: usize = if cfg!(feature = "max_buffer_len_1024") {
    1024
} else if cfg!(feature = "max_buffer_len_512") {
    512
} else if cfg!(feature = "max_buffer_len_448") {
    448
} else if cfg!(feature = "max_buffer_len_384") {
    384
} else {
    256 + 64
};
pub const CBOR_BYTE_STRING: u8 = 0x58u8;
pub const CBOR_TEXT_STRING: u8 = 0x78u8;
pub const CBOR_UINT_1BYTE: u8 = 0x18u8;
pub const CBOR_NEG_INT_1BYTE_START: u8 = 0x20u8;
pub const CBOR_NEG_INT_1BYTE_END: u8 = 0x37u8;
pub const CBOR_UINT_1BYTE_START: u8 = 0x0u8;
pub const CBOR_UINT_1BYTE_END: u8 = 0x17u8;
const CBOR_MAJOR_UNSIGNED: u8 = 0 << 5;
const CBOR_MAJOR_NEGATIVE: u8 = 1 << 5;
const CBOR_MAJOR_TAG: u8 = 6 << 5;
const CBOR_MAJOR_FLOATSIMPLE: u8 = 7 << 5;
pub const CBOR_MAJOR_TEXT_STRING: u8 = 0x60u8;
pub const CBOR_MAJOR_BYTE_STRING: u8 = 0x40u8;
pub const CBOR_MAJOR_BYTE_STRING_MAX: u8 = 0x57u8;
pub const CBOR_MAJOR_ARRAY: u8 = 0x80u8;
pub const CBOR_MAJOR_ARRAY_MAX: u8 = 0x97u8;
pub const CBOR_MAJOR_MAP: u8 = 0xA0;
pub const MAX_INFO_LEN: usize = 2 + SHA256_DIGEST_LEN + // 32-byte digest as bstr
				            1 + MAX_KDF_LABEL_LEN +     // label <24 bytes as tstr
						    1 + MAX_KDF_CONTEXT_LEN +   // context <24 bytes as bstr
						    1; // length as u8

pub const KCCS_LABEL: u8 = 14;
#[deprecated(note = "Typo for KCCS_LABEL")]
pub const KCSS_LABEL: u8 = KCCS_LABEL;
pub const KID_LABEL: u8 = 4;

pub const ENC_STRUCTURE_LEN: usize = 8 + 5 + SHA256_DIGEST_LEN; // 8 for ENCRYPT0
pub const ENC_STRUCTURE_PSK_LEN: usize = 1 + 1 + 8 + 1 + EXTERNAL_AAD_PSK_LEN; //
pub const EXTERNAL_AAD_PSK_LEN: usize = 1 + 1 + 2 +32 + 2+ 38 + 2 + 38 + 1;
pub const MAX_EAD_LEN: usize = if cfg!(feature = "max_ead_len_1024") {
    1024
} else if cfg!(feature = "max_ead_len_768") {
    768
} else if cfg!(feature = "max_ead_len_512") {
    512
} else if cfg!(feature = "max_ead_len_384") {
    384
} else if cfg!(feature = "max_ead_len_256") {
    256
} else if cfg!(feature = "max_ead_len_192") {
    192
} else if cfg!(feature = "max_ead_len_128") {
    128
} else {
    64
};

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
pub type BytesP256ElemLenPSK = [u8; P256_ELEM_LEN_PSK];
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
pub type BytesEncStructurePSKLen = [u8; ENC_STRUCTURE_PSK_LEN];
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
            ConnIdType::ByteString(n) => (1 + n).into(),
        }
    }
}

impl ConnId {
    /// Construct a ConnId from the result of [`cbor_decoder::int_raw`], which is a
    /// byte that represents a single positive or negative CBOR integer encoded in the 5 bits minor
    /// type.
    ///
    /// Evolving from u8-only values, this could later interact with the decoder directly.
    #[deprecated(
        note = "This API is only capable of generating a limited sub-set of the supported identifiers."
    )]
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
    fn classify(&self) -> ConnIdType {
        let Some(t) = ConnIdType::classify(self.0[0]) else {
            unreachable!("Type invariant requires valid classification")
        };
        t
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
        s[..len].copy_from_slice(decoder.read_slice(len)?);
        Ok(Self(s))
    }

    /// The bytes that form the identifier (an arbitrary byte string)
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
                    s[1 + i] = input[i];
                    i = i + 1;
                }
            }
            Some(Self(s))
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum EDHOCMethod {
    StatStat = 3,
    PSK = 4,
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

#[derive(PartialEq, Debug)]
#[non_exhaustive]
pub enum EDHOCError {
    /// In an exchange, a credential was set as "expected", but the credential configured by the
    /// peer did not match what was presented. This is more an application internal than an EDHOC
    /// error: When the application sets the expected credential, that process should be informed
    /// by the known details.
    UnexpectedCredential,
    MissingIdentity,
    IdentityAlreadySet,
    MacVerificationFailed,
    UnsupportedMethod,
    UnsupportedCipherSuite,
    ParsingError,
    EncodingError,
    CredentialTooLongError,
    EadLabelTooLongError,
    EadTooLongError,
    /// An EAD was received that was either not known (and critical), or not understood, or
    /// otherwise erroneous.
    EADUnprocessable,
    /// The credential or EADs could be processed (possibly by a third party), but the decision
    /// based on that was to not to continue the EDHOC session.
    ///
    /// See also
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-lake-authz#name-edhoc-error-access-denied>
    AccessDenied,
}

impl EDHOCError {
    /// The ERR_CODE corresponding to the error
    ///
    /// Errors that refer to internal limitations (such as EadTooLongError) are treated the same
    /// way as parsing errors, and return an unspecified error: Those are equivalent to limitations
    /// of the parser, and a constrained system can not be expected to differentiate between "the
    /// standard allows this but my number space is too small" and "this violates the standard".
    ///
    /// If an EDHOCError is returned through EDHOC, it will use this in its EDHOC error message.
    ///
    /// Note that this on its own is insufficient to create an error message: Additional ERR_INFO
    /// is needed, which may or may not be available with the EDHOCError alone.
    ///
    /// TODO: Evolve the EDHOCError type such that all information needed is available.
    pub fn err_code(&self) -> ErrCode {
        use EDHOCError::*;
        match self {
            UnexpectedCredential => ErrCode::UNSPECIFIED,
            MissingIdentity => ErrCode::UNSPECIFIED,
            IdentityAlreadySet => ErrCode::UNSPECIFIED,
            MacVerificationFailed => ErrCode::UNSPECIFIED,
            UnsupportedMethod => ErrCode::UNSPECIFIED,
            UnsupportedCipherSuite => ErrCode::WRONG_SELECTED_CIPHER_SUITE,
            ParsingError => ErrCode::UNSPECIFIED,
            EncodingError => ErrCode::UNSPECIFIED,
            CredentialTooLongError => ErrCode::UNSPECIFIED,
            EadLabelTooLongError => ErrCode::UNSPECIFIED,
            EadTooLongError => ErrCode::UNSPECIFIED,
            EADUnprocessable => ErrCode::UNSPECIFIED,
            AccessDenied => ErrCode::ACCESS_DENIED,
        }
    }
}

/// Representation of an EDHOC ERR_CODE
#[repr(C)]
pub struct ErrCode(pub NonZeroI16);

impl ErrCode {
    pub const UNSPECIFIED: Self = ErrCode(NonZeroI16::new(1).unwrap());
    pub const WRONG_SELECTED_CIPHER_SUITE: Self = ErrCode(NonZeroI16::new(2).unwrap());
    pub const UNKNOWN_CREDENTIAL: Self = ErrCode(NonZeroI16::new(3).unwrap());
    // Code requested in https://datatracker.ietf.org/doc/html/draft-ietf-lake-authz
    pub const ACCESS_DENIED: Self = ErrCode(NonZeroI16::new(3333).unwrap());
}

#[derive(Debug)]
#[repr(C)]
pub struct InitiatorStart {
    pub suites_i: EdhocBuffer<MAX_SUITES_LEN>,
    pub method: EDHOCMethod,
    pub x: BytesP256ElemLen,        // ephemeral private key of myself
    pub g_x: BytesP256ElemLen,      // ephemeral public key of myself,
    pub cred_i: Option<Credential>, // Added for PSK variant
}

#[derive(Debug)]
pub struct ResponderStart {
    pub method: EDHOCMethod,
    pub y: BytesP256ElemLen,   // ephemeral private key of myself
    pub g_y: BytesP256ElemLen, // ephemeral public key of myself,
    pub cred_r: Credential,    // Added for PSK variant
}

#[derive(Debug, Clone)]
pub struct ProcessingM1 {
    pub method: u8,
    pub y: BytesP256ElemLen,
    pub g_y: BytesP256ElemLen,
    pub c_i: ConnId,
    pub g_x: BytesP256ElemLen, // ephemeral public key of the initiator
    pub h_message_1: BytesHashLen,
    // pub cred_r: Credential, // Added for PSK variant
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct WaitM2 {
    pub method: u8,
    pub x: BytesP256ElemLen, // ephemeral private key of the initiator
    pub h_message_1: BytesHashLen,
    pub cred_i: Option<Credential>, // Added for PSK variant
}

#[derive(Clone, Debug)]
pub struct WaitM3 {
    pub method: u8,
    pub y: BytesP256ElemLen, // ephemeral private key of the responder
    pub prk_3e2m: BytesHashLen,
    // pub salt_3e2m: BytesHashLen,
    pub th_3: BytesHashLen,
    // pub cred_r: Option<Credential>,
}

#[derive(Debug)]
#[repr(C)]
pub struct ProcessingM2 {
    pub method: u8,
    pub mac_2: Option<BytesMac2>,
    pub prk_2e: BytesHashLen,
    pub th_2: BytesHashLen,
    pub x: BytesP256ElemLen,
    pub g_y: BytesP256ElemLen,
    pub plaintext_2: BufferPlaintext2,
    pub c_r: ConnId,
    // pub cred_i: Option<Credential>,
    pub id_cred_r: Option<IdCred>,
    pub ead_2: EadItems,
}

#[derive(Debug)]
#[repr(C)]
pub struct ProcessedM2 {
    pub method: u8,
    pub prk_3e2m: BytesHashLen,
    pub prk_4e3m: BytesHashLen,
    pub th_3: BytesHashLen,
    // pub cred_i: Option<Credential>,
    pub cred_r: Option<Credential>,
    // pub id_cred_r: Option<IdCred>,
}

#[derive(Debug)]
pub struct ProcessingM3 {
    pub method: u8,
    pub mac_3: Option<BytesMac3>,
    pub y: BytesP256ElemLen, // ephemeral private key of the responder
    pub prk_3e2m: BytesHashLen,
    // pub salt_3e2m: BytesHashLen,
    pub th_3: BytesHashLen,
    pub id_cred_i: Option<IdCred>,
    pub plaintext_3: BufferPlaintext3,
    pub ead_3: EadItems,
    // pub cred_r: Option<Credential>,
}

#[derive(Debug)]
pub struct PreparingM3 {
    pub prk_3e2m: BytesHashLen,
    pub prk_4e3m: BytesHashLen,
    pub th_3: BytesHashLen,
    pub mac_3: BytesMac3,
}

#[derive(Debug)]
pub struct ProcessedM3 {
    // pub prk_3e2m: BytesHashLen,
    pub prk_4e3m: BytesHashLen,
    // pub cred_r: Credential,
    // pub th_3: BytesHashLen,
    pub th_4: BytesHashLen,
    // pub id_cred: Option<IdCred>,
    pub prk_out: BytesHashLen,
    pub prk_exporter: BytesHashLen,
}

#[derive(Debug)]
pub struct WaitM4 {
    // pub prk_3e2m: BytesHashLen,
    pub prk_4e3m: BytesHashLen,
    // pub cred_r: Credential,
    // pub th_3: BytesHashLen,
    pub th_4: BytesHashLen,
    // pub id_cred: Option<IdCred>,
    pub ead_3: EadItems,
    pub prk_out: BytesHashLen,
    pub prk_exporter: BytesHashLen,
}

#[derive(Debug)]
pub struct ProcessingM4 {
    pub prk_4e3m: BytesHashLen,
    pub th_4: BytesHashLen,
    pub prk_out: BytesHashLen,
    pub prk_exporter: BytesHashLen,
}

#[derive(Debug)]
pub struct ProcessedM4 {
    pub prk_3e2m: BytesHashLen,
    pub prk_4e3m: BytesHashLen,
    pub cred_i: Credential,
    pub th_3: BytesHashLen,
    pub th_4: BytesHashLen,
}

#[derive(Debug)]
#[repr(C)]
pub struct Completed {
    pub prk_out: BytesHashLen,
    pub prk_exporter: BytesHashLen,
}

/// An enum describing options how to send credentials.
#[cfg_attr(feature = "python-bindings", pyclass(eq, eq_int))]
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
#[cfg_attr(feature = "python-bindings", pyclass)]
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
    pub fn value_bytes(&self) -> Option<&[u8]> {
        let slice = self.value.as_slice();
        if slice.is_empty() {
            // This is a weird ambiguity case in the current storage format of EADItem, allowing
            // "no data" to be either None or Some([])
            return None;
        }
        let mut decoder = CBORDecoder::new(slice);
        let bytes = decoder
            .bytes()
            .expect("The value being CBOR bytes is an implicit invariant of the type");
        debug_assert!(decoder.finished());
        Some(bytes)
    }

    /// The encoded CBOR byte string that represents the value (or empty)
    ///
    /// This API may easily go away after a transition period if `EADItem` stops storing the
    /// encoded value.
    #[track_caller]
    fn value_encoded(&self) -> &[u8] {
        // Compute the value just to check the type invariant
        #[cfg(debug_assertions)]
        self.value_bytes();
        self.value.as_slice()
    }

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

impl<'a> IntoIterator for &'a EadItems {
    type Item = &'a EADItem;

    type IntoIter = core::iter::FilterMap<
        core::slice::Iter<'a, Option<EADItem>>,
        fn(&Option<EADItem>) -> Option<&EADItem>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter().filter_map(Option::as_ref)
    }
}

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

    pub fn iter(&self) -> <&Self as IntoIterator>::IntoIter {
        self.into_iter()
    }

    /// Checks whether there are critical items remaining; if so, it returns the corresponding
    /// error.
    ///
    /// Call this whenever processing EAD items after all processable items have been removed.
    pub fn processed_critical_items(&self) -> Result<(), EDHOCError> {
        if self.iter().any(|i| i.is_critical) {
            return Err(EDHOCError::EADUnprocessable);
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
        self.items.iter().filter(|x| x.is_some()).count()
    }

    // This is frequently tested for, but maybe shouldn't wind up in the final API, because outside
    // of tests that's not a meanginful question.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Encodes all items of self into a buffer.
    ///
    /// If this errs, some EADs may already have been encoded.
    pub fn encode<const N: usize>(&self, output: &mut EdhocBuffer<N>) -> Result<(), EDHOCError> {
        for ead_item in self {
            let encoded = ead_item.encode()?;
            output
                .extend_from_slice(encoded.as_slice())
                .map_err(|_| EDHOCError::EadTooLongError)?;
        }
        Ok(())
    }
}

mod helpers {
    use super::*;

    #[track_caller]
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

        for _ in 0..MAX_EAD_ITEMS {
            if !buffer[cursor..].is_empty() {
                let (item, consumed) = parse_single_ead(&buffer[cursor..])?;
                eads.items[count] = Some(item);
                count += 1;
                cursor += consumed;
            }
        }

        Ok(eads)
    }

    fn parse_single_ead(input: &[u8]) -> Result<(EADItem, usize), EDHOCError> {
        let mut decoder = CBORDecoder::new(input);
        let label = decoder
            .i32_limited()
            .map_err(|_| EDHOCError::ParsingError)?;

        let is_critical = label < 0;
        let label = label.abs();

        let position_after_label = decoder.position();

        let ead_value = if let Ok(_slice) = decoder.bytes() {
            // It's not just from `slice`, because EADItem::value is an *encoded* value. (FIXME: It
            // shouldn't be).
            EdhocBuffer::new_from_slice(&input[position_after_label..decoder.position()])
                .map_err(|_| EDHOCError::ParsingError)?
        } else {
            // If it's not just at the end but a different type, that's an error, but that error is
            // not for us to raise: Instead, the next item being parsed will trip over its label
            // not being an integer.
            EdhocBuffer::new()
        };

        let item = EADItem {
            label: label
                .try_into()
                // That's really only for 0xffff; we could accommodate that if we handled padding
                // differently and stored the (positive label-1) value
                .map_err(|_| EDHOCError::ParsingError)?,
            is_critical,
            value: ead_value,
        };

        Ok((item, decoder.position()))
    }

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
                #[allow(deprecated, reason = "hax complains about mutable references in loops")]
                for i in write_range {
                    suites_i.content[i] = decoder.u8()?;
                }
                Ok((suites_i, decoder))
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
            //println!("g_x: {:?}", g_x);

            // consume c_i encoded as single-byte int (we still do not support bstr encoding)
            let c_i = ConnId::from_int_raw(decoder.int_raw()?);
            // let c_i = ConnId::from_decoder(&mut decoder)?;
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
        let message_slice = rcvd_message_3.as_slice();
        //println!("message_slice :{:?}", message_slice);

        // Get the first byte and convert it to length
        let first_byte = message_slice[0];
        let (ciphertext_3a_len, header_len) = decode_cbor_length(first_byte)?;
        let mut ciphertext_3a = BufferCiphertext3::new();
        // Ensure we have enough data
        if message_slice.len() < header_len + ciphertext_3a_len {
            return Err(EDHOCError::ParsingError);
        }
        ciphertext_3a.fill_with_slice(&message_slice[header_len..header_len + ciphertext_3a_len]);
        // println!("ciphertext_3a: {:?}", ciphertext_3a);

        // let mut ciphertext_3b = BufferCiphertext3::new();
        // ciphertext_3b
        //     .fill_with_slice(&message_slice[ciphertext_3a_len + 1..])
        //     .map_err(|_| EDHOCError::ParsingError)?;
        // println!("ciphertext_3b length: {}", ciphertext_3b.len);
        // println!("ciphertext_3b: {:?}", ciphertext_3b);

        Ok(ciphertext_3a)
    }

    pub fn decode_plaintext_2(
        method: u8,
        plaintext_2: &BufferCiphertext2,
    ) -> Result<(ConnId, Option<IdCred>, Option<BytesMac2>, EadItems), EDHOCError> {
        trace!("Enter decode_plaintext_2");
        let mut mac_2: Option<[u8; MAC_LENGTH_2]> = None;

        let mut decoder = CBORDecoder::new(plaintext_2.as_slice());
        trace!("decoder:{:?}", decoder);

        let c_r = ConnId::from_decoder(&mut decoder)?;

        // the id_cred may have been encoded as a single int, a byte string, or a map
        let (id_cred_r, mac_2) = match method {
            m if m == EDHOCMethod::StatStat.into() => {
                let input = decoder.any_as_encoded()?;
                let id_cred = Some(IdCred::from_encoded_value(&input)?);
                let mut mac_2 = [0x00; MAC_LENGTH_2];
                mac_2.copy_from_slice(decoder.bytes_sized(MAC_LENGTH_2)?);
                (id_cred, Some(mac_2))
            }
            m if m == EDHOCMethod::PSK.into() => {
                // There is no mac_2
                (None, None)
            }
            _ => return Err(EDHOCError::UnsupportedMethod),
        };
        trace!("id_cred_r from plaintext_2:{:?}", id_cred_r);
        trace!("mac_2 from plaintext_2:{:?}", mac_2);
        //mac_2[..].copy_from_slice(decoder.bytes_sized(MAC_LENGTH_2)?);

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

    pub fn decode_plaintext_3(
        method: u8,
        plaintext_3: &BufferPlaintext3,
    ) -> Result<(Option<IdCred>, Option<BytesMac3>, EadItems), EDHOCError> {
        trace!("Enter decode_plaintext_3");
        let mut mac_3: BytesMac3 = [0x00; MAC_LENGTH_3];

        let mut decoder = CBORDecoder::new(plaintext_3.as_slice());
        //println!("decoder plaintext_3:{:?}", decoder);
        // the id_cred may have been encoded as a single int, a byte string, or a map

        let id_cred_i = match method {
            m if m == EDHOCMethod::PSK.into() => None,
            m if m == EDHOCMethod::StatStat.into() => {
                let input = decoder.any_as_encoded()?;
                Some(IdCred::from_encoded_value(&input)?)
            }
            _ => return Err(EDHOCError::UnsupportedMethod),
        };

        let mac_3 = match method {
            m if m == EDHOCMethod::PSK.into() => None,
            m if m == EDHOCMethod::StatStat.into() => {
                let mut mac_array = [0u8; MAC_LENGTH_3];
                mac_array.copy_from_slice(decoder.bytes_sized(MAC_LENGTH_3)?);
                Some(mac_array)
            }
            _ => return Err(EDHOCError::UnsupportedMethod),
        };
        //mac_3[..].copy_from_slice(decoder.bytes_sized(MAC_LENGTH_3)?);

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
 
pub fn decode_plaintext_3a(plaintext_3: &BufferPlaintext3) -> Result<&[u8], EDHOCError> {
    trace!("Enter decode_plaintext_3");

    let mut decoder = CBORDecoder::new(plaintext_3.as_slice());
    //println!("decoder plaintext_3a:{:?}", decoder);
    // the id_cred may have been encoded as a single int, a byte string, or a map
    let id_cred = decoder.bytes()?;
    Ok(id_cred)
}


fn decode_cbor_length(first_byte: u8) -> Result<(usize, usize), EDHOCError> {
    match first_byte & 0x1F {
        n @ 0..=23 => Ok((n as usize, 1)),
        24 => Ok((24, 2)),                  // Next byte is the length
        25 => Ok((25, 3)),                  // Next 2 bytes are the length
        _ => Err(EDHOCError::ParsingError), // Unsupported length encoding
    }
}

fn decode_cbor_prefix(data: &[u8]) -> Result<(BytesKeyKid, &[u8]), EDHOCError> {
    let mut decoder = CBORDecoder::new(data);
    //println!("decoder:{:?}", data);
    // Assuming ciphertext_3a is encoded as a byte string
    //println!("decoder_bytes:{:?}", decoder.bytes()?);
    let bytes = decoder.bytes()?;
    //println!("bytes:{:?}", bytes);

    if bytes.len() != 4 {
        return Err(EDHOCError::ParsingError);
    }

    let mut ciphertext_3a = [0u8; 4];
    ciphertext_3a.copy_from_slice(&bytes);
    //println!("ciphertext_3a:{:?}", ciphertext_3a);

    Ok((ciphertext_3a, &data[decoder.position()..]))
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
            // NOTE: thid could be a `match` with `n @ 0x00..=0x17` clauses but hax doesn't support it
            if (0..=0x17).contains(&n) {
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
            if (0..=0x17).contains(&n) {
                Ok(n as i8)
            } else if (0x20..=0x37).contains(&n) {
                Ok(-1 - (n - 0x20) as i8)
            } else if 0x18 == n {
                Ok(self.read()? as i8)
            } else if 0x38 == n {
                Ok(-1 - (self.read()? - 0x20) as i8)
            } else {
                Err(CBORError::DecodingError)
            }
        }

        /// Decode up to 16 bit (1+2 byte) of an unsigned or negative integer into an i32
        pub fn i32_limited(&mut self) -> Result<i32, CBORError> {
            let (major, argument) = self.read_major_argument16()?;
            match major {
                CBOR_MAJOR_UNSIGNED => Ok(i32::from(argument)),
                // Can not underflow
                CBOR_MAJOR_NEGATIVE => Ok(-1 - i32::from(argument)),
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
                | 18 | 19 | 20 | 21 | 22 | 23 => info.into(),
                24 => self.read()?.into(),
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
            if (0..=0x17).contains(&n) || (0x20..=0x37).contains(&n) {
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
            if (0..=0x17).contains(&b) {
                Ok(usize::from(b))
            } else if 0x18 == b {
                self.read().map(usize::from)
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
            b & 0b000_11111
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
                            self.read_slice(argument.into())?;
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

            Ok(&self.buf[start..self.position()])
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

        // This *should* be an error: the first item is critical.
        items.processed_critical_items().unwrap_err();

        let ead1 = items.pop_by_label(1).unwrap();
        assert_eq!(ead1.label, 1);

        items.processed_critical_items().unwrap();
    }
}

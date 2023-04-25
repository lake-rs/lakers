#![no_std]

pub use common::*;

#[cfg(feature = "hacspec")]
pub use hacspec::*;

#[cfg(feature = "rust")]
pub use rust::*;

mod common {

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

    #[derive(PartialEq, Debug)]
    pub enum EDHOCError {
        Success = 0,
        UnknownPeer = 1,
        MacVerificationFailed = 2,
        UnsupportedMethod = 3,
        UnsupportedCipherSuite = 4,
        ParsingError = 5,
        WrongState = 6,
        UnknownError = 7,
    }

    pub const ID_CRED_LEN: usize = 4;
    pub const SUPPORTED_SUITES_LEN: usize = 1;
    pub const MESSAGE_1_LEN: usize = 37;
    pub const MESSAGE_2_LEN: usize = 45;
    pub const MESSAGE_3_LEN: usize = CIPHERTEXT_3_LEN + 1; // 1 to wrap ciphertext into a cbor byte string
    pub const EDHOC_METHOD: u8 = 3u8; // stat-stat is the only supported method
    pub const P256_ELEM_LEN: usize = 32;
    pub const SHA256_DIGEST_LEN: usize = 32;
    pub const AES_CCM_KEY_LEN: usize = 16;
    pub const AES_CCM_IV_LEN: usize = 13;
    pub const AES_CCM_TAG_LEN: usize = 8;
    pub const MAC_LENGTH_2: usize = 8;
    pub const MAC_LENGTH_3: usize = MAC_LENGTH_2;
    // ciphertext is message_len -1 for c_r, -2 for cbor magic numbers
    pub const CIPHERTEXT_2_LEN: usize = MESSAGE_2_LEN - P256_ELEM_LEN - 1 - 2;
    pub const PLAINTEXT_2_LEN: usize = CIPHERTEXT_2_LEN;
    pub const PLAINTEXT_3_LEN: usize = MAC_LENGTH_3 + 2; // support for kid auth only
    pub const CIPHERTEXT_3_LEN: usize = PLAINTEXT_3_LEN + AES_CCM_TAG_LEN;

    // maximum supported length of connection identifier for R
    pub const MAX_KDF_CONTEXT_LEN: usize = 150;
    pub const MAX_KDF_LABEL_LEN: usize = 15; // for "KEYSTREAM_2"
    pub const MAX_BUFFER_LEN: usize = 220;
    pub const CBOR_BYTE_STRING: u8 = 0x58u8;
    pub const CBOR_UINT_1BYTE: u8 = 0x18u8;
    pub const CBOR_MAJOR_TEXT_STRING: u8 = 0x60u8;
    pub const CBOR_MAJOR_BYTE_STRING: u8 = 0x40u8;
    pub const CBOR_MAJOR_ARRAY: u8 = 0x80u8;
    pub const MAX_INFO_LEN: usize = 2 + SHA256_DIGEST_LEN + // 32-byte digest as bstr
				            1 + MAX_KDF_LABEL_LEN +     // label <24 bytes as tstr
						    1 + MAX_KDF_CONTEXT_LEN +   // context <24 bytes as bstr
						    1; // length as u8

    pub const ENC_STRUCTURE_LEN: usize = 8 + 5 + SHA256_DIGEST_LEN; // 8 for ENCRYPT0
}

#[cfg(feature = "rust")]
mod rust {
    use super::common::*;
    pub type U8 = u8;
    pub type BytesEad2 = [u8; 0];
    pub type BytesIdCred = [u8; ID_CRED_LEN];
    pub type BytesSupportedSuites = [u8; SUPPORTED_SUITES_LEN];
    pub type Bytes8 = [u8; 8];
    pub type BytesCcmKeyLen = [u8; AES_CCM_KEY_LEN];
    pub type BytesCcmIvLen = [u8; AES_CCM_IV_LEN];
    pub type BytesPlaintext2 = [u8; PLAINTEXT_2_LEN];
    pub type BytesPlaintext3 = [u8; PLAINTEXT_3_LEN];
    pub type BytesMac2 = [u8; MAC_LENGTH_2];
    pub type BytesMac3 = [u8; MAC_LENGTH_3];
    pub type BytesMessage1 = [u8; MESSAGE_1_LEN];
    pub type BytesMessage3 = [u8; MESSAGE_3_LEN];
    pub type BytesCiphertext2 = [u8; CIPHERTEXT_2_LEN];
    pub type BytesCiphertext3 = [u8; CIPHERTEXT_3_LEN];
    pub type BytesHashLen = [u8; SHA256_DIGEST_LEN];
    pub type BytesP256ElemLen = [u8; P256_ELEM_LEN];
    pub type BytesMessage2 = [u8; MESSAGE_2_LEN];
    pub type BytesMaxBuffer = [u8; MAX_BUFFER_LEN];
    pub type BytesMaxContextBuffer = [u8; MAX_KDF_CONTEXT_LEN];
    pub type BytesMaxInfoBuffer = [u8; MAX_INFO_LEN];
    pub type BytesMaxLabelBuffeer = [u8; MAX_KDF_LABEL_LEN];
    pub type BytesEncStructureLen = [u8; ENC_STRUCTURE_LEN];

    pub const C_I: u8 = 0x37u8;
    pub const C_R: u8 = 0x00u8;
    pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites = [0x2u8];

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
}

#[cfg(feature = "hacspec")]
mod hacspec {
    use super::common::*;
    use hacspec_lib::*;

    array!(BytesEad2, 0, U8);
    array!(BytesIdCred, ID_CRED_LEN, U8);
    array!(BytesSupportedSuites, SUPPORTED_SUITES_LEN, U8);
    array!(Bytes8, 8, U8);
    array!(BytesCcmKeyLen, AES_CCM_KEY_LEN, U8);
    array!(BytesCcmIvLen, AES_CCM_IV_LEN, U8);
    array!(BytesPlaintext2, PLAINTEXT_2_LEN, U8);
    array!(BytesPlaintext3, PLAINTEXT_3_LEN, U8);
    array!(BytesMac2, MAC_LENGTH_2, U8);
    array!(BytesMac3, MAC_LENGTH_3, U8);
    array!(BytesMessage1, MESSAGE_1_LEN, U8);
    array!(BytesMessage3, MESSAGE_3_LEN, U8);
    array!(BytesCiphertext2, CIPHERTEXT_2_LEN, U8);
    array!(BytesCiphertext3, CIPHERTEXT_3_LEN, U8);
    array!(BytesHashLen, SHA256_DIGEST_LEN, U8);
    array!(BytesP256ElemLen, P256_ELEM_LEN, U8);
    array!(BytesMessage2, MESSAGE_2_LEN, U8);
    array!(BytesMaxBuffer, MAX_BUFFER_LEN, U8);
    array!(BytesMaxContextBuffer, MAX_KDF_CONTEXT_LEN, U8);
    array!(BytesMaxInfoBuffer, MAX_INFO_LEN, U8);
    array!(BytesMaxLabelBuffer, MAX_KDF_LABEL_LEN, U8);
    array!(BytesEncStructureLen, ENC_STRUCTURE_LEN, U8);

    pub const C_I: U8 = U8(0x37u8);
    pub const C_R: U8 = U8(0x00u8);

    // Currently only suite number 2 is supported,
    // which corresponds to the array 10, -16, 8, 1, -7, 10, -16,
    // which in turn corresponds to the following:
    // - AES-CCM-16-64-128 | EDHOC AEAD algorithm
    // - SHA-256 | EDHOC hash algorithm
    // - 8 | MAC length in bytes
    // - P-256 | key exchange algorithm
    // - ES256 | signature algorithm
    // - AES-CCM-16-64-128 | Application AEAD algorithm
    // - SHA-256 | Application hash algorithm
    pub const EDHOC_SUPPORTED_SUITES: BytesSupportedSuites =
        BytesSupportedSuites(secret_bytes!([0x2u8]));

    #[derive(Default, Copy, Clone, Debug)]
    pub struct State(
        pub EDHOCState,
        pub BytesP256ElemLen, // x or y, ephemeral private key of myself
        pub U8,               // c_i, connection identifier chosen by the initiator
        pub BytesP256ElemLen, // g_y or g_x, ephemeral public key of the peer
        pub BytesHashLen,     // prk_3e2m
        pub BytesHashLen,     // prk_4e3m
        pub BytesHashLen,     // prk_out
        pub BytesHashLen,     // prk_exporter
        pub BytesHashLen,     // h_message_1
        pub BytesHashLen,     // th_3
    );
}

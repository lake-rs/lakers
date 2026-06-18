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
pub const EDHOC_METHOD: u8 = 3u8; // stat-stat is the only supported method
pub const P256_ELEM_LEN: usize = 32;
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
pub const CBOR_MAJOR_UNSIGNED: u8 = 0 << 5;
pub const CBOR_MAJOR_NEGATIVE: u8 = 1 << 5;
pub const CBOR_MAJOR_TAG: u8 = 6 << 5;
pub const CBOR_MAJOR_FLOATSIMPLE: u8 = 7 << 5;
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

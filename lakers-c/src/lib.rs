#![no_std]
/// This module contains the FFI bindings for the lakers-c library.
/// Normally the structs can be derived from the Rust structs, except in cases
/// where we need to hide fields that are not compatible with C, such as `Option<..>`.
/// Specifically in the case of `Option<..>` we use a pointer instead, where `NULL` indicates `None`.
///
/// Example command to compile this module for the nRF52840:
/// cargo build --target='thumbv7em-none-eabihf' --no-default-features --features="crypto-cryptocell310"
use lakers::{credential_check_or_fetch as credential_check_or_fetch_rust, *};
use lakers_crypto::{default_crypto, CryptoTrait};

#[cfg(feature = "ead-authz")]
pub mod ead_authz;
pub mod initiator;

// crate type staticlib requires a panic handler and an allocator
use embedded_alloc::Heap;
use panic_semihosting as _;
#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Note that while the Rust version supports optional value to indicate an empty value,
/// in the C version we use an empty buffer for that case.
#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct EADItemC {
    pub label: u16,
    pub is_critical: bool,
    /// The value is only emitted if this is true (otherwise it is an EAD item that has just a label)
    pub has_value: bool,
    /// The bytes of the option
    pub value: EADBuffer,
}

impl EADItemC {
    pub fn to_rust(&self) -> EADItem {
        EADItem::new_full(
            self.label,
            self.is_critical,
            if self.has_value {
                Some(self.value.as_slice())
            } else {
                None
            },
        )
        .unwrap()
    }

    pub unsafe fn copy_into_c(ead: EADItem, ead_c: *mut EADItemC) {
        (*ead_c).label = ead.label();
        (*ead_c).is_critical = ead.is_critical();
        (*ead_c).has_value = ead.value_bytes().is_some();
        (*ead_c).value =
            EdhocBuffer::new_from_slice(ead.value_bytes().unwrap_or_default()).unwrap();
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct EadItemsC {
    pub items: [EADItemC; MAX_EAD_ITEMS],
    pub len: usize,
}

impl EadItemsC {
    pub fn to_rust(&self) -> EadItems {
        let mut items = EadItems::new();

        for i in self.items.iter() {
            items
                .try_push(i.clone().to_rust())
                .expect("EadItemsC can not contain more items than EadItems");
        }

        items
    }

    pub unsafe fn copy_into_c(ead: EadItems, ead_c: *mut EadItemsC) {
        (*ead_c).len = ead.len();

        for (i, item) in ead.iter().enumerate() {
            EADItemC::copy_into_c(item.clone(), &mut (*ead_c).items[i]);
        }
    }

    pub fn try_push(&mut self, item: EADItemC) -> Result<(), EADItemC> {
        if self.len == MAX_EAD_ITEMS {
            return Err(item);
        }
        self.items[self.len] = item;
        self.len += 1;
        Ok(())
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct ProcessingM2C {
    pub method: EDHOCMethod,
    pub mac_2: Option<BytesMac2>,
    pub prk_2e: BytesHashLen,
    pub th_2: BytesHashLen,
    pub x: BytesP256ElemLen,
    pub g_y: BytesP256ElemLen,
    pub plaintext_2: EdhocMessageBuffer,
    pub c_r: u8,
    pub id_cred_r: Option<IdCred>,
    pub ead_2: *mut EadItemsC,
}

impl Default for ProcessingM2C {
    fn default() -> Self {
        ProcessingM2C {
            method: EDHOCMethod::StatStat,
            mac_2: Default::default(),
            prk_2e: Default::default(),
            th_2: Default::default(),
            x: Default::default(),
            g_y: Default::default(),
            plaintext_2: Default::default(),
            c_r: Default::default(),
            id_cred_r: Default::default(),
            ead_2: core::ptr::null_mut(),
        }
    }
}

impl ProcessingM2C {
    pub fn to_rust(&self) -> ProcessingM2 {
        ProcessingM2 {
            method: self.method,
            mac_2: self.mac_2,
            prk_2e: self.prk_2e,
            th_2: self.th_2,
            x: self.x,
            g_y: self.g_y,
            plaintext_2: self.plaintext_2.clone(),
            #[allow(deprecated)]
            c_r: ConnId::from_int_raw(self.c_r),
            id_cred_r: self.id_cred_r.clone(),
            ead_2: unsafe { (*self.ead_2).to_rust() },
        }
    }

    /// note that it is a shallow copy (ead_2 is handled separately by the caller)
    pub unsafe fn copy_into_c(processing_m2: ProcessingM2, processing_m2_c: *mut ProcessingM2C) {
        if processing_m2_c.is_null() {
            panic!("processing_m2_c is null");
        }

        (*processing_m2_c).mac_2 = processing_m2.mac_2;
        (*processing_m2_c).prk_2e = processing_m2.prk_2e;
        (*processing_m2_c).th_2 = processing_m2.th_2;
        (*processing_m2_c).x = processing_m2.x;
        (*processing_m2_c).g_y = processing_m2.g_y;
        (*processing_m2_c).plaintext_2 = processing_m2.plaintext_2;
        let c_r = processing_m2.c_r.as_slice();
        assert_eq!(c_r.len(), 1, "C API only supports short C_R");
        (*processing_m2_c).c_r = c_r[0];
        (*processing_m2_c).id_cred_r = processing_m2.id_cred_r;
    }
}

#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct CredentialC {
    pub bytes: BufferCred,
    pub key: CredentialKey,
    /// differs from Rust: here we assume the kid is always present
    /// this is to simplify the C API, since C doesn't support Option<T>
    /// the alternative would be to use a pointer, but then we need to care about memory management
    pub kid: BufferKid,
    pub cred_type: CredentialType,
}

impl CredentialC {
    pub fn to_rust(&self) -> Credential {
        Credential {
            bytes: self.bytes.clone(),
            key: self.key,
            kid: Some(self.kid.clone()),
            cred_type: self.cred_type,
        }
    }

    pub unsafe fn copy_into_c(cred: Credential, cred_c: *mut CredentialC) {
        (*cred_c).bytes = cred.bytes;
        (*cred_c).key = cred.key;
        (*cred_c).kid = cred.kid.unwrap();
        (*cred_c).cred_type = cred.cred_type;
    }
}

#[no_mangle]
pub unsafe extern "C" fn credential_new(
    cred: *mut CredentialC,
    value: *const u8,
    value_len: usize,
) -> i8 {
    let value = core::slice::from_raw_parts(value, value_len);
    match Credential::parse_ccs(value) {
        Ok(cred_parsed) => {
            CredentialC::copy_into_c(cred_parsed, cred);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn credential_check_or_fetch(
    cred_expected: *mut CredentialC,
    id_cred_received: *mut IdCred,
    cred_out: *mut CredentialC,
) -> i8 {
    let cred_expected = if cred_expected.is_null() {
        None
    } else {
        Some((*cred_expected).to_rust())
    };

    let id_cred_received_value = (*id_cred_received).clone();
    match credential_check_or_fetch_rust(cred_expected, id_cred_received_value) {
        Ok(valid_cred) => {
            CredentialC::copy_into_c(valid_cred, cred_out);
            0
        }
        Err(err) => err as i8,
    }
}

// This function is useful to test the FFI
#[no_mangle]
pub extern "C" fn p256_generate_key_pair_from_c(out_private_key: *mut u8, out_public_key: *mut u8) {
    let (private_key, public_key) = default_crypto().p256_generate_key_pair();

    unsafe {
        // copy the arrays to the pointers received from C
        // this makes sure that data is not dropped when the function returns
        core::ptr::copy_nonoverlapping(
            private_key.as_ptr(),
            out_private_key,
            lakers::P256_ELEM_LEN,
        );
        core::ptr::copy_nonoverlapping(public_key.as_ptr(), out_public_key, lakers::P256_ELEM_LEN);
    }
}

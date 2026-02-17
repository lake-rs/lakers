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

#[derive(Default, Clone, Copy, Debug)]
#[repr(C)]
pub struct OptionBytesMac2 {
    pub is_some: bool,
    pub value: BytesMac2,
}

impl OptionBytesMac2 {
    pub fn to_rust(&self) -> Option<BytesMac2> {
        if self.is_some {
            Some(self.value)
        } else {
            None
        }
    }

    pub fn from_rust(value: Option<BytesMac2>) -> Self {
        match value {
            Some(v) => Self {
                is_some: true,
                value: v,
            },
            None => Self {
                is_some: false,
                value: Default::default(),
            },
        }
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct OptionIdCred {
    pub is_some: bool,
    pub value: IdCred,
}

impl OptionIdCred {
    pub fn to_rust(&self) -> Option<IdCred> {
        if self.is_some {
            Some(self.value.clone())
        } else {
            None
        }
    }

    pub fn from_rust(value: Option<IdCred>) -> Self {
        match value {
            Some(v) => Self {
                is_some: true,
                value: v,
            },
            None => Self {
                is_some: false,
                value: Default::default(),
            },
        }
    }
}
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct OptionCredentialC {
    pub value: *mut CredentialC, // NULL => None
}

impl Default for OptionCredentialC {
    fn default() -> Self {
        Self {
            value: core::ptr::null_mut(),
        }
    }
}

impl OptionCredentialC {
    pub fn to_rust(&self) -> Option<Credential> {
        if self.value.is_null() {
            None
        } else {
            Some(unsafe { (*self.value).to_rust() })
        }
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct SuitesBufferC {
    pub content: [u8; MAX_SUITES_LEN],
    pub len: usize,
}

#[derive(Debug)]
#[repr(C)]
pub struct InitiatorStartC {
    pub suites_i: SuitesBufferC,
    pub method: EDHOCMethod,
    pub x: BytesP256ElemLen,       // ephemeral private key of myself
    pub g_x: BytesP256ElemLen,     // ephemeral public key of myself,
    pub cred_i: OptionCredentialC, // Added for PSK
}

impl Default for InitiatorStartC {
    fn default() -> Self {
        InitiatorStartC {
            suites_i: Default::default(),
            method: EDHOCMethod::StatStat,
            x: Default::default(),
            g_x: Default::default(),
            cred_i: Default::default(),
        }
    }
}

impl InitiatorStartC {
    pub fn to_rust(&self) -> InitiatorStart {
        let suites_i = EdhocBuffer::<MAX_SUITES_LEN>::new_from_slice(
            &self.suites_i.content[..self.suites_i.len],
        )
        .unwrap();

        InitiatorStart {
            suites_i,
            method: self.method,
            x: self.x,
            g_x: self.g_x,
            cred_i: self.cred_i.to_rust(),
        }
    }

    /// note that it is a shallow copy (ead_2 is handled separately by the caller)
    pub unsafe fn copy_into_c(start: InitiatorStart, start_c: *mut InitiatorStartC) {
        if start_c.is_null() {
            panic!("initiator_start_c is null");
        }

        let suites = start.suites_i.as_slice();
        (&mut (*start_c).suites_i.content)[..suites.len()].copy_from_slice(suites);
        (*start_c).suites_i.len = suites.len();
        (*start_c).method = start.method;
        (*start_c).x = start.x;
        (*start_c).g_x = start.g_x;

        if let Some(cred_i) = start.cred_i {
            if (*start_c).cred_i.value.is_null() {
                panic!("initiator_start_c.cred_i.value is null but Rust state has Some(cred_i)");
            }
            CredentialC::copy_into_c(cred_i, (*start_c).cred_i.value);
        } else {
            (*start_c).cred_i.value = core::ptr::null_mut();
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct WaitM2C {
    pub method: EDHOCMethod,
    pub x: BytesP256ElemLen,
    pub h_message_1: BytesHashLen,
    pub cred_i: OptionCredentialC,
}

impl Default for WaitM2C {
    fn default() -> Self {
        WaitM2C {
            method: EDHOCMethod::StatStat,
            x: Default::default(),
            h_message_1: Default::default(),
            cred_i: Default::default(),
        }
    }
}

impl WaitM2C {
    pub fn to_rust(&self) -> WaitM2 {
        WaitM2 {
            method: self.method,
            x: self.x,
            h_message_1: self.h_message_1,
            cred_i: self.cred_i.to_rust(),
        }
    }

    pub unsafe fn copy_into_c(wait_m2: WaitM2, wait_m2c: *mut WaitM2C) {
        if wait_m2c.is_null() {
            panic!("wait_m2c is null");
        }

        (*wait_m2c).method = wait_m2.method;
        (*wait_m2c).x = wait_m2.x;
        (*wait_m2c).h_message_1 = wait_m2.h_message_1;

        if let Some(cred_i) = wait_m2.cred_i {
            if (*wait_m2c).cred_i.value.is_null() {
                panic!("initiator_start_c.cred_i.value is null but Rust state has Some(cred_i)");
            }
            CredentialC::copy_into_c(cred_i, (*wait_m2c).cred_i.value);
        } else {
            (*wait_m2c).cred_i.value = core::ptr::null_mut();
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct ProcessingM2C {
    pub method: EDHOCMethod,
    pub mac_2: OptionBytesMac2,
    pub prk_2e: BytesHashLen,
    pub th_2: BytesHashLen,
    pub x: BytesP256ElemLen,
    pub g_y: BytesP256ElemLen,
    pub plaintext_2: EdhocMessageBuffer,
    pub c_r: u8,
    pub id_cred_r: OptionIdCred,
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
            mac_2: self.mac_2.to_rust(),
            prk_2e: self.prk_2e,
            th_2: self.th_2,
            x: self.x,
            g_y: self.g_y,
            plaintext_2: self.plaintext_2.clone(),
            #[allow(deprecated)]
            c_r: ConnId::from_int_raw(self.c_r),
            id_cred_r: self.id_cred_r.to_rust(),
            ead_2: unsafe { (*self.ead_2).to_rust() },
        }
    }

    /// note that it is a shallow copy (ead_2 is handled separately by the caller)
    pub unsafe fn copy_into_c(processing_m2: ProcessingM2, processing_m2_c: *mut ProcessingM2C) {
        if processing_m2_c.is_null() {
            panic!("processing_m2_c is null");
        }

        (*processing_m2_c).mac_2 = OptionBytesMac2::from_rust(processing_m2.mac_2);
        (*processing_m2_c).prk_2e = processing_m2.prk_2e;
        (*processing_m2_c).th_2 = processing_m2.th_2;
        (*processing_m2_c).x = processing_m2.x;
        (*processing_m2_c).g_y = processing_m2.g_y;
        (*processing_m2_c).plaintext_2 = processing_m2.plaintext_2;
        let c_r = processing_m2.c_r.as_slice();
        assert_eq!(c_r.len(), 1, "C API only supports short C_R");
        (*processing_m2_c).c_r = c_r[0];
        (*processing_m2_c).id_cred_r = OptionIdCred::from_rust(processing_m2.id_cred_r);
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct ProcessedM2C {
    pub method: EDHOCMethod,
    pub prk_3e2m: BytesHashLen,
    pub prk_4e3m: BytesHashLen,
    pub th_3: BytesHashLen,
    pub cred_r: OptionCredentialC,
}

impl Default for ProcessedM2C {
    fn default() -> Self {
        ProcessedM2C {
            method: EDHOCMethod::StatStat,
            prk_3e2m: Default::default(),
            prk_4e3m: Default::default(),
            th_3: Default::default(),
            cred_r: Default::default(),
        }
    }
}

impl ProcessedM2C {
    pub fn to_rust(&self) -> ProcessedM2 {
        ProcessedM2 {
            method: self.method,
            prk_3e2m: self.prk_3e2m,
            prk_4e3m: self.prk_4e3m,
            th_3: self.th_3,
            cred_r: self.cred_r.to_rust(),
        }
    }

    /// note that it is a shallow copy (ead_2 is handled separately by the caller)
    pub unsafe fn copy_into_c(processed_m2: ProcessedM2, processed_m2_c: *mut ProcessedM2C) {
        if processed_m2_c.is_null() {
            panic!("processed_m2_c is null");
        }

        (*processed_m2_c).method = processed_m2.method;
        (*processed_m2_c).prk_3e2m = processed_m2.prk_3e2m;
        (*processed_m2_c).prk_4e3m = processed_m2.prk_4e3m;
        (*processed_m2_c).th_3 = processed_m2.th_3;
        if let Some(cred_r) = processed_m2.cred_r {
            if (*processed_m2_c).cred_r.value.is_null() {
                panic!("initiator_start_c.cred_i.value is null but Rust state has Some(cred_i)");
            }
            CredentialC::copy_into_c(cred_r, (*processed_m2_c).cred_r.value);
        } else {
            (*processed_m2_c).cred_r.value = core::ptr::null_mut();
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct WaitM4C {
    pub prk_4e3m: BytesHashLen,
    pub th_4: BytesHashLen,
    pub ead_3: *mut EadItemsC,
    pub prk_out: BytesHashLen,
    pub prk_exporter: BytesHashLen,
}

impl Default for WaitM4C {
    fn default() -> Self {
        WaitM4C {
            prk_4e3m: Default::default(),
            th_4: Default::default(),
            ead_3: core::ptr::null_mut(),
            prk_out: Default::default(),
            prk_exporter: Default::default(),
        }
    }
}

impl WaitM4C {
    pub fn to_rust(&self) -> WaitM4 {
        WaitM4 {
            prk_4e3m: self.prk_4e3m,
            th_4: self.th_4,
            ead_3: unsafe { (*self.ead_3).to_rust() },
            prk_out: self.prk_out,
            prk_exporter: self.prk_exporter,
        }
    }

    /// note that it is a shallow copy (ead_2 is handled separately by the caller)
    pub unsafe fn copy_into_c(wait_m4: WaitM4, wait_m4_c: *mut WaitM4C) {
        if wait_m4_c.is_null() {
            panic!("wait_m4_c is null");
        }

        (*wait_m4_c).prk_4e3m = wait_m4.prk_4e3m;
        (*wait_m4_c).th_4 = wait_m4.th_4;
        (*wait_m4_c).prk_out = wait_m4.prk_out;
        (*wait_m4_c).prk_exporter = wait_m4.prk_exporter;
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

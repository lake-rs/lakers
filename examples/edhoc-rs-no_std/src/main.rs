#![no_std]
#![no_main]
#![feature(default_alloc_error_handler)]

use cortex_m_rt::entry;
use cortex_m_semihosting::debug::{self, EXIT_SUCCESS};

#[cfg(not(feature = "rtt"))]
use cortex_m_semihosting::hprintln as println;

use panic_semihosting as _;

#[cfg(feature = "rtt")]
use rtt_target::{rprintln as println, rtt_init_print};

use edhoc_rs::*;

extern crate alloc;

use embedded_alloc::Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

extern "C" {
    pub fn mbedtls_memory_buffer_alloc_init(buf: *mut c_char, len: usize);
}

#[entry]
fn main() -> ! {
    #[cfg(feature = "rtt")]
    rtt_init_print!();

    // Initialize the allocator BEFORE you use it
    // The hacspec version does some heap allocations
    // TODO: we still don't have a baremetal version with hacspec as crypto backend, so maybe remove `HEAP`.
    #[cfg(any(feature = "crypto-hacspec"))]
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 1 << 10;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
    }

    // Memory buffer for mbedtls
    #[cfg(feature = "crypto-psa")]
    let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    #[cfg(feature = "crypto-psa")]
    unsafe {
        mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    }

    // testing output
    println!("Hello, edhoc-rs!");

    // testing asserts
    assert!(1 == 1);

    // edhoc-rs test code
    use hexlit::hex;

    const ID_CRED_I: &[u8] = &hex!("a104412b");
    const ID_CRED_R: &[u8] = &hex!("a104410a");
    const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
    const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
    const G_I: &[u8] = &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"); // used
    const _G_I_Y_COORD: &[u8] =
        &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"); // not used
    const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
    const G_R: &[u8] = &hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const C_R_TV: [u8; 1] = hex!("27");

    fn test_new_initiator() {
        let state: EdhocState = Default::default();
        let _initiator = EdhocInitiator::new(state, I, G_R, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);
    }

    test_new_initiator();
    println!("Test test_new_initiator passed.");

    fn test_p256_keys() {
        let (x, g_x) = p256_generate_key_pair();
        let (y, g_y) = p256_generate_key_pair();

        let g_xy = p256_ecdh(&x, &g_y);
        let g_yx = p256_ecdh(&y, &g_x);

        assert_eq!(g_xy, g_yx);
    }
    test_p256_keys();
    println!("Test test_p256_keys passed.");

    fn test_prepare_message_1() {
        let state: EdhocState = Default::default();
        let mut initiator =
            EdhocInitiator::new(state, I, G_R, ID_CRED_I, CRED_I, ID_CRED_R, CRED_R);

        let c_i: u8 = generate_connection_identifier_cbor().into();
        let message_1 = initiator.prepare_message_1(c_i);
        assert!(message_1.is_ok());
    }

    test_prepare_message_1();
    println!("Test test_prepare_message_1 passed.");

    fn test_handshake() {
        let state_initiator: EdhocState = Default::default();
        let mut initiator = EdhocInitiator::new(
            state_initiator,
            I,
            G_R,
            ID_CRED_I,
            CRED_I,
            ID_CRED_R,
            CRED_R,
        );
        let state_responder: EdhocState = Default::default();
        let mut responder = EdhocResponder::new(
            state_responder,
            R,
            G_I,
            ID_CRED_I,
            CRED_I,
            ID_CRED_R,
            CRED_R,
        );

        let c_i: u8 = generate_connection_identifier_cbor().into();
        let ret = initiator.prepare_message_1(c_i); // to update the state
        assert!(ret.is_ok());
        let message_1 = ret.unwrap();

        let ret = responder.process_message_1(&message_1);
        assert!(ret.is_ok());

        let c_r: u8 = generate_connection_identifier_cbor().into();
        let ret = responder.prepare_message_2(c_r);
        assert!(ret.is_ok());
        let message_2 = ret.unwrap();
        assert!(c_r != 0xff);

        let _c_r = initiator.process_message_2(&message_2);
        assert!(_c_r.is_ok());

        let ret = initiator.prepare_message_3();
        assert!(ret.is_ok());
        let (message_3, i_prk_out) = ret.unwrap();

        let r_prk_out = responder.process_message_3(&message_3);
        assert!(r_prk_out.is_ok());

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out.unwrap());

        // derive OSCORE secret and salt at both sides and compare
        let i_oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
        assert!(i_oscore_secret.is_ok());
        let i_oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1
        assert!(i_oscore_salt.is_ok());

        let r_oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
        assert!(r_oscore_secret.is_ok());
        let r_oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1
        assert!(r_oscore_salt.is_ok());

        assert_eq!(i_oscore_secret.unwrap(), r_oscore_secret.unwrap());
        assert_eq!(i_oscore_salt.unwrap(), r_oscore_salt.unwrap());
    }

    test_handshake();
    println!("Test test_handshake passed.");
    println!("All tests passed.");

    // exit via semihosting call
    debug::exit(EXIT_SUCCESS);

    // the cortex_m_rt `entry` macro requires `main()` to never return
    loop {}
}

use core::ffi::{c_char, c_ulong, c_void};

#[no_mangle]
pub extern "C" fn strstr(_cs: *const c_char, _ct: *const c_char) -> *mut c_char {
    panic!("strstr handler!");
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn calloc(__count: c_ulong, __size: c_ulong) -> *mut c_void {
    panic!("calloc handler!");
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn free(_ptr: *const c_void) {
    panic!("free handler!");
}

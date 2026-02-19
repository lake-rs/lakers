#![no_std]
#![no_main]

use cortex_m_rt::entry;
use cortex_m_semihosting::debug::{self, EXIT_SUCCESS};

#[cfg(not(target_abi = "eabihf"))]
use cortex_m_semihosting::hprintln as info;

#[cfg(target_abi = "eabihf")]
use defmt::info;

use defmt_rtt as _; // global logger

use lakers::*;
use lakers_crypto::{default_crypto, CryptoTrait};
use panic_semihosting as _;

extern crate alloc;

use embedded_alloc::Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

extern "C" {
    pub fn mbedtls_memory_buffer_alloc_init(buf: *mut c_char, len: usize);
}

#[entry]
fn main() -> ! {
    // Memory buffer for mbedtls
    #[cfg(feature = "crypto-psa")]
    let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    #[cfg(feature = "crypto-psa")]
    unsafe {
        mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    }

    // testing output
    info!("Hello, lakers!");

    // testing asserts
    assert!(1 == 1);

    // lakers test code
    use hexlit::hex;

    const _ID_CRED_I: &[u8] = &hex!("a104412b");
    const _ID_CRED_R: &[u8] = &hex!("a104410a");
    const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
    const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
    const _G_I: &[u8] = &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
    const _G_I_Y_COORD: &[u8] =
        &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
    const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
    const _G_R: &[u8] = &hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
    const _C_R_TV: [u8; 1] = hex!("27");

    fn test_new_initiator() {
        let _initiator = EdhocInitiator::new(
            lakers_crypto::default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );
    }

    test_new_initiator();
    info!("Test test_new_initiator passed.");

    fn test_p256_keys() {
        let (x, g_x) = default_crypto().p256_generate_key_pair();
        let (y, g_y) = default_crypto().p256_generate_key_pair();

        let g_xy = default_crypto().p256_ecdh(&x, &g_y);
        let g_yx = default_crypto().p256_ecdh(&y, &g_x);

        assert_eq!(g_xy, g_yx);
    }
    test_p256_keys();
    info!("Test test_p256_keys passed.");

    fn test_prepare_message_1() {
        let initiator = EdhocInitiator::new(
            lakers_crypto::default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );

        let _c_i =
            generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto()).as_slice();
        let message_1 = initiator.prepare_message_1(None, &EadItems::new());
        assert!(message_1.is_ok());
    }

    test_prepare_message_1();
    info!("Test test_prepare_message_1 passed.");

    fn test_handshake() {
        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

        let initiator = EdhocInitiator::new(
            lakers_crypto::default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );
        let responder = EdhocResponder::new(
            lakers_crypto::default_crypto(),
            R.try_into().expect("Wrong length of responder private key"),
            cred_r.clone(),
        );

        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();

        let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
        let (responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, None, &EadItems::new())
            .unwrap();

        let (mut initiator, _c_r, id_cred_r, _ead_2) =
            initiator.parse_message_2(&message_2).unwrap();
        let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r).unwrap();
        initiator
            .set_identity(
                I.try_into().expect("Wrong length of initiator private key"),
                cred_i.clone(),
            )
            .unwrap(); // exposing own identity only after validating cred_r
        let initiator = initiator.verify_message_2(valid_cred_r).unwrap();

        let (initiator, message_3, i_prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();

        let (responder, id_cred_i, _ead_3) = responder.parse_message_3(&message_3).unwrap();
        let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i).unwrap();
        let (responder, r_prk_out) = responder.verify_message_3(valid_cred_i).unwrap();

        let mut initiator = initiator.completed_without_message_4().unwrap();
        let mut responder = responder.completed_without_message_4().unwrap();

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let mut i_oscore_secret = [0; 16];
        initiator.edhoc_exporter(0u8, &[], &mut i_oscore_secret); // label is 0
        let mut i_oscore_salt = [0; 8];
        initiator.edhoc_exporter(1u8, &[], &mut i_oscore_salt); // label is 1

        let mut r_oscore_secret = [0; 16];
        responder.edhoc_exporter(0u8, &[], &mut r_oscore_secret); // label is 0
        let mut r_oscore_salt = [0; 8];
        responder.edhoc_exporter(1u8, &[], &mut r_oscore_salt); // label is 1

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);
    }

    test_handshake();
    info!("Test test_handshake passed.");
    info!("All tests passed.");

    // exit via semihosting call
    debug::exit(EXIT_SUCCESS);

    // the cortex_m_rt `entry` macro requires `main()` to never return
    loop {}
}

use core::ffi::c_char;

#[no_mangle]
pub extern "C" fn strstr(_cs: *const c_char, _ct: *const c_char) -> *mut c_char {
    panic!("strstr handler!");
}

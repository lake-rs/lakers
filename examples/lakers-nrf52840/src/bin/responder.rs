#![no_std]
#![no_main]

use common::{Packet, PacketError, ADV_ADDRESS, ADV_CRC_INIT, CRC_POLY, FREQ, MAX_PDU};
use defmt::info;
use defmt::unwrap;
use embassy_executor::Spawner;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::radio::ble::Mode;
use embassy_nrf::radio::ble::Radio;
use embassy_nrf::radio::TxPower;
use embassy_nrf::{bind_interrupts, peripherals, radio};
use embassy_time::{Duration, Timer};
use {defmt_rtt as _, panic_probe as _};

use lakers::*;

use core::ffi::c_char;

extern crate alloc;

use embedded_alloc::Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

extern "C" {
    pub fn mbedtls_memory_buffer_alloc_init(buf: *mut c_char, len: usize);
}

mod common;

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let peripherals: embassy_nrf::Peripherals = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio = Radio::new(peripherals.RADIO, Irqs);

    radio.set_mode(Mode::BLE_1MBIT);
    radio.set_tx_power(TxPower::_0D_BM);
    radio.set_frequency(FREQ);

    radio.set_access_address(ADV_ADDRESS);
    radio.set_header_expansion(false);
    radio.set_crc_init(ADV_CRC_INIT);
    radio.set_crc_poly(CRC_POLY);

    // Memory buffer for mbedtls
    #[cfg(feature = "crypto-psa")]
    let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    #[cfg(feature = "crypto-psa")]
    unsafe {
        mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    }

    info!("Responder started, will wait for messages");

    loop {
        let mut buffer: [u8; MAX_PDU] = [0x00u8; MAX_PDU];
        let mut c_r: Option<ConnId> = None;
        let pckt = common::receive_and_filter(&mut radio, Some(0xf5)) // filter all incoming packets waiting for CBOR TRUE (0xf5)
            .await
            .unwrap();

        info!("Received message_1");

        let cred_r = Credential::parse_ccs(common::CRED_R.try_into().unwrap()).unwrap();
        let responder = EdhocResponder::new(
            lakers_crypto::default_crypto(),
            EDHOCMethod::StatStat,
            Some(common::R.try_into().unwrap()),
            cred_r,
        );

        let message_1: EdhocMessageBuffer = pckt.pdu[1..pckt.len].try_into().expect("wrong length"); // get rid of the TRUE byte

        let result = responder.process_message_1(&message_1);

        if let Ok((responder, _c_i, mut ead_1)) = result {
            c_r = generate_connection_identifier_cbor(
                &mut lakers_crypto::default_crypto(),
            );
            let ead_2 = EadItems::new();

            let (responder, message_2) = responder
                .prepare_message_2(CredentialTransfer::ByReference, Some(c_r), &ead_2)
                .unwrap();

            // prepend 0xf5 also to message_2 in order to allow the Initiator filter out from other BLE packets
            let message_3 = common::transmit_and_wait_response(
                &mut radio,
                Packet::new_from_slice(message_2.as_slice(), Some(0xf5)).expect("wrong length"),
                Some(c_r.unwrap().as_slice()[0]),
            )
                .await;

            match message_3 {
                Ok(message_3) => {
                    info!("Received message_3");
                    #[allow(deprecated)]
                    let rcvd_c_r: ConnId = ConnId::from_int_raw(message_3.pdu[0] as u8);

                    if rcvd_c_r == c_r.unwrap() {
                        let message_3: EdhocMessageBuffer = message_3.pdu[1..message_3.len]
                            .try_into()
                            .expect("wrong length");
                        let Ok((responder, id_cred_i, _ead_3)) =
                            responder.parse_message_3(&message_3)
                        else {
                            info!("EDHOC error at parse_message_3");
                            // We don't get another chance, it's popped and can't be used any further
                            // anyway legally
                            continue;
                        };
                        let cred_i: Credential =
                            Credential::parse_ccs(common::CRED_I.try_into().unwrap()).unwrap();
                        let valid_cred_i =
                            credential_check_or_fetch(Some(cred_i), id_cred_i.unwrap()).unwrap();
                        let Ok((responder, r_prk_out)) = responder.verify_message_3(valid_cred_i.clone(), None)
                        else {
                            info!("EDHOC error at parse_message_3");
                            continue;
                        };

                        info!("Prepare message_4");
                        let (responder, message_4) = responder.prepare_message_4(&EadItems::new()).unwrap();

                        info!("Send message_4");
                        common::transmit_without_response(
                            &mut radio,
                            common::Packet::new_from_slice(
                                message_4.as_slice(),
                                Some(c_r.unwrap().as_slice()[0]),
                            )
                                .unwrap(),
                        )
                            .await;

                        info!("Handshake completed. prk_out = {:X}", r_prk_out);
                    } else {
                        info!("Another packet interrupted the handshake.");
                    }
                }
                Err(PacketError::TimeoutError) => info!("Timeout while waiting for message_3!"),
                Err(_) => panic!("Unexpected error"),
            }
        }
    }
}

#[embassy_executor::task]
async fn example_application_task(secret: BytesHashLen) {
    info!(
        "Successfully spawned an application task. EDHOC prk_out: {:X}",
        secret
    );
}
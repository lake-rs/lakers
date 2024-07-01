#![no_std]
#![no_main]

use common::{Packet, PacketError, ADV_ADDRESS, ADV_CRC_INIT, CRC_POLY, FREQ, MAX_PDU};
use defmt::info;
use defmt::unwrap;
use embassy_executor::Spawner;
// use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::radio::ble::Mode;
use embassy_nrf::radio::ble::Radio;
use embassy_nrf::radio::TxPower;
use embassy_nrf::{bind_interrupts, peripherals, radio};
// use embassy_time::{Duration, Timer};
use {defmt_rtt as _, panic_probe as _};
use nrf52840_hal::pac;
use nrf52840_hal::prelude::*;
use nrf52840_hal::gpio::{Level, Output, Pin};

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
    let peripherals = pac::Peripherals::take().unwrap();
    let p0 = nrf52840_hal::gpio::p0::Parts::new(peripherals.P0);
    let p1 = nrf52840_hal::gpio::p1::Parts::new(peripherals.P1);

    let mut led_pin_p0_26 = p0.p0_26.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p0_8 = p0.p0_08.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p0_7 = p0.p0_07.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p0_6 = p0.p0_06.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p0_5 = p0.p0_05.into_push_pull_output(nrf52840_hal::gpio::Level::Low);

    let mut led_pin_p1_07 = p1.p1_07.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p1_08 = p1.p1_08.into_push_pull_output(nrf52840_hal::gpio::Level::Low);

    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let embassy_peripherals: embassy_nrf::Peripherals = embassy_nrf::init(config);

    // let mut led_pin_p0_26 = Output::new(embassy_peripherals.P0_26, Level::Low, OutputDrive::Standard);
    // let mut led_pin_p0_10 = Output::new(embassy_peripherals.P0_10, Level::Low, OutputDrive::Standard);
    // let mut led_pin_p0_9 = Output::new(embassy_peripherals.P0_09, Level::Low, OutputDrive::Standard);
    // let mut led_pin_p0_8 = Output::new(embassy_peripherals.P0_08, Level::Low, OutputDrive::Standard);
    // let mut led_pin_p0_7 = Output::new(embassy_peripherals.P0_07, Level::Low, OutputDrive::Standard);
    // let mut led_pin_p0_6 = Output::new(embassy_peripherals.P0_06, Level::Low, OutputDrive::Standard);
    // let mut led_pin_p0_5 = Output::new(embassy_peripherals.P0_05, Level::Low, OutputDrive::Standard);

    info!("Starting BLE radio");
    let mut radio = Radio::new(embassy_peripherals.RADIO, Irqs);

    radio.set_mode(Mode::BLE_1MBIT);
    radio.set_tx_power(TxPower::_0D_BM);
    radio.set_frequency(FREQ);

    radio.set_access_address(ADV_ADDRESS);
    radio.set_header_expansion(false);
    radio.set_crc_init(ADV_CRC_INIT);
    radio.set_crc_poly(CRC_POLY);

    // // Memory buffer for mbedtls
    // #[cfg(feature = "crypto-psa")]
    // let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    // #[cfg(feature = "crypto-psa")]
    // unsafe {
    //     mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    // }
    // Initialize CryptoCell instead of mbedTLS
    #[cfg(feature = "crypto-cell")]
    {
        unsafe {
            nrf_cc310_bl_init(); // Initialize CryptoCell
        }
    }

    info!("Responder started, will wait for messages");

    loop {
        let buffer: [u8; MAX_PDU] = [0x00u8; MAX_PDU];
        let mut c_r: Option<ConnId> = None;

        // info!("Receiving..."); 
        // filter all incoming packets waiting for CBOR TRUE (0xf5)
        let pckt = common::receive_and_filter(
            &mut radio, 
            Some(0xf5), 
            Some(&mut led_pin_p1_07)
            ).await.unwrap();
        // info!("Received message_1");
        // led_pin_p0_26.set_high();

        // PSK
        let cred_i: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
        let cred_r: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
        let responder = EdhocResponder::new(
            lakers_crypto::default_crypto(), 
            EDHOCMethod::PSK2, 
            None, 
            cred_r
        );

        // STATSTAT
        // let cred_i = Credential::parse_ccs(common::CRED_I.try_into().unwrap()).unwrap();
        // let cred_r = Credential::parse_ccs(common::CRED_R.try_into().unwrap()).unwrap();
        // let responder = EdhocResponder::new(
        //     lakers_crypto::default_crypto(), 
        //     EDHOCMethod::StatStat, 
        //     Some(common::R.try_into().unwrap()), 
        //     cred_r
        // );

        led_pin_p0_26.set_high();
        info!("Received message_1");

        let cred_r = Credential::parse_ccs(common::CRED_R.try_into().unwrap()).unwrap();
        let responder = EdhocResponder::new(
            lakers_crypto::default_crypto(),
            EDHOCMethod::StatStat,
            common::R.try_into().unwrap(),
            cred_r,
        );

        let message_1: EdhocMessageBuffer = pckt.pdu[1..pckt.len].try_into().expect("wrong length"); // get rid of the TRUE byte

        led_pin_p0_6.set_high();
        let result = responder.process_message_1(&message_1);
        led_pin_p0_6.set_low();   
        led_pin_p0_26.set_low();
        
        if let Ok((responder, _c_i, ead_1)) = result {
            c_r = Some(generate_connection_identifier_cbor(
                &mut lakers_crypto::default_crypto(),
            ));
            let ead_2 = None;
            info!("Prepare message_2");
            led_pin_p0_26.set_high();
            led_pin_p0_5.set_high();
            let (responder, message_2) = responder
                .prepare_message_2(CredentialTransfer::ByReference, c_r, &ead_2)
                .unwrap();
            led_pin_p0_5.set_low();
            
            // prepend 0xf5 also to message_2 in order to allow the Initiator filter out from other BLE packets
            // info!("Send message_2 and wait message_3");
            led_pin_p0_26.set_low();
            let message_3 = common::transmit_and_wait_response(
                &mut radio,
                Packet::new_from_slice(message_2.as_slice(), Some(0xf5)).expect("wrong length"),
                Some(c_r.unwrap().as_slice()[0]),
                &mut led_pin_p1_08,
            )
            .await;
            
            match message_3 {
                Ok(message_3) => {
                    info!("Received message_3");
                    led_pin_p0_26.set_high();

                    let rcvd_c_r: ConnId = ConnId::from_int_raw(message_3.pdu[0] as u8);

                    if rcvd_c_r == c_r.unwrap() {
                        let message_3: EdhocMessageBuffer = message_3.pdu[1..message_3.len]
                            .try_into()
                            .expect("wrong length");
                        led_pin_p0_8.set_high();
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
                            credential_check_or_fetch(Some(cred_i), id_cred_i).unwrap();
                        let Ok((responder, r_prk_out)) = responder.verify_message_3(valid_cred_i)
                        else {
                            info!("EDHOC error at parse_message_3");
                            continue;
                        };

                        info!("Prepare message_4");
                        let ead_4 = None;
                        let (responder, message_4) = responder.prepare_message_4(&ead_4).unwrap();

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

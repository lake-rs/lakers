#![no_std]
#![no_main]

//! EDHOC Initiator on the nRF54L15.

use defmt::info;
use lakers::*;
use lakers_nrf54l15::{hardware_crypto, Packet, Radio, CRED_I, CRED_R, I};
use {defmt_rtt as _, panic_probe as _};

#[cortex_m_rt::entry]
fn main() -> ! {
    info!("starting ble radio");
    let mut radio = Radio::new();

    info!("init_handshake");

    let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
    let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

    let mut initiator = EdhocInitiator::new(
        hardware_crypto(),
        EDHOCMethod::StatStat,
        EDHOCSuite::CipherSuite2,
    );
    initiator
        .set_identity(
            InitiatorIdentity::StatStat {
                i: I.try_into().unwrap(),
            },
            cred_i,
        )
        .unwrap();

    // The nRF54L15 has a single CRACEN, so we can't spin up a second `Crypto` just to pick a
    // connection identifier; pass `None` and let the initiator generate c_i with its own crypto.
    let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();

    // Send message_1 (prefixed with cbor true, 0xf5) and block until message_2 comes back.
    let pckt_1 = Packet::new(0xf5, message_1.as_slice()).expect("buffer not long enough");
    let pckt_2 = radio.transmit_and_wait_response(pckt_1, 0xf5);

    info!("received message_2");
    let message_2: EdhocMessageBuffer = pckt_2.payload().try_into().expect("wrong length");
    info!("message_2 :{:?}", message_2.as_slice());

    let (initiator, c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
    let initiator = initiator.verify_message_2(Some(cred_r)).unwrap();

    let (initiator, message_3, i_prk_out) = initiator
        .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
        .unwrap();

    // From now on packets are filtered by c_r (the responder's connection identifier).
    info!("send message_3 and wait message_4");
    let pckt_3 =
        Packet::new(c_r.as_slice()[0], message_3.as_slice()).expect("buffer not long enough");
    let pckt_4 = radio.transmit_and_wait_response(pckt_3, c_r.as_slice()[0]);

    info!("received message_4");
    let message_4: EdhocMessageBuffer = pckt_4.payload().try_into().expect("wrong length");

    let (_initiator, _ead_4) = initiator.process_message_4(&message_4).unwrap();

    info!("handshake completed. prk_out = {:X}", i_prk_out);

    loop {
        cortex_m::asm::wfi();
    }
}

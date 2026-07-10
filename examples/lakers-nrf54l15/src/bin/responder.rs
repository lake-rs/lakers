#![no_std]
#![no_main]

//! EDHOC Responder on the nRF54L15.

use defmt::info;
use lakers::*;
use lakers_nrf54l15::{hardware_crypto, Packet, Radio, CRED_I, CRED_R, R};
use {defmt_rtt as _, panic_probe as _};

#[cortex_m_rt::entry]
fn main() -> ! {
    info!("starting ble radio");
    let mut radio = Radio::new();

    info!("responder started, will wait for messages");

    loop {
        // filter all incoming packets, waiting for cbor true (0xf5), which prefixes message_1
        let pckt = radio.receive_and_filter(Some(0xf5));
        info!("received message_1");

        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();
        // Each handshake gets its own hardware `Crypto`; the previous one was dropped at the end of
        // the last iteration, so only one is ever alive on the single CRACEN.
        let responder = EdhocResponder::new(hardware_crypto(), R.try_into().unwrap(), cred_r);

        // get rid of the 0xf5 metadata byte
        let message_1: EdhocMessageBuffer = pckt.pdu[1..pckt.len].try_into().expect("wrong length");

        let Ok((responder, _c_i, _ead_1)) = responder.process_message_1(&message_1) else {
            info!("edhoc error at process_message_1");
            continue;
        };

        // The nRF54L15 has a single CRACEN, so we can't spin up a second `Crypto` just to pick a
        // connection identifier; use a fixed c_r instead.
        let c_r = ConnId::from_slice(&[0x08]).unwrap();
        let ead_2 = EadItems::new();

        let (responder, message_2) = responder
            .prepare_message_2(CredentialTransfer::ByReference, Some(c_r), &ead_2)
            .unwrap();

        // prepend 0xf5 to message_2 too so the initiator can filter it out from other ble packets,
        // then wait for message_3, now filtered by c_r
        let pckt_3 = radio.transmit_and_wait_response(
            Packet::new_from_slice(message_2.as_slice(), Some(0xf5)).expect("wrong length"),
            Some(c_r.as_slice()[0]),
        );
        info!("received message_3");

        let rcvd_c_r = ConnId::from_slice(&[pckt_3.pdu[0]]).unwrap();
        if rcvd_c_r != c_r {
            info!("another packet interrupted the handshake");
            continue;
        }

        let message_3: EdhocMessageBuffer =
            pckt_3.pdu[1..pckt_3.len].try_into().expect("wrong length");
        let Ok((responder, id_cred_i, _ead_3)) = responder.parse_message_3(&message_3) else {
            info!("edhoc error at parse_message_3");
            continue;
        };

        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i).unwrap();
        let Ok((responder, r_prk_out)) = responder.verify_message_3(valid_cred_i) else {
            info!("edhoc error at verify_message_3");
            continue;
        };

        info!("prepare message_4");
        let ead_4 = EadItems::new();
        let (_responder, message_4) = responder.prepare_message_4(&ead_4).unwrap();

        info!("send message_4");
        radio.transmit_without_response(
            Packet::new_from_slice(message_4.as_slice(), Some(c_r.as_slice()[0])).unwrap(),
        );

        info!("handshake completed. prk_out = {:X}", r_prk_out);
    }
}

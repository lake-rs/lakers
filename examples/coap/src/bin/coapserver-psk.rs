use coap_lite::{CoapRequest, Packet, ResponseType};
use hexlit::hex;
use lakers::*;
use log::*;
use std::net::UdpSocket;
use defmt_or_log::info;
use hex::encode;

// const ID_CRED: &[u8] = &hex!("a1044120");
const CRED_PSK: &[u8] =
    &hex!("A202686D79646F74626F7408A101A30104024110205050930FF462A77A3540CF546325DEA214");

// Run with RUST_LOG=info cargo run --bin coapserver-psk2

fn main() {
    env_logger::init();
    info!("Starting EDHOC CoAP Server");

    let mut buf = [0; MAX_MESSAGE_SIZE_LEN];
    let socket = UdpSocket::bind("127.0.0.1:5683").unwrap();
    // let socket = UdpSocket::bind("0.0.0.0:5683").unwrap(); // Listen on all available network interfaces

    let mut edhoc_connections = Vec::new();

    println!("Waiting for CoAP messages...");
    loop {
        let (size, src) = socket.recv_from(&mut buf).expect("Didn't receive data");
        let packet = Packet::from_bytes(&buf[..size]).unwrap();
        let request = CoapRequest::from_packet(packet, src);

        let path = request.get_path();
        let mut response = request.response.unwrap();

        if path == ".well-known/edhoc" {
            println!("Received message from {}", src);
            // This is an EDHOC message
            if request.message.payload[0] == 0xf5 {
                let cred_psk: Credential =
                    Credential::parse_ccs_symmetric(CRED_PSK.try_into().unwrap()).unwrap();
                let responder = EdhocResponder::new(
                    lakers_crypto::default_crypto(),
                    EDHOCMethod::PSK,
                    None,
                    cred_psk,
                );
                println!("cred:{:?}", cred_psk);

                println!("\n---------MESSAGE_1-----------\n");
                let message_1: EdhocMessageBuffer = request.message.payload[1..]
                    .try_into()
                    .expect("wrong length");
                // println!("message_1_rcvd:{:?}", message_1);
                println!("message_1 len:{:?}", message_1.len);
                let result = responder.process_message_1(&message_1);
                println!("\n---------MESSAGE_2-----------\n");
                if let Ok((responder, _c_i, ead_1)) = result {
                    let c_r = ConnId::from_int_raw(5);
                    // let c_r =
                    // generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
                    let ead_2 = None;
                    let (responder, message_2) = responder
                        .prepare_message_2(CredentialTransfer::ByReference, Some(c_r), &ead_2)
                        .unwrap();
                    response.message.payload = Vec::from(message_2.as_slice());
                    // save edhoc connection
                    edhoc_connections.push((c_r, responder));
                    println!("message_2 : 0x{}", encode(message_2.as_slice()));
                } else {
                    println!("msg1 err");
                    response.set_status(ResponseType::BadRequest);
                }
            } else {
                println!("\n---------MESSAGE_3-----------\n");
                // potentially message 3
                println!("Received message 3");
                let c_r_rcvd = ConnId::from_int_raw(request.message.payload[0]);
                // FIXME let's better not *panic here
                let responder = take_state(c_r_rcvd, &mut edhoc_connections).unwrap();

                println!("Found state with connection identifier {:?}", c_r_rcvd);
                let message_3 =
                    EdhocMessageBuffer::new_from_slice(&request.message.payload[1..]).unwrap();
                println!("message_3: 0x{}", encode(message_3.as_slice()));
                let Ok((responder, id_cred_i, _ead_3)) = responder.parse_message_3(&message_3)
                else {
                    println!("EDHOC error at parse_message_3: {:?}", message_3);
                    // We don't get another chance, it's popped and can't be used any further
                    // anyway legally
                    continue;
                };
                println!("message_3 parsed");
                let cred = Credential::parse_ccs_symmetric(CRED_PSK.try_into().unwrap()).unwrap();
                let valid_cred_i =
                    credential_check_or_fetch(Some(cred), id_cred_i.unwrap()).unwrap();
                let Ok(mut responder) = responder.verify_message_3(valid_cred_i) else {
                    println!("EDHOC error at verify_message_3: {:?}", valid_cred_i);
                    continue;
                };
                // Prepare message_4
                println!("\n---------MESSAGE_3-----------\n");
                println!("Preparing message_4");
                let ead_4: Option<EADItem> = None;
                let result = responder.prepare_message_4(CredentialTransfer::ByReference, &ead_4);
                match result {
                    Ok((mut responder, message_4, prk_out)) => {
                        // Handle the success case
                        println!("Message 4 prepared successfully");
                        // Use responder, message_4, and prk_out as needed
                        println!("message_4: 0x{}", encode(message_4.as_slice()));
                        response.message.payload = Vec::from(message_4.as_slice());
                        // response.message.payload = b"".to_vec();

                        println!("EDHOC exchange successfully completed");
                        println!("PRK_out: {:02x?}", prk_out);

                        let mut _oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
                        // println!("OSCORE secret: {:02x?}", _oscore_secret);
                        let mut _oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1
                        // println!("OSCORE salt: {:02x?}", _oscore_salt);

                        // context of key update is a test vector from draft-ietf-lake-traces
                        let prk_out_new = responder.edhoc_key_update(&[
                            0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02,
                            0xb8, 0xbc, 0xea,
                        ]);
                        println!("PRK_out after key update: {:02x?}?", prk_out_new);

                        _oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
                        // println!("OSCORE secret after key update: {:02x?}", _oscore_secret);
                        _oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1
                        // println!("OSCORE salt after key update: {:02x?}", _oscore_salt);
                    },
                    Err(e) => {
                        // Handle the error case
                        println!("Error preparing message 4: {:?}", e);
                        // Decide how to proceed in case of an error
                    }
                }
            }
            response.set_status(ResponseType::Changed);
        } else {
            println!("Received message at unknown resource");
            response.message.payload = b"Resource not found".to_vec();
            response.set_status(ResponseType::BadRequest);
        }
        let packet = response.message.to_bytes().unwrap();
        socket
            .send_to(&packet[..], &src)
            .expect("Could not send the data");
    }
}

fn take_state<R>(
    c_r_rcvd: ConnId,
    edhoc_protocol_states: &mut Vec<(ConnId, R)>,
) -> Result<R, &'static str> {
    for (i, element) in edhoc_protocol_states.iter().enumerate() {
        let (c_r, _responder) = element;
        if *c_r == c_r_rcvd {
            let max_index = edhoc_protocol_states.len() - 1;
            edhoc_protocol_states.swap(i, max_index);
            let Some((_c_r, responder)) = edhoc_protocol_states.pop() else {
                unreachable!();
            };
            return Ok(responder);
        }
    }
    return Err("No stored state available for that C_R");
}
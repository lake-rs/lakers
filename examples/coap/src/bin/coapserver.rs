use coap_lite::{CoapRequest, Packet, ResponseType};
use defmt_or_log::info;
use hexlit::hex;
use lakers::*;
use lakers_ead_authz::{ZeroTouchAuthenticator, ZeroTouchServer};
use std::net::UdpSocket;

const ID_CRED_I: &[u8] = &hex!("a104412b");
const _ID_CRED_R: &[u8] = &hex!("a104410a");
const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");

// ead authz
const W_TV: &[u8] = &hex!("4E5E15AB35008C15B89E91F9F329164D4AACD53D9923672CE0019F9ACD98573F");

fn main() {
    env_logger::init();
    info!("Starting EDHOC CoAP Server");

    let mut buf = [0; MAX_MESSAGE_SIZE_LEN];
    let socket = UdpSocket::bind("127.0.0.1:5683").unwrap();

    let mut edhoc_connections = Vec::new();

    // ead authz server (W)
    let acl = EdhocMessageBuffer::new_from_slice(&[ID_CRED_I[3]]).unwrap(); // [kid]
    let server = ZeroTouchServer::new(
        W_TV.try_into().unwrap(),
        CRED_R.try_into().unwrap(),
        Some(acl),
    );

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
                let cred_r: Credential = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();
                let responder = EdhocResponder::new(
                    lakers_crypto::default_crypto(),
                    EDHOCMethod::StatStat,
                    Some(R.try_into().unwrap()),
                    cred_r,
                );

                let message_1: BufferMessage1 = request.message.payload[1..]
                    .try_into()
                    .expect("wrong length");
                let result = responder.process_message_1(&message_1);

                if let Ok((responder, _c_i, mut ead_1)) = result {
                    let c_r =
                        generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());

                    let mut ead_2 = EadItems::new();
                    if let Some(ead_item) =
                        ead_1.pop_by_label(lakers_ead_authz::consts::EAD_AUTHZ_LABEL)
                    {
                        let authenticator = ZeroTouchAuthenticator::default();
                        let (authenticator, _loc_w, voucher_request) =
                            authenticator.process_ead_1(&ead_item, &message_1).unwrap();

                        // mock a request to the server
                        let voucher_response = server
                            .handle_voucher_request(
                                &mut lakers_crypto::default_crypto(),
                                &voucher_request,
                            )
                            .unwrap();

                        let res = authenticator.prepare_ead_2(&voucher_response);
                        assert!(res.is_ok());

                        ead_2.try_push(res.unwrap()).unwrap();
                    }
                    ead_1.processed_critical_items().unwrap();

                    let (responder, message_2) = responder
                        .prepare_message_2(CredentialTransfer::ByReference, Some(c_r), &ead_2)
                        .unwrap();
                    response.message.payload = Vec::from(message_2.as_slice());
                    // save edhoc connection
                    edhoc_connections.push((c_r, responder));
                    println!("message_2 : {:?}", message_2.as_slice());
                    println!("message_2 len = {}", message_2.len());


                } else {
                    println!("msg1 err");
                    response.set_status(ResponseType::BadRequest);
                }
            } else {
                // potentially message 3
                println!("Received message 3");
                #[allow(deprecated)]
                let c_r_rcvd = ConnId::from_int_raw(request.message.payload[0]);
                // FIXME let's better not *panic here
                let responder = take_state(c_r_rcvd, &mut edhoc_connections).unwrap();

                println!("Found state with connection identifier {:?}", c_r_rcvd);
                let message_3 = EdhocBuffer::new_from_slice(&request.message.payload[1..]).unwrap();
                let Ok((responder, id_cred_i, ead_3)) = responder.parse_message_3(&message_3)
                else {
                    println!("EDHOC error at parse_message_3: {:?}", message_3);
                    // We don't get another chance, it's popped and can't be used any further
                    // anyway legally
                    continue;
                };
                ead_3.processed_critical_items().unwrap();
                let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
                let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i.unwrap()).unwrap();
                // FIXME: instead of cloning, take by reference
                let Ok((responder, prk_out)) = responder.verify_message_3(valid_cred_i.clone())
                else {
                    println!("EDHOC error at verify_message_3: {:?}", valid_cred_i);
                    continue;
                };
                let (mut responder, message_4) =
                    responder.prepare_message_4(&EadItems::new()).unwrap();
                // send empty ack back
                response.message.payload = Vec::from(message_4.as_slice());

                println!("EDHOC exchange successfully completed");
                println!("PRK_out: {:02x?}", prk_out);

                let mut oscore_secret = [0; 16];
                responder.edhoc_exporter(0u8, &[], &mut oscore_secret); // label is 0
                println!("OSCORE secret: {:02x?}", oscore_secret);
                let mut oscore_salt = [0; 8];
                responder.edhoc_exporter(1u8, &[], &mut oscore_salt); // label is 1
                println!("OSCORE salt: {:02x?}", oscore_salt);

                // context of key update is a test vector from draft-ietf-lake-traces
                let prk_out_new = responder.edhoc_key_update(&[
                    0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02,
                    0xb8, 0xbc, 0xea,
                ]);
                println!("PRK_out after key update: {:02x?}?", prk_out_new);

                responder.edhoc_exporter(0u8, &[], &mut oscore_secret); // label is 0
                println!("OSCORE secret after key update: {:02x?}", oscore_secret);
                responder.edhoc_exporter(1u8, &[], &mut oscore_salt); // label is 1
                println!("OSCORE salt after key update: {:02x?}", oscore_salt);
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

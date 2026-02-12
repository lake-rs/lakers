use coap::CoAPClient;
use coap_lite::ResponseType;
use defmt_or_log::info;
use hex::encode;
use hexlit::hex;
use lakers::*;
use std::time::Duration;

const _ID_CRED_PSK: &[u8] = &hex!("a1044120");
const CRED_I: &[u8] =
    &hex!("A20269696E69746961746F7208A101A30104024110205050930FF462A77A3540CF546325DEA214");
const CRED_R: &[u8] =
    &hex!("A20269726573706F6E64657208A101A30104024110205050930FF462A77A3540CF546325DEA214");

fn main() {
    env_logger::init();
    info!("Starting EDHOC CoAP Client");
    match client_handshake() {
        Ok(_) => println!("Handshake completed"),
        Err(e) => panic!("Handshake failed with error: {:?}", e),
    }
}

fn client_handshake() -> Result<(), EDHOCError> {
    // let url = "coap://10.56.24.235:5683/.well-known/edhoc";
    let url = "coap://127.0.0.1:5683/.well-known/edhoc";
    let timeout = Duration::new(5, 0);
    println!("Client request: {}", url);

    let cred_i: Credential = Credential::parse_ccs_symmetric(CRED_I.try_into().unwrap()).unwrap();
    let cred_r: Credential = Credential::parse_ccs_symmetric(CRED_R.try_into().unwrap()).unwrap();

    let mut initiator = EdhocInitiator::new(
        lakers_crypto::default_crypto(),
        EDHOCMethod::PSK,
        EDHOCSuite::CipherSuite2,
    );
    println!("\n---------MESSAGE_1-----------\n");
    // Send Message 1 over CoAP and convert the response to byte
    let mut msg_1_buf = Vec::from([0xf5u8]); // EDHOC message_1 when transported over CoAP is prepended with CBOR true
                                             // let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
    #[allow(deprecated)]
    let c_i = ConnId::from_int_raw(10);
    // println!("c_i: {:?}", c_i);
    initiator.set_identity(None, cred_i.clone());
    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &EadItems::new())?;
    println!("message_1 len = {}", message_1.len());
    println!("message_1 = 0x{}", encode(message_1.as_slice()));
    msg_1_buf.extend_from_slice(message_1.as_slice());

    let response = CoAPClient::post_with_timeout(url, msg_1_buf, timeout).unwrap();
    if response.get_status() != &ResponseType::Changed {
        panic!("Message 1 response error: {:?}", response.get_status());
    }
    println!("\n---------MESSAGE_2-----------\n");
    // println!("response_vec = {:02x?}", response.message.payload);
    println!(
        "message_2 : 0x{}",
        encode(response.message.payload.as_slice())
    );
    println!("message_2 len = {}", response.message.payload.len());

    let message_2 = EdhocMessageBuffer::new_from_slice(&response.message.payload[..]).unwrap();
    let (initiator, c_r, _id_cred_r, _ead_2) = initiator.parse_message_2(&message_2)?;

    let initiator = initiator.verify_message_2(cred_r)?;

    println!("\n---------MESSAGE_3-----------\n");
    let mut msg_3 = Vec::from(c_r.as_cbor());
    let (initiator, message_3, prk_out) =
        initiator.prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())?;

    msg_3.extend_from_slice(message_3.as_slice());
    println!("message_3 len = {}", msg_3.len());
    println!("message_3 = 0x{}", encode(message_3.as_slice()));

    let response = CoAPClient::post_with_timeout(url, msg_3, timeout).unwrap();
    if response.get_status() != &ResponseType::Changed {
        panic!("Message 4 response error: {:?}", response.get_status());
    }
    println!("\n---------MESSAGE_4-----------\n");
    println!("message_4 len = {}", response.message.payload.len());
    let message_4 = EdhocMessageBuffer::new_from_slice(&response.message.payload[..]).unwrap();
    println!("message_4: 0x{}", encode(message_4.as_slice()));

    println!("Entering parse message 4");
    let (initiator, _ead_4) = initiator.parse_message_4(&message_4)?;
    println!("Entering verify message 4");
    let mut initiator = initiator.verify_message_4()?;

    println!("\n---------END-----------\n");
    println!("EDHOC exchange successfully completed");
    println!("PRK_out: {:02x?}", prk_out);

    let mut oscore_secret = [0; 16];
    initiator.edhoc_exporter(0u8, &[], &mut oscore_secret); // label is 0
    let mut oscore_salt = [0; 8];
    initiator.edhoc_exporter(1u8, &[], &mut oscore_salt); // label is 1

    // println!("OSCORE secret: {:02x?}", oscore_secret);
    // println!("OSCORE salt: {:02x?}", oscore_salt);

    // context of key update is a test vector from draft-ietf-lake-traces
    let prk_out_new = initiator.edhoc_key_update(&[
        0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8, 0xbc,
        0xea,
    ]);

    println!("PRK_out after key update: {:02x?}?", prk_out_new);

    // compute OSCORE secret and salt after key update
    initiator.edhoc_exporter(0u8, &[], &mut oscore_secret); // label is 0
    initiator.edhoc_exporter(1u8, &[], &mut oscore_salt); // label is 1

    // println!("OSCORE secret after key update: {:02x?}", oscore_secret);
    // println!("OSCORE salt after key update: {:02x?}", oscore_salt);

    Ok(())
}

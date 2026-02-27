use coap::CoAPClient;
use coap_lite::ResponseType;
use defmt_or_log::info;
use hexlit::hex;
use lakers::*;
use std::time::Duration;

const _ID_CRED_I: &[u8] = &hex!("a104412b");
const _ID_CRED_R: &[u8] = &hex!("a104410a");
const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
const _G_I_X_COORD: &[u8] =
    &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
const _G_I_Y_COORD: &[u8] =
    &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
const _G_R: &[u8] = &hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");

fn main() {
    env_logger::init();
    info!("Starting EDHOC CoAP Client");
    match client_handshake() {
        Ok(_) => println!("Handshake completed"),
        Err(e) => panic!("Handshake failed with error: {:?}", e),
    }
}

fn client_handshake() -> Result<(), EDHOCError> {
    let url = "coap://127.0.0.1:5683/.well-known/edhoc";
    let timeout = Duration::new(5, 0);
    println!("Client request: {}", url);

    let cred_i: Credential = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
    let cred_r: Credential = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

    let initiator = EdhocInitiator::new(
        lakers_crypto::default_crypto(),
        EDHOCMethod::StatStat,
        EDHOCSuite::CipherSuite2,
    );

    // Send Message 1 over CoAP and convert the response to byte
    let mut msg_1_buf = Vec::from([0xf5u8]); // EDHOC message_1 when transported over CoAP is prepended with CBOR true
    let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &EadItems::new())?;
    msg_1_buf.extend_from_slice(message_1.as_slice());
    println!("message_1 len = {}", msg_1_buf.len());

    let response = CoAPClient::post_with_timeout(url, msg_1_buf, timeout).unwrap();
    if response.get_status() != &ResponseType::Changed {
        panic!("Message 1 response error: {:?}", response.get_status());
    }
    println!("response_vec = {:02x?}", response.message.payload);
    println!("message_2 len = {}", response.message.payload.len());

    let message_2 = EdhocBuffer::new_from_slice(&response.message.payload[..]).unwrap();
    let (mut initiator, c_r, details) = initiator.parse_message_2(&message_2)?;
    let ParsedMessage2Details::StatStat { id_cred_r, ead_2 } = details;
    ead_2.processed_critical_items().unwrap();
    let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r).unwrap();
    initiator.set_identity(I.try_into().unwrap(), cred_i)?;
    let initiator = initiator.verify_message_2(valid_cred_r)?;

    let mut msg_3 = Vec::from(c_r.as_cbor());
    let (initiator, message_3, prk_out) =
        initiator.prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())?;
    msg_3.extend_from_slice(message_3.as_slice());
    println!("message_3 len = {}", msg_3.len());

    let response = CoAPClient::post_with_timeout(url, msg_3, timeout).unwrap();
    if response.get_status() != &ResponseType::Changed {
        panic!("Message 3 response error: {:?}", response.get_status());
    }
    println!("response_vec = {:02x?}", response.message.payload);
    println!("message_3 len = {}", response.message.payload.len());
    let message_4 = EdhocBuffer::new_from_slice(&response.message.payload[..]).unwrap();
    let (mut initiator, ead_4) = initiator.process_message_4(&message_4).unwrap();
    ead_4.processed_critical_items().unwrap();

    println!("EDHOC exchange successfully completed");
    println!("PRK_out: {:02x?}", prk_out);

    let mut oscore_secret = [0; 16];
    initiator.edhoc_exporter(0u8, &[], &mut oscore_secret); // label is 0
    let mut oscore_salt = [0; 8];
    initiator.edhoc_exporter(1u8, &[], &mut oscore_salt); // label is 1

    println!("OSCORE secret: {:02x?}", oscore_secret);
    println!("OSCORE salt: {:02x?}", oscore_salt);

    // context of key update is a test vector from draft-ietf-lake-traces
    let prk_out_new = initiator.edhoc_key_update(&[
        0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8, 0xbc,
        0xea,
    ]);

    println!("PRK_out after key update: {:02x?}?", prk_out_new);

    // compute OSCORE secret and salt after key update
    initiator.edhoc_exporter(0u8, &[], &mut oscore_secret); // label is 0
    initiator.edhoc_exporter(1u8, &[], &mut oscore_salt); // label is 1

    println!("OSCORE secret after key update: {:02x?}", oscore_secret);
    println!("OSCORE salt after key update: {:02x?}", oscore_salt);

    Ok(())
}

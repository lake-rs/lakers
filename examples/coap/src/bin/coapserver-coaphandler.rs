use hexlit::hex;
use lakers::*;
use lakers_crypto::Crypto;
use lakers_ead_authz::{ZeroTouchAuthenticator, ZeroTouchServer};

use coap_message::{Code, MinimalWritableMessage, MutableWritableMessage, ReadableMessage};
use coap_message_utils::{Error, OptionsExt as _};
use embedded_nal::UdpFullStack;

const ID_CRED_I: &[u8] = &hex!("a104412b");
const _ID_CRED_R: &[u8] = &hex!("a104410a");
const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
const _G_I: &[u8] = &hex!("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
const _G_I_Y_COORD: &[u8] =
    &hex!("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");

// authz server
const W_TV: &[u8] = &hex!("4E5E15AB35008C15B89E91F9F329164D4AACD53D9923672CE0019F9ACD98573F");

#[derive(Debug)]
struct EdhocHandler {
    connections: Vec<(ConnId, EdhocResponderWaitM3<Crypto>)>,
    mock_server: ZeroTouchServer,
}

/// Render a MessageBufferError into the common Error type.
///
/// It is yet to be determined whether anything more informative should be returned (likely it
/// should; maybe Request Entity Too Large or some error code about unusable credential.
///
/// Places using this function may be simplified if From/Into is specified (possibly after
/// enlarging the Error type)
fn too_small(_e: EdhocBufferError) -> Error {
    Error::bad_request()
}

/// Render an EDHOCError into the common Error type.
///
/// It is yet to be decided based on the EDHOC specification which EDHOCError values would be
/// reported with precise data, and which should rather produce a generic response.
///
/// Places using this function may be simplified if From/Into is specified (possibly after
/// enlarging the Error type)
fn render_error(_e: EDHOCError) -> Error {
    Error::bad_request()
}

impl EdhocHandler {
    fn take_connection_by_c_r(&mut self, c_r: ConnId) -> Option<EdhocResponderWaitM3<Crypto>> {
        let index = self
            .connections
            .iter()
            .position(|(current_c_r, _)| current_c_r == &c_r)?;
        let last = self.connections.len() - 1;
        self.connections.swap(index, last);
        Some(self.connections.pop().unwrap().1)
    }

    fn new_c_r(&self) -> ConnId {
        // FIXME: We'll need to do better, but a) that'll be more practical when we can do more
        // than u8, and b) that'll best be coordinated with a storage that not only stores EDHOC
        // contexts but also OSCORE ones.
        let result = self.connections.len();
        if result >= 24 {
            panic!("Contexts exceeded");
        }
        #[allow(deprecated)]
        ConnId::from_int_raw(result as _)
    }
}

enum EdhocResponse {
    // We could also store the responder in the Vec (once we're done rendering the response, we'll
    // take up a slot there anyway) if we make it an enum.
    OkSend2 {
        c_r: ConnId,
        responder: EdhocResponderProcessedM1<Crypto>,
        // FIXME: Is the ead_2 the most practical data to store here? An easy alternative is the
        // voucher_response; ideal would be the voucher, bu that is only internal to prepare_ead_2.
        //
        // Also, we'll want to carry around the set of actually authenticated claims (right now
        // it's just "if something is here, our single W completed authz")
        ead_2: EadItems,
    },
    Message3Processed,
}

impl coap_handler::Handler for EdhocHandler {
    type RequestData = EdhocResponse;

    type ExtractRequestError = Error;
    type BuildResponseError<M: MinimalWritableMessage> = M::UnionError;

    fn extract_request_data<M: ReadableMessage>(
        &mut self,
        request: &M,
    ) -> Result<Self::RequestData, Self::ExtractRequestError> {
        if request.code().into() != coap_numbers::code::POST {
            return Err(Error::method_not_allowed());
        }

        request.options().ignore_elective_others()?;

        let first_byte = request.payload().get(0).ok_or_else(Error::bad_request)?;
        let starts_with_true = first_byte == &0xf5;

        if starts_with_true {
            let cred_r =
                Credential::parse_ccs(CRED_R.try_into().expect("Static credential is too large"))
                    .expect("Static credential is not processable");

            let message_1 =
                &EdhocBuffer::new_from_slice(&request.payload()[1..]).map_err(too_small)?;
            let r_arr: [u8; 32] = R.try_into().expect("Wrong length of responder private key");
            let r_opt: Option<[u8; 32]> = Some(r_arr);
            let (responder, _c_i, mut ead_1) = EdhocResponder::new(
                lakers_crypto::default_crypto(),
                EDHOCMethod::StatStat,
                r_opt,
                //R.try_into().expect("Wrong length of responder private key"),
                cred_r,
            )
            .process_message_1(message_1)
            .map_err(render_error)?;

            let mut ead_2 = EadItems::new();
            if let Some(ead1_item) = ead_1.pop_by_label(lakers_ead_authz::consts::EAD_AUTHZ_LABEL) {
                let authenticator = ZeroTouchAuthenticator::default();
                let (authenticator, _loc_w, voucher_request) = authenticator
                    .process_ead_1(&ead1_item, &message_1)
                    .map_err(render_error)?;

                // mock a request to the server
                let voucher_response = self
                    .mock_server
                    .handle_voucher_request(&mut lakers_crypto::default_crypto(), &voucher_request)
                    .map_err(render_error)?;

                let ead_item = authenticator
                    .prepare_ead_2(&voucher_response)
                    .map_err(render_error)?;

                println!("Authenticator confirmed authz");
                ead_2.try_push(ead_item).expect("ead_2 is already full");
            }
            ead_1.processed_critical_items().map_err(render_error)?;

            let c_r = self.new_c_r();
            Ok(EdhocResponse::OkSend2 {
                c_r,
                responder,
                ead_2,
            })
        } else {
            // potentially message 3
            //
            // FIXME: Work with longer IDs as well (https://github.com/openwsn-berkeley/lakers/issues/258)
            let (c_r_rcvd, message_3) = request
                .payload()
                .split_first()
                // FIXME: Being way too short, is that an EDHOC error or a CoAP error?
                .ok_or_else(Error::bad_request)?;

            // FIXME: This panics or creates an in valid ConnId (but once we fix
            // working with longer IDs, there will be a function that has proper error handling)
            #[allow(deprecated)]
            let c_r_rcvd = ConnId::from_int_raw(*c_r_rcvd);

            let responder = self
                .take_connection_by_c_r(c_r_rcvd)
                // FIXME: Produce proper error
                .ok_or_else(Error::bad_request)?;

            println!("Found state with connection identifier {:?}", c_r_rcvd);

            let message_3 = EdhocBuffer::new_from_slice(&message_3).map_err(too_small)?;
            let result = responder.parse_message_3(&message_3, None, None);
            let (responder, id_cred_i, ead_3) = result.map_err(|e| {
                println!("EDHOC processing error: {:?}", e);
                render_error(e)
            })?;
            ead_3.processed_critical_items().map_err(|e| {
                println!("Critical EAD3 items were present that were not processed: {ead_3:?}");
                render_error(e)
            })?;
            let cred_i =
                Credential::parse_ccs(CRED_I.try_into().expect("Static credential is too large"))
                    .expect("Static credential is not processable");
            let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i.unwrap())
                .map_err(render_error)?;
            let (responder, prk_out) =
                responder
                    .verify_message_3(valid_cred_i, None)
                    .map_err(|e| {
                        println!("EDHOC processing error: {:?}", e);
                        render_error(e)
                    })?;

            let (mut responder, _message_4) =
                responder.prepare_message_4(&EadItems::new()).unwrap();
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
                0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8,
                0xbc, 0xea,
            ]);
            println!("PRK_out after key update: {:02x?}?", prk_out_new);

            responder.edhoc_exporter(0u8, &[], &mut oscore_secret); // label is 0
            println!("OSCORE secret after key update: {:02x?}", oscore_secret);
            responder.edhoc_exporter(1u8, &[], &mut oscore_salt); // label is 1
            println!("OSCORE salt after key update: {:02x?}", oscore_salt);

            Ok(EdhocResponse::Message3Processed)
        }
    }
    fn estimate_length(&mut self, _: &Self::RequestData) -> usize {
        200
    }
    fn build_response<M: MutableWritableMessage>(
        &mut self,
        response: &mut M,
        req: Self::RequestData,
    ) -> Result<(), Self::BuildResponseError<M>> {
        response.set_code(M::Code::new(coap_numbers::code::CHANGED)?);
        match req {
            EdhocResponse::OkSend2 {
                c_r,
                responder,
                ead_2,
            } => {
                let (responder, message_2) = responder
                    .prepare_message_2(CredentialTransfer::ByReference, Some(c_r), &ead_2)
                    .unwrap();
                self.connections.push((c_r, responder));
                response.set_payload(message_2.as_slice())?;
            }
            EdhocResponse::Message3Processed => (), // "send empty ack back"?
        };
        Ok(())
    }
}

fn build_handler() -> impl coap_handler::Handler {
    use coap_handler_implementations::{HandlerBuilder, ReportingHandlerBuilder};

    // ead authz server (W)
    let acl = EdhocMessageBuffer::new_from_slice(&[ID_CRED_I[3]]).unwrap(); // [kid]
    let mock_server = ZeroTouchServer::new(
        W_TV.try_into().unwrap(),
        CRED_R.try_into().unwrap(),
        Some(acl),
    );

    let edhoc = EdhocHandler {
        connections: Vec::with_capacity(3),
        mock_server,
    };

    coap_handler_implementations::new_dispatcher()
        .at_with_attributes(&[".well-known", "edhoc"], &[], edhoc)
        .with_wkc()
}

fn main_on_stack<S: UdpFullStack>(stack: &mut S) {
    let mut sock = stack.socket().expect("Can't create a socket");

    let mut handler = build_handler();

    stack.bind(&mut sock, 5683).expect("Can't bind to port");

    loop {
        match embedded_nal_minimal_coapserver::poll(stack, &mut sock, &mut handler) {
            Err(embedded_nal::nb::Error::WouldBlock) => {
                // See <https://github.com/rust-embedded-community/embedded-nal/issues/47>
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            e => e.expect("UDP error during send/receive"),
        }
    }
}

fn main() {
    let mut stack = std_embedded_nal::Stack::default();
    main_on_stack(&mut stack);
}

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lakers_shared.h"
#include "lakers.h"
#include <coap3/coap.h>
#include <arpa/inet.h>

static const uint8_t CRED_I_PSK[] = {0xA2, 0x02, 0x69, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6F, 0x72, 0x08, 0xA1, 0x01, 0xA3, 0x01, 0x04, 0x02, 0x41, 0x10, 0x20, 0x50, 0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35, 0x40, 0xCF, 0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14};
static const uint8_t CRED_R_PSK[] = {0xA2, 0x02, 0x69, 0x72, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x64, 0x65, 0x72, 0x08, 0xA1, 0x01, 0xA3, 0x01, 0x04, 0x02, 0x41, 0x10, 0x20, 0x50, 0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35, 0x40, 0xCF, 0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14};
//static const BytesElemLenPSK PSK = {};

static coap_context_t *ctx = NULL;
static coap_session_t *session = NULL;
static int has_coap_response = 0;
static uint8_t coap_response_payload[MAX_MESSAGE_SIZE_LEN];
static size_t coap_response_payload_len;

void print_hex(uint8_t *arr, size_t len)
{
    printf("%ld bytes: ", len);
    for (int i = 0; i < len; i++) {
        printf("%02X", arr[i]);
    }
    printf("\n");
}

static coap_response_t message_handler(coap_session_t *session COAP_UNUSED,
                                       const coap_pdu_t *sent,
                                       const coap_pdu_t *received,
                                       const coap_mid_t id COAP_UNUSED)
{
    has_coap_response = 1;
    // coap_show_pdu(COAP_LOG_WARN, received);
    const uint8_t *data;
    if (coap_get_data(received, &coap_response_payload_len, &data)) {
        memcpy(coap_response_payload, data, coap_response_payload_len);
        puts("received coap response");
        print_hex((uint8_t *)coap_response_payload, coap_response_payload_len);
    } else {
        puts("received coap response without payload");
    }
    return COAP_RESPONSE_OK;
}

int coap_send_edhoc_message(uint8_t *edhoc_msg, size_t edhoc_msg_len, uint8_t value_to_prepend)
{
    printf("sending coap message of size %zu+1\n", edhoc_msg_len);
    coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON,
                                    COAP_REQUEST_CODE_POST,
                                    coap_new_message_id(session),
                                    coap_session_max_pdu_size(session));
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 11, (const uint8_t *)".well-known");
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 5, (const uint8_t *)"edhoc");
    uint8_t payload[MAX_MESSAGE_SIZE_LEN];
    payload[0] = value_to_prepend;
    memcpy(payload + 1, edhoc_msg, edhoc_msg_len);
    print_hex(payload, edhoc_msg_len+1);
    coap_add_data(pdu, edhoc_msg_len + 1, payload);
    // coap_show_pdu(COAP_LOG_WARN, pdu);
    if (coap_send(session, pdu) == COAP_INVALID_MID)
    {
        coap_log_err("cannot send CoAP pdu\n");
        return -1;
    }
    while (has_coap_response == 0) {
        coap_io_process(ctx, COAP_IO_WAIT);
    }
    has_coap_response = 0;

    return 0;
}

int main(void)
{
    printf("Calling lakers from C!\n");

    // coap init
    coap_address_t dst;
    coap_startup();
    coap_set_log_level(COAP_LOG_WARN);
    coap_address_init(&dst);
    dst.addr.sin.sin_family = AF_INET;
    dst.addr.sin.sin_port = htons(5683);
    dst.size = sizeof(dst.addr.sin);
    if (inet_pton(AF_INET, "127.0.0.1", &dst.addr.sin.sin_addr) <= 0) {
        printf("Error converting the IP address\n");
        return -1;
    }
    if (!(ctx = coap_new_context(NULL)))
    {
        coap_log_emerg("cannot create libcoap context\n");
        goto finish;
    }
    if (!(session = coap_new_client_session(ctx, NULL, &dst,
                                            COAP_PROTO_UDP)))
    {
        coap_log_emerg("cannot create client session\n");
        goto finish;
    }
    coap_register_response_handler(ctx, message_handler);

    // lakers init
    puts("loading credentials.");
    CredentialC cred_i = {0}, cred_r = {0};
    if (credential_new_symmetric(&cred_i, CRED_I_PSK, sizeof(CRED_I_PSK)) != 0) {
        puts("Error loading initiator PSK credential.");
        return 1;
    }
    if (credential_new_symmetric(&cred_r, CRED_R_PSK, sizeof(CRED_R_PSK)) != 0) {
        puts("Error loading responder PSK credential.");
        return 1;
    }
    puts("creating edhoc initiator.");
    EdhocInitiator initiator = {0};
    initiator_new(&initiator, PSK);

    puts("Begin test: edhoc initiator.");
    EdhocMessageBuffer message_1 = {0};

    int res = initiator_prepare_message_1(&initiator, NULL, NULL, &message_1);

    if (res != 0) {
        printf("Error prep msg1: %d\n", res);
        return 1;
    }
    print_hex(message_1.content, message_1.len);

    puts("sending msg1");
    coap_send_edhoc_message(message_1.content, message_1.len, 0xf5);

    puts("processing msg2");
    EdhocMessageBuffer message_2 = {.len = coap_response_payload_len};
    memcpy(message_2.content, coap_response_payload, coap_response_payload_len);
    EadItemsC ead_2 = {0};
    uint8_t c_r;
    bool has_id_cred_r = false;
    IdCred id_cred_r = {0};
    res = initiator_parse_message_2(&initiator, &message_2, &c_r, &has_id_cred_r, &id_cred_r, &ead_2);

    if (res != 0) {
        printf("Error parse msg2: %d\n", res);
        return 1;
    }
    if (has_id_cred_r) {
        puts("Responder unexpectedly provided ID_CRED_R in PSK mode.");
        return 1;
    }
    res = initiator_verify_message_2(&initiator, NULL, &cred_i, &cred_r);
    if (res != 0) {
        printf("Error verify msg2: %d\n", res);
        return 1;
    }

    puts("preparing msg3");
    EdhocMessageBuffer message_3 = {0};
    uint8_t prk_out[SHA256_DIGEST_LEN] = {0};
    res = initiator_prepare_message_3(&initiator, ByReference, NULL, &message_3, &prk_out);
    if (res != 0) {
        printf("Error prep msg3: %d\n", res);
        return 1;
    }
    print_hex(message_3.content, message_3.len);

    puts("sending msg3");
    coap_send_edhoc_message(message_3.content, message_3.len, c_r);

    puts("processing msg4");
    EdhocMessageBuffer message_4 = {.len = coap_response_payload_len};
    memcpy(message_4.content, coap_response_payload, coap_response_payload_len);
    EadItemsC ead_4 = {0};
    res = initiator_process_message_4(&initiator, &message_4, &ead_4);
    if (res != 0) {
        printf("Error process msg4: %d\n", res);
        return 1;
    }

    puts("All went good.");

finish:
    coap_session_release(session);
    coap_free_context(ctx);
    coap_cleanup();

    return 0;
}

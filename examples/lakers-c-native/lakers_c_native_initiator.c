#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lakers_shared.h"
#include "lakers_ead_authz.h"
#include "lakers.h"
#include <coap3/coap.h>
#include <arpa/inet.h>

#ifdef LAKERS_EAD_AUTHZ
static const uint8_t ID_U[] = {0xa1, 0x04, 0x41, 0x2b};
static const uint8_t ID_U_LEN = sizeof(ID_U) / sizeof(ID_U[0]);
static const BytesP256ElemLen G_W = {0xFF, 0xA4, 0xF1, 0x02, 0x13, 0x40, 0x29, 0xB3, 0xB1, 0x56, 0x89, 0x0B, 0x88, 0xC9, 0xD9, 0x61, 0x95, 0x01, 0x19, 0x65, 0x74, 0x17, 0x4D, 0xCB, 0x68, 0xA0, 0x7D, 0xB0, 0x58, 0x8E, 0x4D, 0x41};
static const uint8_t LOC_W[] = {0x63, 0x6F, 0x61, 0x70, 0x3A, 0x2F, 0x2F, 0x65, 0x6E, 0x72, 0x6F, 0x6C, 0x6C, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72};
static const uint8_t LOC_W_LEN = sizeof(LOC_W) / sizeof(LOC_W[0]);
static const uint8_t SS = 2;
#endif

static const uint8_t CRED_I[] = {0xA2, 0x02, 0x77, 0x34, 0x32, 0x2D, 0x35, 0x30, 0x2D, 0x33, 0x31, 0x2D, 0x46, 0x46, 0x2D, 0x45, 0x46, 0x2D, 0x33, 0x37, 0x2D, 0x33, 0x32, 0x2D, 0x33, 0x39, 0x08, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x02, 0x41, 0x2B, 0x20, 0x01, 0x21, 0x58, 0x20, 0xAC, 0x75, 0xE9, 0xEC, 0xE3, 0xE5, 0x0B, 0xFC, 0x8E, 0xD6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5C, 0x47, 0xBF, 0x16, 0xDF, 0x96, 0x66, 0x0A, 0x41, 0x29, 0x8C, 0xB4, 0x30, 0x7F, 0x7E, 0xB6, 0x22, 0x58, 0x20, 0x6E, 0x5D, 0xE6, 0x11, 0x38, 0x8A, 0x4B, 0x8A, 0x82, 0x11, 0x33, 0x4A, 0xC7, 0xD3, 0x7E, 0xCB, 0x52, 0xA3, 0x87, 0xD2, 0x57, 0xE6, 0xDB, 0x3C, 0x2A, 0x93, 0xDF, 0x21, 0xFF, 0x3A, 0xFF, 0xC8};
static const uint8_t CRED_R[] = {0xA2, 0x02, 0x60, 0x08, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x02, 0x41, 0x0A, 0x20, 0x01, 0x21, 0x58, 0x20, 0xBB, 0xC3, 0x49, 0x60, 0x52, 0x6E, 0xA4, 0xD3, 0x2E, 0x94, 0x0C, 0xAD, 0x2A, 0x23, 0x41, 0x48, 0xDD, 0xC2, 0x17, 0x91, 0xA1, 0x2A, 0xFB, 0xCB, 0xAC, 0x93, 0x62, 0x20, 0x46, 0xDD, 0x44, 0xF0, 0x22, 0x58, 0x20, 0x45, 0x19, 0xE2, 0x57, 0x23, 0x6B, 0x2A, 0x0C, 0xE2, 0x02, 0x3F, 0x09, 0x31, 0xF1, 0xF3, 0x86, 0xCA, 0x7A, 0xFD, 0xA6, 0x4F, 0xCD, 0xE0, 0x10, 0x8C, 0x22, 0x4C, 0x51, 0xEA, 0xBF, 0x60, 0x72};
static const BytesP256ElemLen I = {0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5, 0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e, 0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9, 0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b};

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
    credential_new(&cred_i, CRED_I, 107);
    credential_new(&cred_r, CRED_R, 84);
    puts("creating edhoc initiator.");
    EdhocInitiator initiator = {0};
    initiator_new(&initiator, StatStat);
#ifdef LAKERS_EAD_AUTHZ
    puts("creating ead-authz device.");
    EadAuthzDevice device = {0};
    authz_device_new(&device, ID_U, ID_U_LEN, &G_W, LOC_W, LOC_W_LEN);
    puts("computing authz_secret.");
    BytesP256ElemLen authz_secret;
    initiator_compute_ephemeral_secret(&initiator, &G_W, &authz_secret);
    puts("computing ead_1.");
    EadItemsC ead_1 = {0};
    authz_device_prepare_ead_1(&device, &authz_secret, SS, &ead_1);
    for (int i = 0; i < MAX_EAD_ITEMS; i++) {
        print_hex(ead_1.items[i].value.content, ead_1.items[i].value.len);
    }
#endif

    puts("Begin test: edhoc initiator.");
    EdhocMessageBuffer message_1 = {0};
#ifdef LAKERS_EAD_AUTHZ
    int res = initiator_prepare_message_1(&initiator, NULL, &ead_1, &message_1);
    memcpy(device.wait_ead2.h_message_1, initiator.wait_m2.h_message_1, SHA256_DIGEST_LEN);
#else
    int res = initiator_prepare_message_1(&initiator, NULL, NULL, &message_1);
#endif
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
#ifdef LAKERS_EAD_AUTHZ
    // res = initiator_parse_message_2(&initiator, &message_2, &cred_r, &c_r, &id_cred_r, &ead_2);
    res = initiator_parse_message_2(&initiator, &message_2, &c_r, &has_id_cred_r, &id_cred_r, &ead_2);
#else
    // res = initiator_parse_message_2(&initiator, &message_2, &cred_r, &c_r, &id_cred_r, &ead_2);
    res = initiator_parse_message_2(&initiator, &message_2, &c_r, &has_id_cred_r, &id_cred_r, &ead_2);
#endif
    if (res != 0) {
        printf("Error parse msg2: %d\n", res);
        return 1;
    }
    if (!has_id_cred_r) {
        puts("Responder did not provide ID_CRED_R.");
        return 1;
    }
    // FIXME: failing on native when cred_expected is NULL (memory allocation of 48 bytes failed)
    CredentialC fetched_cred_r = {0};
    res = credential_check_or_fetch(&cred_r, &id_cred_r, &fetched_cred_r);
    if (res != 0) {
        printf("Error handling credential: %d\n", res);
        return 1;
    }
#ifdef LAKERS_EAD_AUTHZ
    puts("processing ead2");
    res = authz_device_process_ead_2(&device, &ead_2, &fetched_cred_r);
    if (res != 0) {
        printf("Error process ead2 (authz): %d\n", res);
        return 1;
    } else {
        puts("ead-authz voucher received and validated");
    }
#endif
    res = initiator_verify_message_2(&initiator, &I, &cred_i, &fetched_cred_r);
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

    puts("All went good.");

finish:
    coap_session_release(session);
    coap_free_context(ctx);
    coap_cleanup();

    return 0;
}

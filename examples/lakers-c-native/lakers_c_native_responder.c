#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <coap3/coap.h>
#include "lakers_shared.h"
#include "lakers.h"

static const uint8_t CRED_I[] = {0xA2, 0x02, 0x77, 0x34, 0x32, 0x2D, 0x35, 0x30, 0x2D, 0x33, 0x31, 0x2D, 0x46, 0x46, 0x2D, 0x45, 0x46, 0x2D, 0x33, 0x37, 0x2D, 0x33, 0x32, 0x2D, 0x33, 0x39, 0x08, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x02, 0x41, 0x2B, 0x20, 0x01, 0x21, 0x58, 0x20, 0xAC, 0x75, 0xE9, 0xEC, 0xE3, 0xE5, 0x0B, 0xFC, 0x8E, 0xD6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5C, 0x47, 0xBF, 0x16, 0xDF, 0x96, 0x66, 0x0A, 0x41, 0x29, 0x8C, 0xB4, 0x30, 0x7F, 0x7E, 0xB6, 0x22, 0x58, 0x20, 0x6E, 0x5D, 0xE6, 0x11, 0x38, 0x8A, 0x4B, 0x8A, 0x82, 0x11, 0x33, 0x4A, 0xC7, 0xD3, 0x7E, 0xCB, 0x52, 0xA3, 0x87, 0xD2, 0x57, 0xE6, 0xDB, 0x3C, 0x2A, 0x93, 0xDF, 0x21, 0xFF, 0x3A, 0xFF, 0xC8};
static const uint8_t CRED_R[] = {0xA2, 0x02, 0x60, 0x08, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x02, 0x41, 0x0A, 0x20, 0x01, 0x21, 0x58, 0x20, 0xBB, 0xC3, 0x49, 0x60, 0x52, 0x6E, 0xA4, 0xD3, 0x2E, 0x94, 0x0C, 0xAD, 0x2A, 0x23, 0x41, 0x48, 0xDD, 0xC2, 0x17, 0x91, 0xA1, 0x2A, 0xFB, 0xCB, 0xAC, 0x93, 0x62, 0x20, 0x46, 0xDD, 0x44, 0xF0, 0x22, 0x58, 0x20, 0x45, 0x19, 0xE2, 0x57, 0x23, 0x6B, 0x2A, 0x0C, 0xE2, 0x02, 0x3F, 0x09, 0x31, 0xF1, 0xF3, 0x86, 0xCA, 0x7A, 0xFD, 0xA6, 0x4F, 0xCD, 0xE0, 0x10, 0x8C, 0x22, 0x4C, 0x51, 0xEA, 0xBF, 0x60, 0x72};
static const BytesP256ElemLen R = {0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f, 0x75, 0x89, 0x31, 0xaa, 0x58, 0x9d, 0x34, 0x8d, 0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03, 0xed, 0xe2, 0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac};

static EdhocResponder responder = {0};
static CredentialC cred_i = {0};
static CredentialC cred_r = {0};
static uint8_t c_r = 5;
static bool has_active_state = false;

static void fail_response(coap_pdu_t *response, const char *message, int rc)
{
    printf("%s failed: %d\n", message, rc);
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
}

static void handle_edhoc(coap_resource_t *resource,
                         coap_session_t *session,
                         const coap_pdu_t *request,
                         const coap_string_t *query,
                         coap_pdu_t *response)
{
    (void)resource;
    (void)session;
    (void)query;

    size_t payload_len = 0;
    const uint8_t *payload = NULL;
    if (!coap_get_data(request, &payload_len, &payload) || payload_len == 0) {
        fail_response(response, "coap_get_data", -1);
        return;
    }

    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);

    if (payload[0] == 0xf5) {
        EdhocMessageBuffer message_1 = {.len = payload_len - 1};
        memcpy(message_1.content, payload + 1, payload_len - 1);

        responder_new(&responder);

        uint8_t c_i = 0;
        EadItemsC ead_1 = {0};
        int rc = responder_process_message_1(&responder, &message_1, &c_i, &ead_1);
        if (rc != 0) {
            fail_response(response, "responder_process_message_1", rc);
            return;
        }

        EdhocMessageBuffer message_2 = {0};
        rc = responder_prepare_message_2(&responder, &R, &cred_r, ByReference, &c_r, NULL, &message_2);
        if (rc != 0) {
            fail_response(response, "responder_prepare_message_2", rc);
            return;
        }

        has_active_state = true;
        coap_add_data(response, message_2.len, message_2.content);
        puts("Sent EDHOC message 2 from C responder.");
        return;
    }

    if (!has_active_state || payload[0] != c_r) {
        fail_response(response, "unknown connection identifier", -1);
        return;
    }

    EdhocMessageBuffer message_3 = {.len = payload_len - 1};
    memcpy(message_3.content, payload + 1, payload_len - 1);

    IdCred id_cred_i = {0};
    EadItemsC ead_3 = {0};
    int rc = responder_parse_message_3(&responder, &message_3, &id_cred_i, &ead_3);
    if (rc != 0) {
        fail_response(response, "responder_parse_message_3", rc);
        return;
    }

    uint8_t prk_out[SHA256_DIGEST_LEN] = {0};
    rc = responder_verify_message_3(&responder, &cred_i, &prk_out);
    if (rc != 0) {
        fail_response(response, "responder_verify_message_3", rc);
        return;
    }

    EdhocMessageBuffer message_4 = {0};
    rc = responder_prepare_message_4(&responder, NULL, &message_4);
    if (rc != 0) {
        fail_response(response, "responder_prepare_message_4", rc);
        return;
    }

    has_active_state = false;
    coap_add_data(response, message_4.len, message_4.content);
    puts("EDHOC exchange completed by C responder.");
}

int main(void)
{
    if (credential_new(&cred_i, CRED_I, sizeof(CRED_I)) != 0 ||
        credential_new(&cred_r, CRED_R, sizeof(CRED_R)) != 0) {
        puts("failed to load credentials");
        return 1;
    }

    coap_startup();
    coap_set_log_level(COAP_LOG_WARN);

    coap_context_t *ctx = coap_new_context(NULL);
    if (ctx == NULL) {
        puts("cannot create libcoap context");
        return 1;
    }

    coap_address_t listen_addr;
    coap_address_init(&listen_addr);
    listen_addr.addr.sin.sin_family = AF_INET;
    listen_addr.addr.sin.sin_port = htons(5683);
    listen_addr.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    coap_endpoint_t *endpoint = coap_new_endpoint(ctx, &listen_addr, COAP_PROTO_UDP);
    if (endpoint == NULL) {
        puts("cannot create CoAP endpoint on 127.0.0.1:5683");
        coap_free_context(ctx);
        coap_cleanup();
        return 1;
    }

    coap_resource_t *resource = coap_resource_init(coap_make_str_const(".well-known/edhoc"), 0);
    if (resource == NULL) {
        puts("cannot create EDHOC resource");
        coap_free_context(ctx);
        coap_cleanup();
        return 1;
    }
    coap_register_request_handler(resource, COAP_REQUEST_CODE_POST, handle_edhoc);
    coap_add_resource(ctx, resource);

    puts("C stat-static EDHOC responder listening on coap://127.0.0.1:5683/.well-known/edhoc");
    while (1) {
        coap_io_process(ctx, COAP_IO_WAIT);
    }
}

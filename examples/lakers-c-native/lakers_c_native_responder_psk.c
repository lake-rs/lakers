#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <coap3/coap.h>
#include "lakers_shared.h"
#include "lakers.h"

static const uint8_t CRED_I_PSK[] = {0xA2, 0x02, 0x69, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6F, 0x72, 0x08, 0xA1, 0x01, 0xA3, 0x01, 0x04, 0x02, 0x41, 0x10, 0x20, 0x50, 0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35, 0x40, 0xCF, 0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14};
static const uint8_t CRED_R_PSK[] = {0xA2, 0x02, 0x69, 0x72, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x64, 0x65, 0x72, 0x08, 0xA1, 0x01, 0xA3, 0x01, 0x04, 0x02, 0x41, 0x10, 0x20, 0x50, 0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35, 0x40, 0xCF, 0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14};

static EdhocResponder responder = {0};
static CredentialC cred_i = {0};
static CredentialC cred_r = {0};
static uint8_t c_r = 5;
static bool has_active_state = false;

static int8_t resolve_cred_i_from_context(const IdCred *id_cred_i,
                                          CredentialC *cred_out,
                                          void *context)
{
    if (id_cred_i == NULL || cred_out == NULL || context == NULL) {
        return -1;
    }

    return credential_check_or_fetch((CredentialC *)context, (IdCred *)id_cred_i, cred_out);
}

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
        rc = responder_prepare_message_2(&responder, NULL, &cred_r, ByReference, &c_r, NULL, &message_2);
        if (rc != 0) {
            fail_response(response, "responder_prepare_message_2", rc);
            return;
        }

        has_active_state = true;
        coap_add_data(response, message_2.len, message_2.content);
        puts("Sent EDHOC message 2 from C PSK responder.");
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
    int rc = responder_parse_message_3_with_cred_resolver(&responder,
                                                          &message_3,
                                                          &id_cred_i,
                                                          &ead_3,
                                                          resolve_cred_i_from_context,
                                                          &cred_i);
    if (rc != 0) {
        fail_response(response, "responder_parse_message_3_with_cred_resolver", rc);
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
    puts("EDHOC exchange completed by C PSK responder.");
}

int main(void)
{
    if (credential_new_symmetric(&cred_i, CRED_I_PSK, sizeof(CRED_I_PSK)) != 0 ||
        credential_new_symmetric(&cred_r, CRED_R_PSK, sizeof(CRED_R_PSK)) != 0) {
        puts("failed to load PSK credentials");
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

    puts("C PSK EDHOC responder listening on coap://127.0.0.1:5683/.well-known/edhoc");
    while (1) {
        coap_io_process(ctx, COAP_IO_WAIT);
    }
}

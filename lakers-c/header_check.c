#include "lakers_shared.h"
#include "lakers.h"

int main(void) {
    EdhocResponder responder = {0};
    EdhocMessageBuffer msg = {0};
    EadItemsC ead = {0};
    uint8_t c_i = 0;

    responder_new(&responder);

    (void)msg;
    (void)ead;
    (void)c_i;
    return 0;
}

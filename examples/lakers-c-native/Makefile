CC=gcc
CFLAGS+=-Wall -I../../target/include -fsanitize=address,undefined,leak

INITIATOR_TARGET=lakers_c_native_initiator
INITIATOR_PSK_TARGET=lakers_c_native_initiator_psk
RESPONDER_TARGET=lakers_c_native_responder
RESPONDER_PSK_TARGET=lakers_c_native_responder_psk

INITIATOR_SRC=lakers_c_native_initiator.c
INITIATOR_PSK_SRC=lakers_c_native_initiator_psk.c
RESPONDER_SRC=lakers_c_native_responder.c
RESPONDER_PSK_SRC=lakers_c_native_responder_psk.c

INITIATOR_OBJ=$(INITIATOR_SRC:.c=.o)
INITIATOR_PSK_OBJ=$(INITIATOR_PSK_SRC:.c=.o)
RESPONDER_OBJ=$(RESPONDER_SRC:.c=.o)
RESPONDER_PSK_OBJ=$(RESPONDER_PSK_SRC:.c=.o)

HOST_TRIPLE := $(shell rustc -vV | sed -n 's|host: ||p')

LIB_DIR=../../target/$(HOST_TRIPLE)/release/
LIB_NAME=lakers_c
COAP_LIB ?= coap-3-notls

ifeq ($(LAKERS_EAD), authz)
	CFLAGS += -DLAKERS_EAD_AUTHZ
endif

LDFLAGS+=-fsanitize=address,undefined,leak

all: $(INITIATOR_TARGET) $(INITIATOR_PSK_TARGET) $(RESPONDER_TARGET) $(RESPONDER_PSK_TARGET)

# rule for building the target executable
$(INITIATOR_TARGET): $(INITIATOR_OBJ)
	$(CC) $(CFLAGS) -ggdb -O0 -o $@ $^ $(LDFLAGS) -L$(LIB_DIR) -l$(LIB_NAME) -l$(COAP_LIB)

$(INITIATOR_PSK_TARGET): $(INITIATOR_PSK_OBJ)
	$(CC) $(CFLAGS) -ggdb -O0 -o $@ $^ $(LDFLAGS) -L$(LIB_DIR) -l$(LIB_NAME) -l$(COAP_LIB)

$(RESPONDER_TARGET): $(RESPONDER_OBJ)
	$(CC) $(CFLAGS) -ggdb -O0 -o $@ $^ $(LDFLAGS) -L$(LIB_DIR) -l$(LIB_NAME) -l$(COAP_LIB)

$(RESPONDER_PSK_TARGET): $(RESPONDER_PSK_OBJ)
	$(CC) $(CFLAGS) -ggdb -O0 -o $@ $^ $(LDFLAGS) -L$(LIB_DIR) -l$(LIB_NAME) -l$(COAP_LIB)

# rule for building object files
%.o: %.c
	$(CC) $(CFLAGS) -ggdb -c $<

clean:
	rm -f $(INITIATOR_OBJ) $(INITIATOR_PSK_OBJ) $(RESPONDER_OBJ) $(RESPONDER_PSK_OBJ) $(INITIATOR_TARGET) $(INITIATOR_PSK_TARGET) $(RESPONDER_TARGET) $(RESPONDER_PSK_TARGET)
	rm -f main.o main_psk.o responder_selftest.o responder_selftest_psk.o
	rm -f lakers_c_native lakers_c_native_psk lakers_c_responder_selftest lakers_c_responder_selftest_psk

.PHONY: all clean

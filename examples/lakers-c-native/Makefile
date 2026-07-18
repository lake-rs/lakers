CC=gcc
CFLAGS+=-Wall -I../../target/include -fsanitize=address,undefined,leak

TARGET=lakers_c_native
PSK_TARGET=lakers_c_native_psk

SRC=main.c
PSK_SRC=main_psk.c

OBJ=$(SRC:.c=.o)
PSK_OBJ=$(PSK_SRC:.c=.o)

HOST_TRIPLE := $(shell rustc -vV | sed -n 's|host: ||p')

LIB_DIR=../../target/$(HOST_TRIPLE)/release/
LIB_NAME=lakers_c
COAP_LIB ?= coap-3

ifeq ($(LAKERS_EAD), authz)
	CFLAGS += -DLAKERS_EAD_AUTHZ
endif

LDFLAGS+=-fsanitize=address,undefined,leak

all: $(TARGET) $(PSK_TARGET)

# rule for building the target executable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -ggdb -O0 -o $@ $^ $(LDFLAGS) -L$(LIB_DIR) -l$(LIB_NAME) -l$(COAP_LIB)

$(PSK_TARGET): $(PSK_OBJ)
	$(CC) $(CFLAGS) -ggdb -O0 -o $@ $^ $(LDFLAGS) -L$(LIB_DIR) -l$(LIB_NAME) -l$(COAP_LIB)

# rule for building object files
%.o: %.c
	$(CC) $(CFLAGS) -ggdb -c $<

clean:
	rm -f $(OBJ) $(PSK_OBJ) $(TARGET) $(PSK_TARGET)

.PHONY: all clean

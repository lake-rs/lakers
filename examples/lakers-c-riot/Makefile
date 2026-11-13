# name of your application
APPLICATION = lakers-c-riot

# If no BOARD is found in the environment, use this default:
BOARD ?= nrf52840dk

# adjust these according to your needs
INCLUDES += -I$(CURDIR)/../../target/include
ARCHIVES += $(CURDIR)/../../target/thumbv7em-none-eabihf/release/liblakers_c.a

ifeq ($(LAKE_CRYPTO), psa)
	CFLAGS += -DCRYPTO_PSA
else
	CFLAGS += -DCRYPTO_CRYPTOCELL310
endif

# This is actually only needed in the CRYPTO_CRYPTOCELL310 configuration
CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=16384 -DISR_STACKSIZE=16384

USEMODULE += od
USEMODULE += ztimer
USEMODULE += ztimer_msec
USEMODULE += ps

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../../../RIOT

DEVELHELP ?= 1

# flags for development only
CFLAGS += -Wno-error=unused-variable -Wno-error=unused-const-variable -Wno-error=unused-function -Wno-error=unused-parameter -Wno-error=pedantic

include $(RIOTBASE)/Makefile.include

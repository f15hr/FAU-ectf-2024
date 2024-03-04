.PHONY: all, release, clean, wolfssl, wolfclean

ifeq ($(DEVICE), AP)
WOLFSSL_DIR = $(abspath ../common/wolfssl/IDE/MAX78000_Client/)
SSLHEADER_FILE = $(abspath ../application_processor/inc/secrets_ap.h) 

else ifeq ($(DEVICE), COMPONENT)
WOLFSSL_DIR := $(abspath ../common/wolfssl/IDE/MAX78000_Server/)
SSLHEADER_FILE = $(abspath ../component/inc/secrets_component.h)

else 
$(error ERROR: common.mk: Variable DEVICE with value $(DEVICE) is not valid!)
endif

print-%: 
	$(MAKE) -f ./Makefile.maxim print-$*

all: $(WOLFSSL_DIR)/Build/libwolfssl.a $(SSLHEADER_FILE)
	$(MAKE) -f ./Makefile.maxim DEVICE=$(DEVICE)

$(WOLFSSL_DIR)/Build/libwolfssl.a:
	-$(MAKE) -C $(WOLFSSL_DIR) WolfSSLStaticLib

$(SSLHEADER_FILE):
	@bash ../common/openssl/ssl_gen_device.sh $(CURDIR)
	cd ../common/openssl && python make_ssl_headers.py "$(DEVICE)" $(CURDIR)

release:
	$(MAKE) -f ./Makefile.maxim release DEVICE=$(DEVICE)

clean:
	$(MAKE) -f ./Makefile.maxim clean DEVICE=$(DEVICE)

wolfssl_all:
	-$(MAKE) -C $(abspath ../common/wolfssl/IDE/MAX78000_Client/) WolfSSLStaticLib
	-$(MAKE) -C $(abspath ../common/wolfssl/IDE/MAX78000_Server/) WolfSSLStaticLib

wolfclean_all:
	-$(MAKE) -C $(abspath ../common/wolfssl/IDE/MAX78000_Client/) clean
	-$(MAKE) -C $(abspath ../common/wolfssl/IDE/MAX78000_Server/) clean

wolfssl_client:
	-$(MAKE) -C $(abspath ../common/wolfssl/IDE/MAX78000_Client/) clean
	-$(MAKE) -C $(abspath ../common/wolfssl/IDE/MAX78000_Client/) WolfSSLStaticLib

wolfssl_server:
	-$(MAKE) -C $(abspath ../common/wolfssl/IDE/MAX78000_Server/) clean
	-$(MAKE) -C $(abspath ../common/wolfssl/IDE/MAX78000_Server/) WolfSSLStaticLib
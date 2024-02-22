.PHONY: all, release, clean, wolfssl, wolfclean, sslgen

print-%: 
	$(MAKE) -f ./Makefile.maxim print-$*

ifeq ($(DEVICE), AP)
WOLFSSL_DIR := $(abspath ../common/wolfssl/IDE/MAX78000_Client/)
all:
	cd ../common/openssl && python make_ssl_headers.py "AP" $(CURDIR)
	-$(MAKE) -C $(WOLFSSL_DIR) WolfSSLStaticLib
	$(MAKE) -f ./Makefile.maxim DEVICE=$(DEVICE)

sslgen:
	cd ../common/openssl && python make_ssl_headers.py "AP" $(CURDIR)

else ifeq ($(DEVICE), COMPONENT)
WOLFSSL_DIR := $(abspath ../common/wolfssl/IDE/MAX78000_Server/)
all:
	@bash ../common/openssl/ssl_gen_server.sh $(CURDIR)
	cd ../common/openssl && python make_ssl_headers.py "COMPONENT" $(CURDIR)
	-$(MAKE) -C $(WOLFSSL_DIR) WolfSSLStaticLib
	$(MAKE) -f ./Makefile.maxim DEVICE=$(DEVICE)

sslgen:
	@bash ../common/openssl/ssl_gen_server.sh $(CURDIR)
	cd ../common/openssl && python make_ssl_headers.py "COMPONENT" $(CURDIR)
else 
$(error ERROR: common.mk: Variable DEVICE with value $(DEVICE) is not valid!)
endif

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
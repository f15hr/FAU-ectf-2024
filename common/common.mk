WOLFSSL_DIR := $(abspath ../common/wolfssl/IDE/GCC-ARM/)

.PHONY: all, release, clean, wolfssl, wolfclean, sslgen

print-%: 
	$(MAKE) -f ./Makefile.maxim print-$*

ifeq ($(DEVICE), "COMPONENT")
all:
	@bash ../common/openssl/ssl_gen_server.sh $(CURDIR)
	cd ../common/openssl && python make_ssl_headers.py "COMPONENT" $(CURDIR)
	-$(MAKE) -C $(WOLFSSL_DIR) WolfSSLStaticLib
	$(MAKE) -f ./Makefile.maxim

sslgen:
	@bash ../common/openssl/ssl_gen_server.sh $(CURDIR)
	cd ../common/openssl && python make_ssl_headers.py "COMPONENT" $(CURDIR)
	
else ifeq ($(DEVICE), "AP")
all:
	cd ../common/openssl && python make_ssl_headers.py "AP" $(CURDIR)
	-$(MAKE) -C $(WOLFSSL_DIR) WolfSSLStaticLib
	$(MAKE) -f ./Makefile.maxim

sslgen:
	cd ../common/openssl && python make_ssl_headers.py "AP" $(CURDIR)

else 
$(error ERROR: Varaible DEVICE with value $(DEVICE) is not valid!)
endif

release:
	$(MAKE) -f ./Makefile.maxim release

clean:
	$(MAKE) -f ./Makefile.maxim clean

wolfssl:
	-$(MAKE) -C $(WOLFSSL_DIR) WolfSSLStaticLib

wolfclean:
	-$(MAKE) -C $(WOLFSSL_DIR) clean
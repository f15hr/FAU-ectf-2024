all: 
	-$(MAKE) -C $(abspath ./wolfssl/IDE/GCC-ARM/) WolfSSLStaticLib
	$(MAKE) -f ./Makefile.maxim

release:
	$(MAKE) -f ./Makefile.maxim release

clean:
	$(MAKE) -f ./Makefile.maxim clean


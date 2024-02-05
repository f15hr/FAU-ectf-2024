
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

PWD := $(shell echo $$PWD)

all:
	echo "#define SECRET 1234" > global_secrets.h
	chmod +x gen_certs.sh
	bash gen_certs.sh
	python make_secrets.py $(PWD)

clean:
	rm -f global_secrets.h

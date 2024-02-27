
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	# echo "#define SECRET 1234" > global_secrets.h
	# dd bs=16 count=1025 if=/dev/urandom | od -An -tx1 | tr -d ' \n' | fold -w32 | awk '{print "#define KEY" NR-1 " 0x" $$1}' > global_secrets.h
	# dd bs=16 count=1025 if=/dev/urandom | od -An -tx1 -v | tr -d ' \n' | fold -w32 | awk 'BEGIN {print "#define KEY(index) (\\\n"} {printf "    (index) == %d ? 0x%s : \\\n", NR-1, $$1} END {print "    0)\n"}' > global_secrets.h
	# dd bs=16 count=1025 if=/dev/urandom | od -An -tx1 -v | tr -d ' \n' | fold -w32 | awk 'BEGIN {print "#define KEY(index) (\\\n"} {printf "    (index) == %d ? {", NR-1; for(i = 1; i <= 32; i+=2) printf "0x%s%s", substr($$1, i, 1), (i < 30 ? ", " : ""); printf "} : \\\n"} END {print "    {0})\n"}' > global_secrets.h
	# dd bs=16 count=1025 if=/dev/urandom | od -An -tx1 -v | tr -d ' \n' | fold -w32 | awk 'BEGIN {print "#define KEY(index) (\\\n"} {printf "    (index) == %d ? {", NR-1; for(i = 1; i <= 32; i+=2) printf "0x%s%s", substr($$1, i, 2), (i < 31 ? ", " : ""); printf "} : \\\n"} END {print "    {0})\n"}' > global_secrets.h
	# dd bs=16 count=1025 if=/dev/urandom | od -An -tx1 -v | tr -d ' \n' | fold -w32 | awk 'BEGIN {print "#define KEY(index) (\\\n"} {printf "    (index) == %d ? (uint8_t[]){", NR-1; for(i = 1; i <= 32; i+=2) printf "0x%s%s", substr($$1, i, 2), (i < 31 ? ", " : ""); printf "} : \\\n"} END {print "    NULL)\n"}' > global_secrets.h
	dd bs=16 count=1025 if=/dev/urandom | od -An -tx1 -v | tr -d ' \n' | fold -w32 | awk 'BEGIN {printf "#define KEY(index) (\\"} {if (NR == 1) printf "\n    (index) == %d ? (char[]){", NR-1; else printf "    (index) == %d ? (char[]){", NR-1; for(i = 1; i <= 32; i+=2) printf "0x%s%s", substr($$1, i, 2), (i < 31 ? ", " : ""); printf "} : \\\n"} END {print "    NULL)\n"}' > global_secrets.h




clean:
	rm -f global_secrets.h

# Makefile for common settings between the AP and the Components
DEBUG = 1

############## BEGIN WOLFSSL CONFIGURATION ############## 
# wolfssl Flags
# https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#building-with-gcc-arm
# https://www.wolfssl.com/how-do-i-manage-the-build-configuration-of-wolfssl/
PROJ_CFLAGS += -DWOLFSSL_USER_SETTINGS -DHAVE_PK_CALLBACKS \
               -DWOLFSSL_USER_IO -DNO_WRITEV -DTIME_T_NOT_64BIT \
			   -DWOLFSSL_LOAD_FLAG_DATE_ERR_OKAY
USER_SETTINGS_DIR ?= $(abspath ../common/wolfssl/IDE/GCC-ARM/Header)
IPATH += $(USER_SETTINGS_DIR)
IPATH += $(abspath ../common/wolfssl)
IPATH += $(abspath ../common/)

PROJ_LDFLAGS += -L$(abspath ../common/wolfssl/IDE/GCC-ARM/Build/)
PROJ_LIBS += :libwolfssl.a
############## END WOLFSSL CONFIGURATION ############## 

# Prints a variable's value to tty
# example usage: 'make print-PROJ_LDFLAGS'
print-%  : ; @echo $* = $($*)

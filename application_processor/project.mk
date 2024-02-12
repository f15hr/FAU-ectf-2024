# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Og
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# Add your config here!

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
VPATH+=src/

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
# Uncomment the commented lines below and comment the disable
# lines to enable the eCTF Crypto Example.
# WolfSSL must be included in this directory as wolfssl/
# WolfSSL can be downloaded from: https://www.wolfssl.com/download/

# Disable Crypto Example
CRYPTO_EXAMPLE=0

# Enable Crypto Example
# CRYPTO_EXAMPLE=1

DEBUG = 1

# wolfssl Flags
# https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#building-with-gcc-arm
# https://www.wolfssl.com/how-do-i-manage-the-build-configuration-of-wolfssl/
PROJ_CFLAGS += -DWOLFSSL_USER_SETTINGS -DHAVE_PK_CALLBACKS -DWOLFSSL_USER_IO -DNO_WRITEV -DTIME_T_NOT_64BIT
USER_SETTINGS_DIR ?= $(abspath wolfssl/IDE/GCC-ARM/Header)
IPATH += $(USER_SETTINGS_DIR)
IPATH += $(abspath ./wolfssl)

PROJ_LDFLAGS += -L$(abspath ./wolfssl/IDE/GCC-ARM/Build/)
PROJ_LIBS += :libwolfssl.a

print-%  : ; @echo $* = $($*)


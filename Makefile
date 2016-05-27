#TARGET = $(notdir $(CURDIR))
BUILD_DIR=../../platform/linux-hisilicon/build
BUILD_TYPE=build_64
FILE_NAME=OCC_fwd
THIS_MAKEFILE=$(abspath $(firstword $(subst $(MAKEFILES),,$(MAKEFILE_LIST))))
SRC_DIR = $(dir $(THIS_MAKEFILE))
DIR_NAME = $(shell basename $(SRC_DIR))
ROOT            = $(SRC_DIR)../..

ifeq ("$(BUILD_TYPE)", "build_32")
	GNU_PREFIX=arm-linux-gnueabi-
	LIB_ODP=odp32
	APP_OUT=$(FILE_NAME)_app
	CFLAGS= -O3 -D_GNU_SOURCE -mlittle-endian -lpthread -march=armv7-a  -D__arm32__
else
	GNU_PREFIX = aarch64-linux-gnu-
	LIB_ODP=odp
	APP_OUT=$(FILE_NAME)_app
	CFLAGS= -O3 -D_GNU_SOURCE -mlittle-endian -lpthread -march=armv8-a -mtune=cortex-a57 -mcpu=cortex-a57
endif

CC                := $(GNU_PREFIX)gcc
LD                := $(GNU_PREFIX)ld
OBJDUMP           := $(GNU_PREFIX)objdump
ECHO              := @echo

SRCS          := $(wildcard $(SRC_DIR)*.c)

OBJ_FILE      := $(SRCS:.c=.o)
I_OBJ_FILE    := $(SRCS:.c=.i)

AC_OBJ := ac/sm_builder.o ac/acsmx.o ac/acsmx2.o ac/bnfa_search.o ac/util.o

LIBS := -L$(BUILD_DIR)/objs/lib -l$(LIB_ODP) -lpthread -ldl -lrt -lm



INCLUDE_FILES      := -I$(SRC_DIR) \
                     -I$(ROOT)/platform/linux-generic/include \
                     -I$(ROOT)/platform/linux-generic/arch/linux \
                     -I$(ROOT)/platform/linux-generic/include/odp/plat \
                     -I$(ROOT)/helper/include/odp/helper \
                     -I$(ROOT)/helper/include \
                     -I$(ROOT)/include \
                     -I$(ROOT)/test \
                     -I$(ROOT)/platform/linux-hisilicon/example \
                     -I$(BUILD_DIR) \
		     		 -I$(ROOT)/example \
                     -I$(ROOT)/platform/linux-hisilicon/include \
					 -I$(ROOT)/helper

$(APP_OUT) : $(OBJ_FILE) $(AC_OBJ)
	$(ECHO) "LD " $@;\
	$(CC) $(LIBS) $(CFLAGS) -o $@ $^  $(BUILD_DIR)/objs/libcrypto.a
	rm -f $(SRC_DIR)*.o $(SRC_DIR)*.d $(SRC_DIR)*.so ac/*.o

clean:
	rm -f $(SRC_DIR)*.o $(SRC_DIR)*.d $(SRC_DIR)*.so $(SRC_DIR)$(APP_OUT) ac/*.o



$(OBJ_FILE) : %.o : %.c
	$(ECHO) "CC " $(notdir $@);
	$(CC)  $(CFLAGS) $(INCLUDE_FILES) -c -o $@ $<

include ac/Makefile

$(I_OBJ_FILE) :%.i :%.c
	$(ECHO) "CC " $@;
	$(CC) $(CFLAGS) $(INCLUDE_FILES) $< -E -P -o $@

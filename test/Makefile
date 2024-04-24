#this is a makefile
CC 				= gcc
APP_NAME 		= "test_app.bin"

# Source Files
SRCS += "test_app.c"
SRCS += "../ice_api.c"
SRCS += "../stun_serializer.c"
SRCS += "../stun_deserializer.c"
SRCS += "../stun_endianness.c"

# Include Directories
INCLUDE_DIRS += "../ice_api.h"
INCLUDE_DIRS += "../ice_data_types.h"
INCLUDE_DIRS += "../stun_data_types.h"
INCLUDE_DIRS += "../stun_serializer.h"
INCLUDE_DIRS += "../stun_deserializer.h"
INCLUDE_DIRS += "../stun_endianness.h"


OBJS=$(SRCS:.c=.o)

CFLAGS+=-ggdb

.DEFAULT_GOAL:=build

build:
	$(CC) -o $(APP_NAME) $(SRCS) $(INCLUDE_DIRS) $(CFLAGS)

clean:
	rm -rf $(APP_NAME)

.PHONY: build clean

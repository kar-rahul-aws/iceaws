#this is a makefile
CC 				= gcc
APP_NAME 		= "test_app.bin"

# Source Files
SRCS += "test_app.c"
SRCS += "../source/ice_api.c"
SRCS += "../source/dependency/amazon-kinesis-video-streams-stun/source/stun_serializer.c"
SRCS += "../source/dependency/amazon-kinesis-video-streams-stun/source/stun_deserializer.c"
SRCS += "../source/dependency/amazon-kinesis-video-streams-stun/source/stun_endianness.c"

# Include Directories
INCLUDE_DIRS += "-I../source/include"
INCLUDE_DIRS += "-I../source/dependency/amazon-kinesis-video-streams-stun/source/include"

OBJS=$(SRCS:.c=.o)

CFLAGS+=-ggdb

.DEFAULT_GOAL:=build

build:
	$(CC) -o $(APP_NAME) $(SRCS) $(INCLUDE_DIRS) $(CFLAGS)

clean:
	rm -rf $(APP_NAME)

.PHONY: build clean

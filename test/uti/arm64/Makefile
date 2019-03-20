# Makefile COPYRIGHT FUJITSU LIMITED 2019
CC = gcc
LDFLAGS = -Wall -lpthread

SRCS = $(shell ls CT*.c)
TARGET = $(SRCS:.c=)

all: $(TARGET)

test: all
	./run.sh

clean:
	rm -f $(TARGET)

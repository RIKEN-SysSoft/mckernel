# Makefile COPYRIGHT FUJITSU LIMITED 2018
CC = gcc
TARGET = get_rusage
LDFLAGS = -Wall

include $(HOME)/.mck_test_config

INCLUDE_DIR = $(BIN)/../include
LIBDIR = $(BIN)/../lib

all: $(TARGET)

get_rusage: get_rusage.c
	$(CC) -o $@ $^ $(LDFLAGS) -I$(INCLUDE_DIR) -Wl,-rpath=$(LIBDIR) -L$(LIBDIR) -lihk

test: all
	./run.sh

clean:
	rm -f $(TARGET)

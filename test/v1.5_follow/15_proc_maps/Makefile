# Makefile COPYRIGHT FUJITSU LIMITED 2018
MCK_DIR = /opt/ppos

CC = gcc
TARGET = proc_maps
LDFLAGS = 
MCEXEC = $(MCK_DIR)/bin/mcexec

all: $(TARGET)

proc_maps: proc_maps.c
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	$(MCEXEC) ./proc_maps

clean:
	rm -f $(TARGET)

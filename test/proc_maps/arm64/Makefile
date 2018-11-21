# Makefile COPYRIGHT FUJITSU LIMITED 2018
CC = gcc
TARGET = proc_maps
LDFLAGS = 

all: $(TARGET)

proc_maps: proc_maps.c
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	./run.sh

clean:
	rm -f $(TARGET)

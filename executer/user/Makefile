#CC=/usr/linux-k1om-4.7/bin/x86_64-k1om-linux-gcc
CC=gcc
CFLAGS=-Wall -O
TARGET=mcexec

all: $(TARGET)

mcexec: mcexec.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -pthread -o $@ $^ $(EXTRA_OBJS)

clean:
	$(RM) $(TARGET) *.o

.PHONY: all clean



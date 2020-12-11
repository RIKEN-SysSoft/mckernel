CC=gcc
CFLAGS=-g
LDFLAGS=

TARGET=C1555T01 C1555T02

all: $(TARGET)

C1555T01: C1555.c
	$(CC) -o $@ $^

C1555T02: C1555.c
	$(CC) -DMIGRATE_ON_OFFLOAD -o $@ $^

test: all
	sh ./C1555.sh
clean:
	rm -f $(TARGET) *.o *.txt

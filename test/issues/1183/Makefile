CC = gcc
TARGET=hugemap

CPPFLAGS =
LDFLAGS =

all: $(TARGET)

hugemap: hugemap.c
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	@sh ./C1183.sh

clean:
	rm -f $(TARGET) *.o


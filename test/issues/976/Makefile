CC = gcc
TARGET=CT_001 CT_002 CT_003

CPPFLAGS =
LDFLAGS =

all: $(TARGET)

CT_001: CT_001.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_002: CT_002.c
	$(CC) -o $@ $^ $(LDFLAGS) -lm

CT_003: CT_003.c
	$(CC) -o $@ $^ $(LDFLAGS) -lm

test: all
	@sh ./C976.sh

clean:
	rm -f $(TARGET) *.o


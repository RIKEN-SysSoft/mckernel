CC = gcc
TARGET=CT_001 CT_002

CPPFLAGS =
LDFLAGS =

all: $(TARGET)

CT_001: CT_001.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_002: CT_002.c
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	@sh ./C1018.sh

clean:
	rm -f $(TARGET) *.o


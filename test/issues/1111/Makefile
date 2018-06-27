CC = gcc
TARGET=CT_001 CT_002 CT_003 CT_004 CT_005

CPPFLAGS =
LDFLAGS =

all: $(TARGET)

CT_001: CT_001.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_002: CT_002.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_003: CT_003.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_004: CT_004.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_005: CT_005.c
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	@sh ./C1111.sh

clean:
	rm -f $(TARGET) *.o


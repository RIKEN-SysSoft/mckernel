CC = gcc
TARGET=CT_001

CPPFLAGS =
LDFLAGS =

all: $(TARGET)

CT_001: CT_001.c
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	@sh ./C1036.sh

clean:
	rm -f $(TARGET) *.o


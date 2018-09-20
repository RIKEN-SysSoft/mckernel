CC = gcc
TARGET=devmap_and_segv

CPPFLAGS =
LDFLAGS =

all: $(TARGET)

devmap_and_segv: devmap_and_segv.c
	$(CC) -g -o $@ $^ $(LDFLAGS)

test: all
	@sh ./C1005.sh

clean:
	rm -f $(TARGET) *.o ./core ./core.* ./maps.txt ./gdb_out.txt


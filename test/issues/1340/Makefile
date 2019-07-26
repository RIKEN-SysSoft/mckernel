CFLAGS=-g
LDFLAGS=

TARGET=segv raise_sig

all: $(TARGET)

test: all
	./C1340.sh
clean:
	rm -f $(TARGET) *.o mccore* core.* *.txt

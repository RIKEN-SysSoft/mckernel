CFLAGS=-g
LDFLAGS=-lpthread

TARGET=segv_in_sub segv_in_main segv_after_join

all: $(TARGET)

test: all
	./C1219.sh
clean:
	rm -f $(TARGET) *.o mccore* core.* *.txt

CC = gcc
TARGET = C1474T01 C1474T02 C1474T03 C1474T04 C1474T05 C1474T06

all:: $(TARGET)

C1474T01: C1474T01.c
	$(CC) -g -Wall -o $@ $^

C1474T02: C1474T02.c
	$(CC) -g -Wall -o $@ $^

C1474T03: C1474T03.c
	$(CC) -g -Wall -o $@ $^

C1474T04: C1474T04.c
	$(CC) -g -Wall -O0 -pthread -o $@ $^

C1474T05: C1474T05.c
	$(CC) -g -Wall -O0 -pthread -o $@ $^

C1474T06: C1474T06.c
	$(CC) -g -Wall -O0 -pthread -o $@ $^

test:: all
	sh ./C1474.sh

clean::
	rm -f $(TARGET) *.o

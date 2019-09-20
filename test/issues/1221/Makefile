CC = gcc
TARGET = C1221T01

all:: $(TARGET)

C1221T01: C1221T01.c
	$(CC) -g -Wall -o $@ $^

test:: all
	sh ./C1221.sh

clean::
	rm -f $(TARGET) *.o

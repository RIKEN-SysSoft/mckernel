CC = gcc
TARGET = C452T01

all:: $(TARGET)

C452T01: C452T01.c
	$(CC) -g -Wall -o $@ $^

test:: all
	sh ./C452.sh

clean::
	rm -f $(TARGET) *.o

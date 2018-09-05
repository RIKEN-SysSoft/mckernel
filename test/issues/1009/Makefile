CC = gcc
TARGET = C1009T01

all:: $(TARGET)

C1009T01: C1009T01.c
	$(CC) -g -Wall -o $@ $^

test:: all
	sh ./C1009.sh

clean::
	rm -f $(TARGET) *.o

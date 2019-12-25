CC = gcc
TARGET = C1361T01

all:: $(TARGET)

C452T01: C1361T01.c
	$(CC) -g -Wall -o $@ $^

test:: all
	sh ./C1361.sh

clean::
	rm -f $(TARGET) *.o

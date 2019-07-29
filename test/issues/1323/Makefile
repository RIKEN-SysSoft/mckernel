CC = gcc
TARGET = rwlock

all:: $(TARGET)

rwlock: rwlock.c
	$(CC) -g -Wall -o $@ $^ -lpthread

test:: all
	sh ./rwlock.sh

clean::
	rm -f $(TARGET) *.o

CC = gcc
TARGET = CT1166

all:: $(TARGET)

C1009T01: CT1166.c
	$(CC) -g -Wall -o $@ $^

test:: all
	sh ./CT1166.sh

clean::
	rm -f $(TARGET) *.o

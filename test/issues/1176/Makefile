CC=gcc
TARGET=C1176T02 C1176T03 C1176T04

all:: $(TARGET)

C1176T02: C1176T02.c
	$(CC) -g -Wall -o $@ $^

C1176T03: C1176T03.c
	$(CC) -g -Wall -o $@ $^

C1176T04: C1176T04.c
	$(CC) -g -Wall -o $@ $^

test:: $(TARGET)
	sh ./C1176.sh

clean::
	rm -f $(TARGET) *.o

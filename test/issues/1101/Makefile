CC = gcc
TARGET = C1101T02 C1101T03 C1101T04 C1101T05

all:: $(TARGET)

C1101T02: C1101T02.c
	$(CC) -g -Wall -o $@ $^ -lnuma

C1101T03: C1101T03.c
	$(CC) -g -Wall -o $@ $^ -lnuma

C1101T04: C1101T04.c
	$(CC) -g -Wall -o $@ $^ -lnuma

C1101T05: C1101T05.c
	$(CC) -g -Wall -o $@ $^ -lnuma

test:: all
	sh ./C1101.sh

clean::
	rm -f $(TARGET) *.o

CC=gcc
TARGET=C1165T01

all:: $(TARGET)

C1024T01: C1165T01.c
	$(CC) -o C1165T01 C1165T01.c -Wall -g

test:: $(TARGET)
	sh ./C1165.sh

clean::
	rm -f *.o $(TARGET)

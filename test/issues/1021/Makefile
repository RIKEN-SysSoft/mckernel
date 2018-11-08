CC=gcc
TARGET=C1021

all:: $(TARGET)

C1021: C1021.c
	$(CC) -o C1021 C1021.c -Wall -g

test:: $(TARGET)
	sh ./C1021.sh

clean::
	rm -f *.o $(TARGET)

CC=gcc
TARGET=C926

all:: $(TARGET)

C926: C926.c
	$(CC) -o C926 C926.c -Wall -g

test:: $(TARGET)
	sh ./C926.sh

clean::
	rm -f *.o $(TARGET)

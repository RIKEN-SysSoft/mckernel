CC=gcc
TARGET=C765

all:: $(TARGET)

C765: C765.c
	$(CC) -o C765 C765.c -Wall -g

test:: $(TARGET)
	sh ./C765.sh

clean::
	rm -f *.o $(TARGET)

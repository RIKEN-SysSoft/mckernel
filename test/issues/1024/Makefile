CC=gcc
TARGET=C1024T01 C1024T02

all:: $(TARGET)

C1024T01: C1024T01.c
	$(CC) -o C1024T01 C1024T01.c -Wall -g

C1024T02: C1024T02.c
	$(CC) -o C1024T02 C1024T02.c -Wall -g

test:: $(TARGET)
	sh ./C1024.sh

clean::
	rm -f *.o $(TARGET) mcexec

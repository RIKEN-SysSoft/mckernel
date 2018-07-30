CC=gcc
TARGET=g310a

all:: $(TARGET)

g310a: g310a.c
	$(CC) -o g310a g310a.c -Wall -g

test:: $(TARGET)
	sh ./C731.sh

clean::
	rm -f *.o $(TARGET)

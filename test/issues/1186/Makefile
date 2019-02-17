TARGET=C1186
CC=gcc

all:: $(TARGET)

C1186: C1186.c
	$(CC) -o C1186 C1186.c

test:: $(TARGET)
	sh ./C1186.sh

clean::
	rm -f *.o $(TARGET)

CC=gcc
TARGET= C840T01 \
	C840T02 \
	C840T03 \
	C840T04 \
	C840T05 \
	C840T06

all:: $(TARGET)

C840T01: C840T01.c
	$(CC) -o C840T01 C840T01.c -Wall -g

C840T02: C840T02.c
	$(CC) -o C840T02 C840T02.c -Wall -g

C840T03: C840T03.c
	$(CC) -o C840T03 C840T03.c -Wall -g

C840T04: C840T04.c
	$(CC) -o C840T04 C840T04.c -Wall -g

C840T05: C840T05.c
	$(CC) -o C840T05 C840T05.c -Wall -g

C840T06: C840T06.c
	$(CC) -o C840T06 C840T06.c -Wall -g

test:: $(TARGET)
	sh ./C840.sh

clean::
	rm -f *.o $(TARGET) *.kmemleak rpf.data rpf.out

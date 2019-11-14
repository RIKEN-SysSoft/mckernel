CC = gcc
TARGET = C1410T01

all:: $(TARGET)

C1410T01: C1410T01.c
	if [ `uname -m` = x86_64 ]; then \
		$(CC) -g -Wall -o $@ $^ -lpthread ;\
	else \
		$(CC) -DPAUSE_INST=\"yield\" -g -Wall -o $@ $^ -lpthread ;\
	fi

test:: all
	sh ./C1410.sh

clean::
	rm -f $(TARGET) *.o

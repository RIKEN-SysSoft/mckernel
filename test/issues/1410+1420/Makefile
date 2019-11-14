CC = gcc
TARGET = C1410T01 C1420T01

all:: $(TARGET)

C1410T01: C1410T01.c
	if [ `uname -m` = x86_64 ]; then \
		$(CC) -g -Wall -o $@ $^ -lpthread ;\
	else \
		$(CC) -DPAUSE_INST=\"yield\" -g -Wall -o $@ $^ -lpthread ;\
	fi

C1420T01: C1420T01.c
	$(CC) -g -Wall -o $@ $^

test:: all
	sh ./C1410.sh

clean::
	rm -f $(TARGET) *.o

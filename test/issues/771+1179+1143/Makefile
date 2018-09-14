CC = gcc
TARGET= C771T001 C771T033 C771T037

CPPFLAGS =
LDFLAGS =

all: $(TARGET)

C771T001: C771T001.c
	$(CC) -g -Wall -o $@ $^ -pthread

C771T033: C771T033.c
	$(CC) -g -Wall -o $@ $^ -pthread

C771T037: C771T037.c
	$(CC) -g -Wall -o $@ $^ -pthread

test: all
	@sh ./C771.sh

clean:
	rm -f $(TARGET) *.o
	rm -rf gdb-result

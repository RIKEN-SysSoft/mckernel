# Makefile COPYRIGHT FUJITSU LIMITED 2018
CC=gcc
TARGET=sched_test go_test
all:: $(TARGET)

sched_test: sched_test.c
	$(CC) -o $@ $<

go_test: go_test.c
	$(CC) -o $@ $<

test:: $(TARGET)
	./run.sh

clean::
	rm -f $(TARGET)

CC=gcc
MCK_DIR=/home/satoken/ppos
MCEXEC=$(MCK_DIR)/bin/mcexec
TARGET=sched_test go_test
all:: $(TARGET)

sched_test: sched_test.c
	$(CC) -o $@ $<

go_test: go_test.c
	$(CC) -o $@ $<

test:: $(TARGET)
	-$(MCEXEC) ./go_test 2
	-$(MCK_DIR)/sbin/ihkosctl 0 kmsg | grep CT_ | cut -f 2 -d ":" | sort > result.log

clean::
	rm -f $(TARGET)

CC=gcc
MCEXEC=/home/satoken/ppos/bin/mcexec
TARGET=futex_wake_op unhandled_page_fault
all:: $(TARGET)

futex_wake_op: futex_wake_op.c
	$(CC) -o futex_wake_op -pthread $<

unhandled_page_fualt: unhandled_page_fault.c
	$(CC) -o unhandled_page_fault $<

test:: $(TARGET)
	-$(MCEXEC) ./futex_wake_op
	-$(MCEXEC) ./unhandled_page_fault
clean::
	rm -f $(TARGET)

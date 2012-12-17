CFLAGS = -O3 -Wall -g -pthread

all: mcexec

mcexec: mcexec.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ $(EXTRA_OBJS)

clean:
	rm -f mcexec

include $(HOME)/.mck_test_config.mk

CFLAGS=-g -O0 -Wall -I$(MCK_DIR)/include
LDFLAGS=-L$(MCK_DIR)/lib64 -lihk -Wl,-rpath=$(MCK_DIR)/lib64

all:
	$(CC) $(CFLAGS) $(LDFLAGS) get_rusage.c -o get_rusage
	$(CC) $(CFLAGS) filemap_sigbus.c -o filemap_sigbus

test: all
	./C1422.sh

clean:
	rm -f get_rusage filemap_sigbus

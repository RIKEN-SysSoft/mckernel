include $(HOME)/.mck_test_config.mk

CFLAGS=-g -O0 -Wall -I$(MCK_DIR)/include
LDFLAGS=-L$(MCK_DIR)/lib64 -lihk -Wl,-rpath=$(MCK_DIR)/lib64

all:
	$(CC) $(CFLAGS) $(LDFLAGS) get_rusage.c -o get_rusage
	$(CC) $(CFLAGS) issue_1325.c -o issue_1325

test: all
	./1342.sh

clean:
	rm -f get_rusage issue_1325

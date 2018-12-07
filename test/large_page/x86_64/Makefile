include $(HOME)/.mck_test_config.mk

CC = gcc

CPPFLAGS =
CFLAGS = -Wall -Werror -g
LDFLAGS =

PAGESIZE = $(shell getconf PAGESIZE)
ifeq ($(PAGESIZE),4096)
SRCS = $(shell ls *_4K.c | grep -v 502)
endif

EXES = $(SRCS:.c=)
OBJS = $(SRCS:.c=.o)

all: $(EXES)

test:: $(EXES)
	../driver.sh $(TESTSET)

501_4K: 501_4K.o 501_4K.lds
	$(CC) -o $@ $< $(LDFLAGS) -T 501_4K.lds

502_4K: 502_4K.o 502_4K.lds
	$(CC) -o $@ $< $(LDFLAGS) -T 502_4K.lds

clean:
	rm -f core $(EXES) $(OBJS)


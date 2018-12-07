include $(HOME)/.mck_test_config.mk

CC = gcc

CPPFLAGS =
CFLAGS = -Wall -Werror -g
LDFLAGS =

PAGESIZE = $(shell getconf PAGESIZE)
ifeq ($(PAGESIZE),65536)
SRCS = $(shell ls *_64K.c)
endif

ifeq ($(PAGESIZE),4096)
SRCS = $(shell ls *_4K.c)
endif

EXES = $(SRCS:.c=)
OBJS = $(SRCS:.c=.o)

all: $(EXES)

test:: $(EXES)
	../driver.sh $(TESTSET)

501_64K: 501_64K.o 501_64K.lds
	$(CC) -o $@ $< $(LDFLAGS) -T 501_64K.lds

502_64K: 502_64K.o 502_64K.lds
	$(CC) -o $@ $< $(LDFLAGS) -T 502_64K.lds

501_4K: 501_4K.o 501_4K.lds
	$(CC) -o $@ $< $(LDFLAGS) -T 501_4K.lds

502_4K: 502_4K.o 502_4K.lds
	$(CC) -o $@ $< $(LDFLAGS) -T 502_4K.lds

503_4K: 503_4K.o 503_4K.lds
	$(CC) -o $@ $< $(LDFLAGS) -T 503_4K.lds

504_4K: 504_4K.o 504_4K.lds
	$(CC) -o $@ $< $(LDFLAGS) -T 504_4K.lds

clean:
	rm -f core $(EXES) $(OBJS)


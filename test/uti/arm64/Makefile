# Makefile COPYRIGHT FUJITSU LIMITED 2019
CC = gcc
LDFLAGS =  -Wall -lpthread

CCFLAGS = -g -O0
CPPFLAGS =

SRCS = $(shell ls CT*.c)
TARGET = $(SRCS:.c=)

all: $(TARGET)

test: all
	./run.sh

%.o:: %.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

util.o:: util.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

CT31: CT31.o util.o
	$(CC) -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

CT32: CT32.o util.o
	$(CC) -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

CT33: CT33.o util.o
	$(CC) -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

CT34: CT34.o util.o
	$(CC) -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f $(TARGET) *.o

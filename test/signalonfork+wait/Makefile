# Makefile COPYRIGHT FUJITSU LIMITED 2019
CC?=gcc
LDFLAGS=-lpthread
CFLAGS=-Wall -O0 -ggdb3

all: signalonfork_wait
signalonfork_wait: signalonfork_wait.o
signalonfork_wait.o: signalonfork_wait.c
clean:
	rm -f signalonfork_wait.o signalonfork_wait

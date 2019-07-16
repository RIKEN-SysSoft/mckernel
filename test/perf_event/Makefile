CC?=gcc
CPPFLAGS=-D_GNU_SOURCE
CFLAGS=-Wall

all: perf_test

debug:CFLAGS+=-O0 -ggdb3
debug:all

perf_test: perf_test.o perftool.o
perftool.o: perftool.c perftool.h
clean:
	rm -f perf_test.o perftool.o perf_test

# Makefile COPYRIGHT FUJITSU LIMITED 2020

CC      = gcc
INC     = -I../include -I/home/users/ea01/ea0105/aarch64/usr/include
LDFLAGS = -lpthread -L/home/users/ea01/ea0105/aarch64/usr/lib -luti -Wl,-rpath -Wl,/home/users/ea01/ea0105/aarch64/usr/lib
# CFLAGS  = -g -Wall 
CFLAGS  = -g

all: uti_perf ctrl

ctrl: ctrl.c
	$(CC) $(INC) $(LDFLAGS) $(CFLAGS) -o $@ $^

uti_perf: uti_perf.c
	$(CC) $(INC) $(LDFLAGS) $(CFLAGS) -o $@ $^

.PHONY: clean
clean: 
	$(RM) -f uti_perf ctrl


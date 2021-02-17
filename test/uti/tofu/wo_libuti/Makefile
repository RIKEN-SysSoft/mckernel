# Makefile COPYRIGHT FUJITSU LIMITED 2020

CC      = gcc
INC     = -I../include
LDFLAGS = -lpthread
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


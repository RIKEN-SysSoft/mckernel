# Makefile COPYRIGHT FUJITSU LIMITED 2019
CC=$(CROSS_COMPILE)gcc
CPPFLAGS:=$(CPPFLAGS) -I/usr/local/include/ihk -I/usr/local/include/ihk
CFLAGS:=-O0 -ggdb3 -Wall
LDFLAGS:=

all: helloworld fork pthread_create freeze thaw

helloworld: helloworld.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) helloworld.c -o helloworld

fork: fork.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) fork.c -o fork

pthread_create: pthread_create.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -lpthread pthread_create.c -o pthread_create

freeze: freeze.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) freeze.c -o freeze

thaw: thaw.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) thaw.c -o thaw

clean:
	rm -rf helloworld fork pthread_create freeze thaw

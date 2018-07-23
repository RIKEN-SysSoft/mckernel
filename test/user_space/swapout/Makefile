PPOSDIR=/home/iizuka/mckernel
MPIDIR=/usr/lib64/mpich-3.2
MPIBINDIR=$(MPIDIR)/bin
MPILIBDIR=$(MPIDIR)/lib
CC=gcc

LIBDIR=$(PPOSDIR)/lib
LDFLAGS=-L$(LIBDIR) -Wl,-rpath=$(LIBDIR) -Wl,-rpath,$(MPILIBDIR)
CFLAGS= -I$(PPOSDIR)/include

TARGETS= swaptest

all:: $(TARGETS)

swaptest: swaptest.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $@.c

clean::
	rm -f $(TARGETS) 

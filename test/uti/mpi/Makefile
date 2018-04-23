.SUFFIXES:	# Clear suffixes

MYHOME=/work/gg10/e29005
MPILIB=${MYHOME}/project/mpich/install

CC=mpicc 
LD=$(CC)

CFLAGS = -g -O2
LDFLAGS = -lpthread -lpsm2
SRCS = $(shell ls *.c)
OBJS = $(SRCS:.c=.o)
EXES = $(SRCS:.c=)
TMPFILES = $(shell ls psm2-demo-* 2>/dev/null)

all: $(EXES) file

file: $(TMPFILES)
	rm -f $(TMPFILES)
	dd if=/dev/zero of=./file  bs=1M  count=1

async_progress.o:: async_progress.c util.h
	$(CC) $(CFLAGS) -c $<

util.o:: util.c util.h
	$(CC) $(CFLAGS) -c $<

014: 014.o async_progress.o util.o
	$(LD) -o $@ $^ $(LDFLAGS)

015: 015.o async_progress.o
	$(LD) -o $@ $^ $(LDFLAGS)

011: 011.o
	$(LD) -o $@ $^ $(LDFLAGS) -qopenmp

011.o::011.c
	$(CC) $(CFLAGS) -qopenmp -c $<

%: %.o
	$(LD) -o $@ $^ $(LDFLAGS)

%.o::%.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f core $(EXES) $(OBJS) $(DSRCS)


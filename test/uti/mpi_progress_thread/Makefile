.SUFFIXES:	# Clear suffixes

#CC = mpiicc
CC = ${HOME}/project/src/mvapich/install/bin/mpicc

LD=$(CC)

CFLAGS = -g -O2
LDFLAGS =
SRCS = $(shell ls *.c)
OBJS = $(SRCS:.c=.o)
EXES = $(SRCS:.c=)

all: $(EXES) file

file:
	dd if=/dev/zero of=./file  bs=1M  count=1

%: %.o
	$(LD) -o $@ $^ $(LDFLAGS)

%.o::%.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f core $(EXES) $(OBJS) $(DSRCS)


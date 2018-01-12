.SUFFIXES:	# Clear suffixes

MYHOME=/work/gg10/e29005
MPILIB=${MYHOME}/project/mpich/install

CC=${MPILIB}/bin/mpicc 

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


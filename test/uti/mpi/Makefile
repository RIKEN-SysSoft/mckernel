.SUFFIXES:	# Clear suffixes

MYHOME=/home/e29005

# Specify it via 016.sh 
UTI_DIR=${MYHOME}/project/uti/install_linux

CC=mpiicc 
LD=$(CC)

CFLAGS = -g -O0 -Wall
LDFLAGS = -lpthread -lpsm2 -L$(UTI_DIR)/lib -Wl,-rpath -Wl,$(UTI_DIR)/lib -luti
SRCS = $(shell ls *.c)
OBJS = $(SRCS:.c=.o)
EXES = $(SRCS:.c=)
TMPFILES = $(shell ls psm2-demo-* 2>/dev/null)

all: $(EXES) file

file: $(TMPFILES)
	rm -f $(TMPFILES)
	dd if=/dev/zero of=./file  bs=1M  count=1

async_progress.o:: async_progress.c util.h
	$(CC) $(CFLAGS) -I$(UTI_DIR)/include -c $<

util.o:: util.c util.h
	$(CC) $(CFLAGS) -qopenmp -c $<

014: 014.o async_progress.o util.o
	$(LD) -o $@ $^ $(LDFLAGS)

015: 015.o async_progress.o
	$(LD) -o $@ $^ $(LDFLAGS)

016: 016.o async_progress.o util.o
	$(LD) -o $@ $^ $(LDFLAGS) -qopenmp

016.o::016.c
	$(CC) $(CFLAGS) -qopenmp -c $<

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


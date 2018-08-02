.SUFFIXES:	# Clear suffixes
.ONESHELL:	# Pack all the lines and pass it to shell

MYHOME=/home/e29005

# Specify it via *.sh 
UTI_DIR=${MYHOME}/project/uti/install_linux

CC=mpiicc
LD=$(CC)

CFLAGS = -g -O0 -Wall
LDFLAGS = -lpthread -L$(UTI_DIR)/lib -Wl,-rpath -Wl,$(UTI_DIR)/lib -luti
SRCS = $(shell ls *.c)
OBJS = $(SRCS:.c=.o)
EXES = $(SRCS:.c=)

define create_files =
	for i in {1..2}; do
		dd if=/dev/zero of=./data/$i bs=1M count=1
	done
endef

all: $(EXES) file

file::
	$(value create_files)

util.o:: util.c util.h
	$(CC) $(CFLAGS) -qopenmp -c $<

001: 001.o util.o
	$(LD) -o $@ $^ $(LDFLAGS) -qopenmp

001.o:: 001.c
	$(CC) $(CFLAGS) -qopenmp -c $<

%: %.o
	$(LD) -o $@ $^ $(LDFLAGS)

%.o::%.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f core $(EXES) $(OBJS) $(DSRCS)

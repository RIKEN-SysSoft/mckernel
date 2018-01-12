.SUFFIXES:	# Disable implicit rules

CC = gcc

CPPFLAGS =
CCFLAGS = -g -O2
LDFLAGS = -lpthread -lrt
SRCS = $(shell ls CT*.c)
EXES = $(SRCS:.c=)
OBJS = $(SRCS:.c=.o)

all: $(EXES) file

file::
	dd bs=4096 count=1000 if=/dev/zero of=./file

%.o:: %.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

%: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean :
	rm -f core $(EXES) $(OBJS)

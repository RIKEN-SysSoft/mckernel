.SUFFIXES:	# Disable implicit rules

CC = gcc

CPPFLAGS = -I/home/takagi/project/uti/install/include
CCFLAGS = -g -O2
LDFLAGS = -L/home/takagi/project/uti/install/lib -Wl,-rpath,/home/takagi/project/uti/install/lib -luti -lpthread -lrt 
SRCS = $(shell ls CT*.c)
EXES = $(SRCS:.c=)
OBJS = $(SRCS:.c=.o)

all: $(EXES) file

file::
	dd bs=4096 count=1000 if=/dev/zero of=./file

CT30.o:: CT30.c
	icc $(CCFLAGS) -qopenmp $(CPPFLAGS) -c $<

CT30: CT30.o
	icc -o $@ $^ $(LDFLAGS) -qopenmp


%.o:: %.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

%: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean :
	rm -f core $(EXES) $(OBJS)

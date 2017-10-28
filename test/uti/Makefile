.SUFFIXES:	# Disable implicit rules

CC = gcc

CPPFLAGS =
CCFLAGS = -g -O2
LDFLAGS = -lpthread
SRCS = $(shell ls CT*.c)
EXES = $(SRCS:.c=)
OBJS = $(SRCS:.c=.o)

all: $(EXES)

%.o:: %.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

%: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean :
	rm -f core $(EXES) $(OBJS)

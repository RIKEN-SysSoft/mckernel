.SUFFIXES:	# Clear suffixes

CC=gcc

LD=$(CC)

CFLAGS = -g -O2
LDFLAGS = -lpthread -lpsm2
SRCS = $(shell ls *.c)
OBJS = $(SRCS:.c=.o)
EXES = $(SRCS:.c=)
TMPFILES = $(shell ls psm2-demo-*)

all: $(EXES) file

file::$(TMPFILES)
	rm -f $(TMPFILES)

%: %.o
	$(LD) -o $@ $^ $(LDFLAGS)

%.o::%.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f core $(EXES) $(OBJS) $(DSRCS)


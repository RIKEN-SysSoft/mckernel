VPATH = 

CC = icc
CFLAGS = -Wall -O0 -g -DDEBUG -DERROR
LD = $(CC)
LFLAGS = -libverbs

SRCS = list.c curtime.c printmem.c debug.c post.c qp.c read_config.c resource.c rdma_wr.c 
DSRCS = $(SRCS:.c=.d)
OBJS = $(SRCS:.c=.o)
EXECS = rdma_wr 
MODULES = list.o curtime.o printmem.o debug.o post.o qp.o read_config.o resource.o sock.o

CWD := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

all: $(EXECS)

rdma_wr: rdma_wr.o $(MODULES)
	$(LD) -o $@ $^ $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.d: %.c
	$(CC) -MM $< > $*.d

clean:
	rm -f $(EXECS) $(OBJS) $(DSRCS)

-include $(DSRCS)

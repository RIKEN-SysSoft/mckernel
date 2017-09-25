VPATH = 

MCK_DIR=/home/satoken/ppos
MPICH_DIR=/usr/lib64/mpich-3.2

CC = icc
MPICC = mpicc
CFLAGS = -Wall -O0 -g -DDEBUG -DERROR
LD = $(CC)
LFLAGS = -libverbs
LDFLAGS = -L$(MPICH_DIR)/lib -L$(MCK_DIR)/lib

SRCS = list.c curtime.c printmem.c debug.c post.c qp.c read_config.c resource.c mpi_rdma_wr.c
DSRCS = $(SRCS:.c=.d)
OBJS = $(SRCS:.c=.o)
EXECS = mpi_rdma_wr
MODULES = list.o curtime.o printmem.o debug.o post.o qp.o read_config.o resource.o sock.o

CWD := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

all: $(EXECS)

rdma_wr: rdma_wr.o $(MODULES)
	$(LD) -o $@ $^ $(LFLAGS)

mpi_rdma_wr: mpi_rdma_wr.o $(MODULES)
	$(LD) $(LDFLAGS) -lqlmpi -lmpi -o $@ $^ $(LFLAGS) 

mpi_rdma_wr.o: mpi_rdma_wr.c
	$(MPICC) -I$(MCK_DIR)/include $(CFLAGS) -c $<

%.o: %.c
	$(MPICC) $(CFLAGS) $(LDFLAGS) -c $<

%.d: %.c
	$(MPICC) $(LDFLAGS) -MM $< > $*.d

clean:
	rm -f $(EXECS) $(OBJS) $(DSRCS)

-include $(DSRCS)

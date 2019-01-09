VPATH = 

CC = icc
CFLAGS = -Wall -O0 -g -DDEBUG -DERROR
LD = $(CC)
LFLAGS = -libverbs

SRCS = list.c curtime.c printmem.c debug.c post.c qp.c read_config.c resource.c ud.c ud.c rdma_wr.c rdma_wr_chain.c rdma_rd.c rdma_rdv.c send.c
DSRCS = $(SRCS:.c=.d)
OBJS = $(SRCS:.c=.o)
EXECS = send rdma_wr rdma_rd rdma_rdv rdma_wr_chain ud cas
MODULES = list.o curtime.o printmem.o debug.o post.o qp.o read_config.o resource.o sock.o

CWD := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

all: $(EXECS)

run-%: $*
	sudo ssh kncc10 "sh -c 'echo 1024 > /proc/sys/vm/nr_hugepages'"
	sudo ssh kncc11 "sh -c 'echo 1024 > /proc/sys/vm/nr_hugepages'"
	sudo ssh kncc10 "echo userspace > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
	sudo ssh kncc10 "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq > /sys/devices/system/cpu/cpu0/cpufreq/scaling_setspeed"
	sudo ssh kncc11 "echo userspace > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
	sudo ssh kncc11 "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq > /sys/devices/system/cpu/cpu0/cpufreq/scaling_setspeed"
	sudo ssh kncc10 "service cpuspeed stop"
	sudo ssh kncc11 "service cpuspeed stop"
	ssh kncc11 "for i in {1..5}; do taskset 0x00ff $(CWD)/$*; done" &
	ssh kncc10 "for i in {1..5}; do taskset 0x00ff $(CWD)/$* -s kncc11; done"

kill-%:
	ssh kncc11 "~/project/mpich/src/tools/kill.pl $*" 
	ssh kncc10 "~/project/mpich/src/tools/kill.pl $*" 


cas: cas.o $(MODULES)
	$(LD) -o $@ $^ $(LFLAGS)

ud: ud.o $(MODULES)
	$(LD) -o $@ $^ $(LFLAGS)

rdma_wr_chain: rdma_wr_chain.o $(MODULES)
	$(LD) -o $@ $^ ${LFLAGS}

rdma_wr: rdma_wr.o $(MODULES)
	$(LD) -o $@ $^ $(LFLAGS)

rdma_rd: rdma_rd.o $(MODULES)
	$(LD) -o $@ $^ $(LFLAGS)  	

rdma_rdv: rdma_rdv.o $(MODULES)
	$(LD) -o $@ $^ $(LFLAGS)  	

send: send.o $(MODULES)
	$(LD) -o $@ $^ $(LFLAGS)

reg_mr: reg_mr.o $(MODULES)
	$(LD) -o $@ $^ $(LFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.d: %.c
	$(CC) -MM $< > $*.d

clean:
	rm -f $(EXECS) $(OBJS) $(DSRCS)

-include $(DSRCS)

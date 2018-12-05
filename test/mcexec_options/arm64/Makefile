# Makefile COPYRIGHT FUJITSU LIMITED 2018
CC = gcc
TARGET = extend_heap node_bind allow_oversubscribe stack_premap
LDFLAGS = 

all: $(TARGET)

extend_heap: extend_heap.c
	$(CC) -o $@ $^ $(LDFLAGS)

node_bind: node_bind.c
	$(CC) -o $@ $^ $(LDFLAGS) -lnuma

allow_oversubscribe: allow_oversubscribe.c
	$(CC) -o $@ $^ $(LDFLAGS)

stack_premap: stack_premap.c
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	./run_extend_heap.sh
	./run_node_bind.sh
	./run_nr_partitions.sh
	./run_allow_oversubscribe.sh
	./run_stack_premap.sh

clean:
	rm -f $(TARGET)

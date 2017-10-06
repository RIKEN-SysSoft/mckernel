.SUFFIXES:	# Clear suffixes
.SUFFIXES:	.c 

CC = gcc

MCMOD_DIR=$(HOME)/ppos
XPMEM_DIR=$(HOME)/install/xpmem-master

CPPFLAGS = -I$(MCMOD_DIR)/include
CCFLAGS = -g
LDFLAGS = -L$(MCMOD_DIR)/lib -lihk -Wl,-rpath=$(MCMOD_DIR)/ppos/lib
EXES = 
SRCS = 
OBJS = $(SRCS:.c=.o)

CPPFLAGSMCK = -I$(HOME)/usr/include
CCFLAGSMCK = -g -O0
#LDFLAGSMCK = -static 
LDFLAGSMCK = 
SRCSMCK = $(shell ls rusage*.c)
EXESMCK = $(SRCSMCK:.c=)
OBJSMCK = $(SRCSMCK:.c=.o)

all: $(EXES) $(EXESMCK)

rusage010: rusage010.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage010.o: rusage010.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<


rusage008: rusage008.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage008.o: rusage008.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage009: rusage009.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage009.o: rusage009.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage011: rusage011.o
	$(CC) -o $@ $^ $(LDFLAGSMCK) -I$(XPMEM_DIR)/include -L$(XPMEM_DIR)/lib -lxpmem -Wl,-rpath=$(XPMEM_DIR)/lib

rusage011.o: rusage011.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<


clean:
	rm -f core $(EXES) $(OBJS) $(EXESMCK) $(OBJSMCK)

.SUFFIXES:	# Disable implicit rules

SYSCALLL_INTERCEPT_DIR=$(HOME)/install/syscall_intercept
UTI_DIR=$(HOME)/ihk+mckernel

CC = gcc

CPPFLAGS = -I$(UTI_DIR)/include
CCFLAGS = -g -O0
LDFLAGS = -L$(UTI_DIR)/lib -Wl,-rpath,$(UTI_DIR)/lib -luti -lpthread -lrt
LDFLAGS2 = -lpthread -lrt

SRCS = $(shell ls CT*.c)
EXES = $(SRCS:.c=)
OBJS = $(SRCS:.c=.o)

CFLAGS_SO = -g -O2 -I$(SYSCALLL_INTERCEPT_DIR)/include
LDFLAGS_SO = -L$(SYSCALLL_INTERCEPT_DIR)/lib64 -Wl,-rpath,$(SYSCALLL_INTERCEPT_DIR)/lib64 -lsyscall_intercept -fpic -shared
SO_SRCS = preloadlib.c
SOS = $(SO_SRCS:.c=.so)


all: $(EXES) file $(SOS)

file::
	dd bs=4096 count=1000 if=/dev/zero of=./file

CT30.o:: CT30.c
	icc $(CCFLAGS) -qopenmp $(CPPFLAGS) -c $<

CT30: CT30.o util.o
	icc -o $@ $^ $(LDFLAGS) -qopenmp

CT31: CT31.o util.o
	$(CC) -o $@ $^ $(LDFLAGS2) $(CPPFLAGS)

CT32: CT32.o util.o
	$(CC) -o $@ $^ $(LDFLAGS2) $(CPPFLAGS)

CT33: CT33.o util.o
	$(CC) -o $@ $^ $(LDFLAGS2) $(CPPFLAGS)

CT34: CT34.o util.o
	$(CC) -o $@ $^ $(LDFLAGS2) $(CPPFLAGS)

%.o:: %.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

%: %.o util.o
	$(CC) -o $@ $^ $(LDFLAGS)

util.o:: util.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

preloadlib.so: preloadlib.c
	$(CC) $(CFLAGS_SO) $(LDFLAGS_SO) $^ -o $@ 

clean :
	rm -f core $(EXES) $(OBJS)

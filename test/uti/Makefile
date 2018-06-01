.SUFFIXES:	# Disable implicit rules

SI_DIR=/home/takagi/usr
UTI_DIR=/home/takagi/project/uti/install

CC = gcc

CPPFLAGS = -I$(UTI_DIR)/include
CCFLAGS = -g -O2
LDFLAGS = -L$(UTI_DIR)/lib -Wl,-rpath,$(UTI_DIR)/lib -luti -lpthread -lrt 

SRCS = $(shell ls CT*.c)
EXES = $(SRCS:.c=)
OBJS = $(SRCS:.c=.o)

CFLAGS_SO = -g -O2 -I$(SI_DIR)/include
LDFLAGS_SO = -L$(SI_DIR)/lib64 -Wl,-rpath,$(SI_DIR)/lib64 -lsyscall_intercept -fpic -shared
SO_SRCS = preloadlib.c
SOS = $(SO_SRCS:.c=.so)


all: $(EXES) file $(SOS)

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

preloadlib.so: preloadlib.c
	$(CC) $(CFLAGS_SO) $(LDFLAGS_SO) $^ -o $@ 

clean :
	rm -f core $(EXES) $(OBJS)

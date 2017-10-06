.SUFFIXES:	# Clear suffixes
.SUFFIXES:	.c 

CC = gcc

CPPFLAGS = -I$(HOME)/project/os/install/include
CCFLAGS = -g
LDFLAGS = -L$(HOME)/project/os/install/lib -lihk -Wl,-rpath -Wl,$(HOME)/project/os/install/lib
EXES = 
SRCS = 
OBJS = $(SRCS:.c=.o)

CPPFLAGSMCK = -I$(HOME)/usr/include
CCFLAGSMCK = -g -O0
LDFLAGSMCK = -static 
SRCSMCK = $(shell ls rusage*.c)
EXESMCK = $(SRCSMCK:.c=)
OBJSMCK = $(SRCSMCK:.c=.o)

all: $(EXES) $(EXESMCK)

rusage000: rusage000.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage000.o: rusage000.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage010: rusage010.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage010.o: rusage010.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage020: rusage020.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage020.o: rusage020.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage030: rusage030.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage030.o: rusage030.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage001: rusage001.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage001.o: rusage001.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage002: rusage002.o
	$(CC) -o $@ $^ $(LDFLAGSMCK) -lrt

rusage002.o: rusage002.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage003: rusage003.o
	$(CC) -o $@ $^ $(LDFLAGSMCK) -lrt

rusage003.o: rusage003.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage004: rusage004.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage004.o: rusage004.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage006: rusage006.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage006.o: rusage006.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage007: rusage007.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage007.o: rusage007.c
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
	$(CC) -o $@ $^ $(LDFLAGSMCK) -L/home/takagi/usr/lib -lxpmem

rusage011.o: rusage011.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage012: rusage012.o
	$(CC) -o $@ $^ $(LDFLAGSMCK) -L/home/takagi/usr/lib -lxpmem

rusage012.o: rusage012.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage013: rusage013.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage013.o: rusage013.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage014: rusage014.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage014.o: rusage014.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage015: rusage015.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage015.o: rusage015.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage016: rusage016.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage016.o: rusage016.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage017: rusage017.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage017.o: rusage017.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage018: rusage018.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

rusage018.o: rusage018.c
	$(CC) $(CCFLAGSMCK) $(CPPFLAGSMCK) -c $<

rusage100: rusage100.o
	$(CC) -o $@ $^ $(LDFLAGS)

rusage100.o: rusage100.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

rusage101: rusage101.o
	$(CC) -o $@ $^ $(LDFLAGS)

rusage101.o: rusage101.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

rusage102: rusage102.o
	$(CC) -o $@ $^ $(LDFLAGS)

rusage102.o: rusage102.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

rusage103: rusage103.o
	$(CC) -o $@ $^ $(LDFLAGS)

rusage103.o: rusage103.c
	$(CC) $(CCFLAGS) $(CPPFLAGS) -c $<

clean:
	rm -f core $(EXES) $(OBJS) $(EXESMCK) $(OBJSMCK)

.SUFFIXES:	# Clear suffixes
.SUFFIXES:	.c

MCKDIR=$(HOME)/project/os/install
CC=gcc

CPPFLAGS_LIN=-I$(MCKDIR)/include -DMCKDIR=$(MCKDIR)
CCFLAGS_LIN=-g -Wall
LDFLAGS_LIN=-L$(MCKDIR)/lib -lihk -Wl,-rpath -Wl,$(MCKDIR)/lib -lbfd
SRCS_LIN=$(shell ls *_lin.c)
EXES_LIN=$(SRCS_LIN:.c=)
OBJS_LIN=$(SRCS_LIN:.c=.o)

CPPFLAGS_MCK =
CCFLAGS_MCK=-g -Wall
LDFLAGS_MCK=-lpthread
SRCS_MCK=$(shell ls *_mck.c)
EXES_MCK=$(SRCS_MCK:.c=)
OBJS_MCK=$(SRCS_MCK:.c=.o)

all: $(EXES_LIN) $(EXES_MCK)

test: $(EXES_LIN) $(EXES_MCK)
	sudo ./1141_lin

%_lin: %_lin.o
	$(CC) -o $@ $^ $(LDFLAGS_LIN)

%_lin.o: %_lin.c
	$(CC) $(CCFLAGS_LIN) $(CPPFLAGS_LIN) -c $<

%_mck: %_mck.o
	$(CC) -o $@ $^ $(LDFLAGS_MCK)

%_mck.o: %_mck.c
	$(CC) $(CCFLAGS_MCK) $(CPPFLAGS_MCK) -c $<

clean:
	rm -f core $(EXES_LIN) $(OBJS_LIN) $(EXES_MCK) $(OBJS_MCK)


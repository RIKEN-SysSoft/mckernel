include $(HOME)/.mck_test_config.mk
XPMEM_DIR=$(HOME)/usr

CC = gcc

CPPFLAGSLIN = -I$(MCK_DIR)/include
CFLAGSLIN = -Wall -Werror -g
LDFLAGSLIN = -L$(MCK_DIR)/lib -lihk -Wl,-rpath -Wl,$(MCK_DIR)/lib -lpthread
SRCSLIN = $(shell ls *_lin.c)
EXESLIN = $(SRCSLIN:.c=)
OBJSLIN = $(SRCSLIN:.c=.o)

CPPFLAGSMCK =
CFLAGSMCK = -Wall -Werror -g -O0
LDFLAGSMCK =
SRCSMCK = $(shell ls *.c | grep -vE '_lin')
EXESMCK = $(SRCSMCK:.c=)
OBJSMCK = $(SRCSMCK:.c=.o)

all: $(EXESLIN) $(EXESMCK)

011_mck: 011_mck.o
	$(CC) -o $@ $^ $(LDFLAGSMCK) -L$(XPMEM_DIR)/lib -Wl,-rpath -Wl,$(XPMEM_DIR)/lib -lxpmem

011_mck.o: 011_mck.c
	$(CC) $(CFLAGSMCK) $(CPPFLAGSMCK) -I$(XPMEM_DIR)/include -c $<

012_mck: 012_mck.o
	$(CC) -o $@ $^ $(LDFLAGSMCK) -L$(XPMEM_DIR)/lib -lxpmem -Wl,-rpath -Wl,$(XPMEM_DIR)/lib

012_mck.o: 012_mck.c
	$(CC) $(CFLAGSMCK) $(CPPFLAGSMCK) -I$(XPMEM_DIR)/include -c $<

10%_mck: 10%_mck.o
	$(CC) -o $@ $^ $(LDFLAGSMCK) -L$(MCK_DIR)/lib -lihk -Wl,-rpath -Wl,$(MCK_DIR)/lib

10%_mck.o:: 10%_mck.c
	$(CC) $(CFLAGSMCK) $(CPPFLAGSMCK) -I$(MCK_DIR)/include -c $<

20%_mck: 20%_mck.o
	$(CC) -o $@ $^ $(LDFLAGSMCK) -lpthread

20%_mck.o:: 20%_mck.c
	$(CC) $(CFLAGSMCK) $(CPPFLAGSMCK) -c $<

%_mck: %_mck.o
	$(CC) -o $@ $^ $(LDFLAGSMCK)

%_mck.o:: %_mck.c
	$(CC) $(CFLAGSMCK) $(CPPFLAGSMCK) -c $<


%_lin.o:: %_lin.c
	$(CC) $(CFLAGSLIN) $(CPPFLAGSLIN) -c $<

%_lin: %_lin.o
	$(CC) -o $@ $^ $(LDFLAGSLIN)

clean:
	rm -f core $(EXESLIN) $(OBJSLIN) $(EXESMCK) $(OBJSMCK)

include $(HOME)/.mck_test_config.mk

MPIDIR=/usr/lib64/mpich-3.2
MPIBINDIR=$(MPIDIR)/bin
MPILIBDIR=$(MPIDIR)/lib
CC=gcc

MPIF90=$(MPIBINDIR)/mpif90
MPICC=$(MPIBINDIR)/mpicc
LIBDIR=$(MCK_DIR)/lib
LDFLAGS=-L$(LIBDIR) -lqlmpi -Wl,-rpath=$(LIBDIR) -Wl,-rpath,$(MPILIBDIR)
CFLAGS= -I$(MCK_DIR)/include

TARGETS= usr_prg_A usr_prg_B usr_prg_C usr_prg_irreg CT20a CT20b CT21a CT21b file1 file2 CT22a CT22b

all:: $(TARGETS)

usr_prg_A: usr_prg_A.c
	$(MPICC) $(CFLAGS) $(LDFLAGS) -lqlmpi -o $@ $@.c

usr_prg_B: usr_prg_B.c
	$(MPICC) $(CFLAGS) $(LDFLAGS) -lqlmpi -o $@ $@.c

usr_prg_C: usr_prg_C.c
	$(MPICC) $(CFLAGS) $(LDFLAGS) -lqlmpi -o $@ $@.c

usr_prg_irreg: usr_prg_irreg.c
	$(MPICC) $(CFLAGS) $(LDFLAGS) -lqlmpi -o $@ $@.c

CT20a: CT20.f
	$(MPIF90) -o $@ $< $(LDFLAGS)

CT20b: CT20.f
	$(MPIF90) -o $@ $< $(LDFLAGS)

CT21a: CT21.f
	$(MPIF90) -o $@ $< $(LDFLAGS)

CT21b: CT21.f
	$(MPIF90) -o $@ $< $(LDFLAGS)

CT22a: CT22.f
	$(MPIF90) -O -fopenmp -o $@ $< $(LDFLAGS)

CT22b: CT22.f
	$(MPIF90) -O -fopenmp -o $@ $< $(LDFLAGS)

file1: gendata
	./gendata 1 536870912 > $@

file2: gendata
	./gendata 2 536870912 > $@

gendata: gendata.c
	$(CC) -o $@ $<

clean::
	rm -f $(TARGETS) gendata

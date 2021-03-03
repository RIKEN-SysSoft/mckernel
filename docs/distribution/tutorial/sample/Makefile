PPOS_INSTALL=/opt/ppos
CC            = gcc
FORT          = gfortran
FLAGS         =
LDFLAGS       =
PROGRAM       = chello fhello picpth picomp pifomp


all:            $(PROGRAM)

chello:         hello.c 
		$(CC) $(FLAGS) $(LDFLAGS) -o chello hello.c

fhello:         hello.f90
		$(FORT) $(FLAGS) $(LDFLAGS) -o fhello hello.f90

picpth:         pi_pth.c 
		$(CC) $(FLAGS) $(LDFLAGS) -lpthread -o picpth pi_pth.c

picomp:         pi_omp.c 
		$(CC) $(FLAGS) $(LDFLAGS) -openmp -o picomp pi_omp.c

pifomp:         pi_omp.f90 
		$(FORT) $(FLAGS) $(LDFLAGS) -openmp -o pifomp pi_omp.f90

clean:;         rm -f $(PROGRAM)



MCHOME=/home/aleix/install/`uname -r`
MPIHOME=/opt/intel/impi/2017.2.174/bin64/
#CFLAGS+=-I$(MCHOME)/include
#LDFLAGS+=-L$(MCHOME)/lib -lihk

CFLAGS+=-g -std=gnu99

TARGET=test test.mc rpebs test_mt faker

all:  $(TARGET)

test: test.c
	gcc $(CFLAGS) $^ -o $@

test.mc: test.c
	gcc -DMCKERNEL $(CFLAGS) $^ $(LDFLAGS) -o $@

test_mt: test_mt.c
	gcc $(CFLAGS) $^ $(LDFLAGS) -lpthread -o $@

rpebs: rpebs.c
	gcc $(CFLAGS) $^ -o $@

faker: faker.c
	gcc $(CFLAGS) $^ -o $@

mcrun:
	$(MCHOME)/bin/mcexec ./test.mc

mpirun:
	$(MPIHOME)/mpirun -n 3 $(MCHOME)/bin/mcexec -n 3 ./test.mc

clean:
	rm -f $(TARGET) core pebs_*.out *.dat

CC = gcc
TARGET=perf_test perf_case_a perf_case_b perf_case_c perf_case_d perf_case_e perf_case_f

CPPFLAGS =
LDFLAGS =

all: $(TARGET)

perf_tool.o: perftool.c perftool.h

perf_test: perf_test.c perftool.o
	$(CC) -o $@ $^ $(LDFLAGS)

perf_case_a: perf_case_a.c perftool.o
	$(CC) -o $@ $^ $(LDFLAGS)

perf_case_b: perf_case_b.c perftool.o
	$(CC) -o $@ $^ $(LDFLAGS)

perf_case_c: perf_case_c.c perftool.o
	$(CC) -o $@ $^ $(LDFLAGS)

perf_case_d: perf_case_d.c perftool.o
	$(CC) -o $@ $^ $(LDFLAGS)

perf_case_e: perf_case_e.c perftool.o
	$(CC) -o $@ $^ $(LDFLAGS)

perf_case_f: perf_case_f.c perftool.o
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	@sh ./C1025.sh

clean:
	rm -f $(TARGET) *.o *.txt


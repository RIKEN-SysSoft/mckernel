all: perf_test
test: perf_test
	./C1025.sh
perf_test: perf_test.o perftool.o
perftool.o: perftool.c perftool.h
clean:
	rm -f perf_test perf_test.o perftool.o


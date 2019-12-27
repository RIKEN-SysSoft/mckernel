#INPUT=./test-PERF-sampling.dat
INPUT=./python3-PERF-sampling.dat

all: perf_script_faker test

perf_script_faker: perf_script_faker.c ht.c
	gcc -g $^ -o $@

test: test.c
	gcc $^ -lpthread -o $@

run: perf_script_faker
	./perf_script_faker $(INPUT)

conv: perf_script_faker
	./perf_script_faker $(INPUT) > out.perf
	stackcollapse-perf.pl out.perf > out.folded
	flamegraph.pl out.folded > mckernel.svg

clean:
	rm -f perf_script_faker test

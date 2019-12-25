all: perf_script_faker

perf_script_faker: perf_script_faker.c
	gcc $^ -o $@

run: perf_script_faker
	./perf_script_faker ./python3-PERF-sampling.dat

conv: perf_script_faker
	./perf_script_faker ./python3-PERF-sampling.dat > out.perf
	stackcollapse-perf.pl out.perf > out.folded
	flamegraph.pl out.folded > mckernel.svg

clean:
	rm -f perf_script_faker

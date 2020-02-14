
all:: show-omp-cpu-affinity

show-omp-cpu-affinity:: show-omp-cpu-affinity.c
	fcc -Nclang -fopenmp -Nlibomp -o $@ $<

test:: test-core, test-omp

test-core::
	. ${HOME}/.mck_test_config && export MCK_DIR && python C1439.py 1-4,30-33,56-61

test-omp:: show-omp-cpu-affinity
	./test-affinity.sh

clean::
	rm show-omp-cpu-affinity

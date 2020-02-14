#define _GNU_SOURCE

#include <stdio.h>
#include <sched.h>
#include <omp.h>

int main() {
#pragma omp parallel
    {
        int thread_num = omp_get_thread_num();
        int cpu_num = sched_getcpu();
        printf("Thread %d CPU %d\n", thread_num, cpu_num);
    }

    return 0;
}


#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sched.h>

#define UTI_FLAG_NUMA_SET (1ULL<<1) /* Indicates NUMA_SET is specified */

#define UTI_FLAG_SAME_NUMA_DOMAIN (1ULL<<2)
#define UTI_FLAG_DIFFERENT_NUMA_DOMAIN (1ULL<<3)

#define UTI_FLAG_SAME_L1 (1ULL<<4)
#define UTI_FLAG_SAME_L2 (1ULL<<5)
#define UTI_FLAG_SAME_L3 (1ULL<<6)

#define UTI_FLAG_DIFFERENT_L1 (1ULL<<7)
#define UTI_FLAG_DIFFERENT_L2 (1ULL<<8)
#define UTI_FLAG_DIFFERENT_L3 (1ULL<<9)

#define UTI_FLAG_EXCLUSIVE_CPU (1ULL<<10)
#define UTI_FLAG_CPU_INTENSIVE (1ULL<<11)
#define UTI_FLAG_HIGH_PRIORITY (1ULL<<12)
#define UTI_FLAG_NON_COOPERATIVE (1ULL<<13)

/* Linux default value is used */
#define UTI_MAX_NUMA_DOMAINS (1024)

typedef struct uti_attr {
        /* UTI_CPU_SET environmental variable is used to denote the preferred
           location of utility thread */
        uint64_t numa_set[(UTI_MAX_NUMA_DOMAINS + sizeof(uint64_t) * 8 - 1) /
                          (sizeof(uint64_t) * 8)];
        uint64_t flags; /* Representing location and behavior hints by bitmap */
} uti_attr_t;

void
print_sched()
{
	cpu_set_t cpuset;
	int sched;

	sched_getaffinity(0, sizeof cpuset, &cpuset);
	sched = sched_getscheduler(0);
	fprintf(stderr, "\tsched cpu=%16lx sched=%d\n", *(long *)&cpuset, sched);
}

void *
util_thread(void *arg)
{
	print_sched();
	return NULL;
}

void
thread_test(uti_attr_t *attr, char *msg)
{
	pthread_t thr;
	int rc;

	fprintf(stderr, "%s\n", msg);
	rc = syscall(731, 1, attr);
	if (rc) {
		fprintf(stderr, "util_indicate_clone rc=%d, errno=%d\n", rc, errno);
		fflush(stderr);
	}
	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if(rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	pthread_join(thr, NULL);
}

int
main(int argc, char **argv)
{
	uti_attr_t attr;

	memset(&attr, '\0', sizeof attr);
	attr.numa_set[0] = 2; // NUMA domain == 1
	attr.flags = UTI_FLAG_NUMA_SET;
	thread_test(&attr, "CT08001 UTI_FLAG_NUMA_SET");

	memset(&attr, '\0', sizeof attr);
	attr.numa_set[0] = 2;
	attr.flags = UTI_FLAG_NUMA_SET | UTI_FLAG_EXCLUSIVE_CPU;
	thread_test(&attr, "CT08002 UTI_FLAG_NUMA_SET|UTI_FLAG_EXCLUSIVE_CPU");

	memset(&attr, '\0', sizeof attr);
	attr.numa_set[0] = 2;
	attr.flags = UTI_FLAG_NUMA_SET | UTI_FLAG_EXCLUSIVE_CPU;
	thread_test(&attr, "CT08003 UTI_FLAG_NUMA_SET|UTI_FLAG_EXCLUSIVE_CPU(2)");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_SAME_NUMA_DOMAIN;
	thread_test(&attr, "CT08004 UTI_FLAG_SAME_NUMA_DOMAIN");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_SAME_NUMA_DOMAIN | UTI_FLAG_CPU_INTENSIVE;
	thread_test(&attr, "CT08005 UTI_FLAG_SAME_NUMA_DOMAIN|UTI_FLAG_CPU_INTENSIVE");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_DIFFERENT_NUMA_DOMAIN;
	thread_test(&attr, "CT08006 UTI_FLAG_DIFFERENT_NUMA_DOMAIN");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_DIFFERENT_NUMA_DOMAIN | UTI_FLAG_HIGH_PRIORITY;
	thread_test(&attr, "CT08007 UTI_FLAG_DIFFERENT_NUMA_DOMAIN|UTI_FLAG_HIGH_PRIORITY");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_SAME_L1;
	thread_test(&attr, "CT08008 UTI_FLAG_SAME_L1");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_SAME_L1 | UTI_FLAG_NON_COOPERATIVE;
	thread_test(&attr, "CT08009 UTI_FLAG_SAME_L1|UTI_FLAG_NON_COOPERATIVE");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_SAME_L2;
	thread_test(&attr, "CT08010 UTI_FLAG_SAME_L2");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_SAME_L2 | UTI_FLAG_CPU_INTENSIVE;
	thread_test(&attr, "CT08011 UTI_FLAG_SAME_L2|UTI_FLAG_CPU_INTENSIVE");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_SAME_L3;
	thread_test(&attr, "CT08012 UTI_FLAG_SAME_L3");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_SAME_L3 | UTI_FLAG_CPU_INTENSIVE;
	thread_test(&attr, "CT08013 UTI_FLAG_SAME_L3|UTI_FLAG_CPU_INTENSIVE");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_DIFFERENT_L1;
	thread_test(&attr, "CT08014 UTI_FLAG_DIFFERENT_L1");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_DIFFERENT_L1 | UTI_FLAG_CPU_INTENSIVE;
	thread_test(&attr, "CT08015 UTI_FLAG_DIFFERENT_L1|UTI_FLAG_CPU_INTENSIVE");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_DIFFERENT_L2;
	thread_test(&attr, "CT08016 UTI_FLAG_DIFFERENT_L2");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_DIFFERENT_L2 | UTI_FLAG_CPU_INTENSIVE;
	thread_test(&attr, "CT08017 UTI_FLAG_DIFFERENT_L2|UTI_FLAG_CPU_INTENSIVE");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_DIFFERENT_L3;
	thread_test(&attr, "CT08018 UTI_FLAG_DIFFERENT_L3");

	memset(&attr, '\0', sizeof attr);
	attr.flags = UTI_FLAG_DIFFERENT_L3 | UTI_FLAG_CPU_INTENSIVE;
	thread_test(&attr, "CT08019 UTI_FLAG_DIFFERENT_L3|UTI_FLAG_CPU_INTENSIVE");

	exit(0);
}

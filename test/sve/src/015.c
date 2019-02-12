/* 015.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
/* Context switch in the same core check and SIGSTOP -> SIGCONT restart check.(need run on background '&') */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <arm_neon.h>
#include <sys/types.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include "common.h"

static sem_t *sync_sem1 = NULL;
static sem_t *sync_sem2 = NULL;
static int *parent_core = NULL;
static int *sync_flag = NULL;
#define CHILD_DONE 1
#define PARENT_DONE 2

static int *child_count = NULL;

static void child_func(unsigned int vq)
{
	const unsigned int cmp_reg = vq * 2;
	uint64_t a[cmp_reg] ,b[cmp_reg];
	int i = 0;
	pid_t pid = getpid();

	printf("[child] pid = %d\n",pid);

	for (i = 0; i < cmp_reg; i++) {
		a[i] = pid + i;
	}

	asm volatile(
			".cpu cortex-a53+fp+simd+sve\n\t"
			"ldr z31, [%0]\n\t"
			:
			:"r"(a)
			:
	);

	for(;;) {
		asm volatile(
				"add z31.d, z31.d,#1\n\t"
				"str z31, [%0]\n\t"
				:
				:"r"(b)
				:
		);

		for (i = 0; i < cmp_reg; i++) {
			a[i] = a[i] +  1;
			if (a[i] != b[i]) {
				printf("[child] sve failed.a[%d]=%lu,b[%d]=%lu\n",i, a[i], i, b[i]);
				*child_count = -1;
				return;
			}
		}
		*sync_flag = CHILD_DONE;
		while(*sync_flag != PARENT_DONE) {
			cpu_pause();
		}
		(*child_count)++;
		cpu_pause();
	}
}

static void parent_func(void)
{
	uint32x4_t vec_a,vec_b,vec_result;
	uint32_t data1[4] __attribute__((aligned(128))),data2[4] __attribute__((aligned(128)))={1,2,3,4};
	pid_t pid;
	int i = 0;

	pid = getpid();
	printf("[parent] pid = %d\n",pid);

	data1[0] = pid + 1;
	data1[1] = pid + 2;
	data1[2] = pid + 3;
	data1[3] = pid + 4;
	vec_a = vld1q_u32(data1);
	vec_b = vld1q_u32(data2);

	for (;;) {
		*sync_flag = PARENT_DONE;
		while(*sync_flag != CHILD_DONE) {
			cpu_pause();
		}

		vec_result = vec_a - vec_b;

		if ( (vgetq_lane_u32(vec_result,0) != pid)
			|| (vgetq_lane_u32(vec_result,1) != pid)
			|| (vgetq_lane_u32(vec_result,2) != pid)
			|| (vgetq_lane_u32(vec_result,3) != pid)) {
				printf("error\n");
				return;
		} else {
			printf("[parent] loop ok. (%d)\n", i);
			if (*child_count != -1) {
				printf("[child] loop ok. (%d)\n", *child_count);
			} else {
				return;
			}
		}
		i++;
		cpu_pause();
	}
}

TEST_FUNC(TEST_NUMBER, unused1, vq, unused3, unused4)
{
	pid_t pid = 0;

	print_test_overview(tp_num);

	/* get shared memory */
	sync_sem1 = (sem_t *)mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	sync_sem2 = (sem_t *)mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	parent_core = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	sync_flag = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	child_count = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	*parent_core = 0;
	*sync_flag = 0;
	*child_count = 0;

	/* semaphore init */
	sem_init(sync_sem1, 1, 0);
	sem_init(sync_sem2, 1, 0);

	/* create child process */
	pid = fork();

	switch (pid) {
	case -1:
		/* fork() error. */
		perror("fork()");
		return -1;
		break;
	case 0: {
		/* child process */
		/* before migrate, get cpunum */
		int old_mycore = sched_getcpu();
		int new_mycore = -1;

		printf("[child] running core %d\n", old_mycore);

		/* sync parent */
		sem_post(sync_sem1);

		/* sync parent */
		sem_wait(sync_sem2);

		/* after migrate, get cpunum */
		new_mycore = sched_getcpu();

		/* corenum check. */
		if (*parent_core != old_mycore) {
			printf("[child] before migrate prevcore %d, nowcore %d\n", old_mycore, new_mycore);

			if (old_mycore == new_mycore) {
				printf("TP failed, not migrate child process.\n");
				exit(-1);
			}
		} else {
			printf("[child] migrate not required.\n");
		}

		/* loop */
		child_func(vq);

		/* unmap */
		munmap(sync_sem1, sizeof(sem_t));
		munmap(sync_sem2, sizeof(sem_t));
		munmap(parent_core, sizeof(int));
		munmap(sync_flag, sizeof(int));
		munmap(child_count, sizeof(int));

		/* child exit */
		exit(-1);
		break;
	}

	default: {
		/* parent process */
		cpu_set_t cpuset;
		int result = -1;

		/* sync child */
		sem_wait(sync_sem1);

		/* parent corenum get */
		*parent_core = sched_getcpu();

		/* child process to migrate parent core */
		printf("[parent] running core %d\n", *parent_core);
		printf("[parent] child process migrate/bind to core %d\n", *parent_core);

		CPU_ZERO(&cpuset);
		CPU_SET(*parent_core, &cpuset);

		result = sched_setaffinity(pid, sizeof(cpuset), &cpuset);
		if (result == -1) {
			printf("errno = %d\n", errno);
			break;
		}

		/* parent core bind */
		printf("[parent] parent process bind to core %d\n", *parent_core);
		result = sched_setaffinity(0, sizeof(cpuset), &cpuset);
		if (result == -1) {
			printf("errno = %d\n", errno);
			break;
		}

		/* sync child */
		sem_post(sync_sem2);

		/* loop */
		parent_func();

		/* unmap */
		munmap(sync_sem1, sizeof(sem_t));
		munmap(sync_sem2, sizeof(sem_t));
		munmap(parent_core, sizeof(int));
		munmap(sync_flag, sizeof(int));
		munmap(child_count, sizeof(int));
		break;
	}
	}

	/* never return */
	printf("RESULT: NG.\n");
	return 0;
}

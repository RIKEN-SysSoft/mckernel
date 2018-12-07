/* 006.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include "test_mck.h"
#include "testsuite.h"

#define TARGET_PAGE_SIZE (1ULL << 25) /* (1ULL << 21) */ /* 2 MiB */
#define NUM_PAGES 1

/* Aligned range in .data */
char addr_data[TARGET_PAGE_SIZE * NUM_PAGES]
	__attribute__((aligned(TARGET_PAGE_SIZE))) = { 1 }; 

/* Aligned range in .bss */
char addr_bss[TARGET_PAGE_SIZE * NUM_PAGES]
	__attribute__((aligned(TARGET_PAGE_SIZE))); 

char **argv_copy;

SETUP_FUNC(TEST_SUITE, TEST_NUMBER)
{
	argv_copy = tc_argv;
	return NULL;
}

RUN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	int ret;
	struct memory_info info = {0};

	char addr_stack[TARGET_PAGE_SIZE * NUM_PAGES]
		__attribute__((aligned(TARGET_PAGE_SIZE))); 

        key_t key;
        int shmid;
        struct shmid_ds shmid_ds;
	char *addr_mmap;
	char *addr_shmat;

	/* mmap without flag */
	addr_mmap = mmap(0, TARGET_PAGE_SIZE * NUM_PAGES,
			    PROT_READ | PROT_WRITE,
			    MAP_ANONYMOUS | MAP_PRIVATE,
			    -1, 0);
	tp_assert(addr_mmap != (void *)-1, "mmap failed");

	addr_mmap[0] = 'z';
	get_memory_info_self((unsigned long)addr_mmap, &info);
	printf("anonymous mmap: present=%ld,pgsize=%lx\n", info.present, info.pgsize);
#if 0
	tp_assert(info.present == 1, "PTE not present.");
	tp_assert(info.pgsize == TARGET_PAGE_SIZE,
		  "unexpected PTE page size");
#endif

	/* shmat without flag */
	key = ftok(argv_copy[0], 0);

	shmid = shmget(key, TARGET_PAGE_SIZE * NUM_PAGES, IPC_CREAT | 0660);
	tp_assert(shmid != -1, "shmget failed");

	addr_shmat = shmat(shmid, NULL, 0);
	tp_assert(addr_shmat != (void *)-1, "shmat failed");

	addr_shmat[0] = 'z';
	get_memory_info_self((unsigned long)addr_data, &info);
	printf("shmat: present=%ld,pgsize=%lx\n", info.present, info.pgsize);
#if 0
	tp_assert(info.present == 1, "PTE not present.");
	tp_assert(info.pgsize == TARGET_PAGE_SIZE,
		  "unexpected PTE page size");
#endif

	ret = shmctl(shmid, IPC_RMID, &shmid_ds);
	tp_assert(ret != -1, "shmctl failed");

	ret = shmdt(addr_shmat);
	tp_assert(ret != -1, "shmdt failed");

	/* .data */
	addr_data[0] = 'z';
	get_memory_info_self((unsigned long)addr_data, &info);
	printf(".data: present=%ld,pgsize=%lx\n", info.present, info.pgsize);
#if 0
	tp_assert(info.present == 1, "PTE not present.");
	tp_assert(info.pgsize == TARGET_PAGE_SIZE,
		  "unexpected PTE page size");
#endif

	/* .bss */
	addr_bss[0] = 'z';
	get_memory_info_self((unsigned long)addr_bss, &info);
	printf(".bss: present=%ld,pgsize=%lx\n", info.present, info.pgsize);
#if 0
	tp_assert(info.present == 1, "PTE not present.");
	tp_assert(info.pgsize == TARGET_PAGE_SIZE,
		  "unexpected PTE page size");
#endif

	/* stack */
	addr_stack[0] = 'z';
	get_memory_info_self((unsigned long)addr_stack, &info);
	printf("stack: present=%ld,pgsize=%lx\n", info.present, info.pgsize);
#if 0
	tp_assert(info.present == 1, "PTE not present.");
	tp_assert(info.pgsize == TARGET_PAGE_SIZE,
		  "unexpected PTE page size");
#endif

	return NULL;
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
}

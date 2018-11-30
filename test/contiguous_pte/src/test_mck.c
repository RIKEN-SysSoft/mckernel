/* test_mck.c COPYRIGHT FUJITSU LIMITED 2018 */
#include "test_mck.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * test case function declaration
 */
#define TEST_CASE_DEF(ts, number)									\
	void* ts ## number ## _setup(int tp_num, int argc, char** argv);	\
	const char* ts ## number(int tp_num, void* arg);					\
	void ts ## number ## _teardown(int tp_num, void* arg);
#include "test_case.list"
#undef TEST_CASE_DEF

/*
 * test case
 */
struct test_case {
	const char* test_suite;
	int num;
	void* (*setup)(int tp_num, int argc, char** argv);
	const char* (*run)(int tp_num, void* arg);
	void (*teardown)(int tp_num, void* arg);
};

#define TEST_CASE_DEF(ts, number)				\
	{											\
		.test_suite = #ts,						\
		.num = number,					\
		.setup = ts ## number ## _setup,		\
		.run = ts ## number,				    \
		.teardown = ts ## number ## _teardown,	\
	},
const struct test_case test_cases[] = {
#include "test_case.list"
};
#undef TEST_CASE_DEF

char* the_app;

static const char* run_test_case(const struct test_case* tc, int argc, char** argv)
{
	void* args = NULL;
	const char* msg = NULL;

	/* setup */
	args = tc->setup(tc->num, argc, argv);

	/* run */
	msg = tc->run(tc->num, args);

	/* tear_down */
	tc->teardown(tc->num, args);

	/* result */
	return msg;
}

const struct test_case* find_test_case(const char* test_suite, int num)
{
	const struct test_case* ret = NULL;
	int i;

	for (i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++) {
		const struct test_case* tc = test_cases + i;
		if (tc->num == num && strcmp(tc->test_suite, test_suite) == 0) {
			ret = tc;
			break;
		}
	}
	return ret;
}

static void usage(void)
{
	printf("Usage: %s -n test_number [-h] -- [args]\n"
	       "   -n      test case number.\n"
	       "   -h      show this message.\n"
	       "   args    test case arguments.\n",
	       the_app);
}

int main(int argc, char** argv)
{
	const struct test_case* tc;
	const char* result;
	const char* ts = "contiguous_pte";
	int num = INT_MIN;
	int opt;
	int i;

	the_app = argv[0];
	while ((opt = getopt(argc, argv, "n:h")) != -1) {
		switch (opt) {
		case 'n':
			num = atoi(optarg);
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			usage();
			return EXIT_FAILURE;
		}
	}
	argv[optind - 1] = argv[0];
	argv += (optind - 1);
	argc -= (optind - 1);
	optind = 1;

	/* validate */
	if (ts == NULL || num == INT_MIN) {
		usage();
		return EXIT_FAILURE;
	}

	/* find */
	tc = find_test_case(ts, num);
	if (tc == NULL) {
		printf("%s#%d is not found.\n", ts, num);
		return EXIT_FAILURE;
	}

	/* print info */
	printf("TEST_SUITE: %s\n", tc->test_suite);
	printf("TEST_NUMBER: %d\n", tc->num);
	printf("ARGS: ");
	for (i = 1; i < argc; i++) {
		printf("%s ", argv[i]);
	}
	printf("\n");

	/* run */
	result = run_test_case(tc, argc, argv);
	if (result) {
		printf("RESULT: %s\n", result);
		return EXIT_FAILURE;
	}
	printf("RESULT: ok\n");
	return EXIT_SUCCESS;
}

#define PM_ENTRY_BYTES      sizeof(unsigned long)
#define PM_STATUS_BITS      3
#define PM_STATUS_OFFSET    (64 - PM_STATUS_BITS)
#define PM_STATUS_MASK      (((1LL << PM_STATUS_BITS) - 1) << PM_STATUS_OFFSET)
#define PM_STATUS(nr)       (((nr) << PM_STATUS_OFFSET) & PM_STATUS_MASK)
#define PM_PSHIFT_BITS      6
#define PM_PSHIFT_OFFSET    (PM_STATUS_OFFSET - PM_PSHIFT_BITS)
#define PM_PSHIFT_MASK      (((1LL << PM_PSHIFT_BITS) - 1) << PM_PSHIFT_OFFSET)
#define PM_PSHIFT(x)        (((uint64_t) (x) << PM_PSHIFT_OFFSET) & PM_PSHIFT_MASK)
#define PM_PFRAME_MASK      ((1LL << PM_PSHIFT_OFFSET) - 1)
#define PM_PFRAME(x)        ((x) & PM_PFRAME_MASK)
#define PM_PRESENT          PM_STATUS(4LL)
#define PM_SWAP             PM_STATUS(2LL)
static int __get_memory_info(const char* path, unsigned long virt, struct memory_info* info)
{
	int ret = 0;
	int fd = -1;
	unsigned long pagemap = 0;
	off_t offset = 0;

	if (info == NULL) {
		ret = -EINVAL;
		goto out;
	}
	memset(info, 0, sizeof(*info));

	/* open */
	if ((fd = open(path, O_RDONLY)) == -1) {
		printf("%s open() failed. %d\n", path, errno);
		ret = -EIO;
		goto out;
	}

	/* calc offset */
	offset = virt & PAGE_MASK;
	offset /= PAGE_SIZE;
	offset *= PM_ENTRY_BYTES;

	/* lseek */
	if ((lseek(fd, offset, SEEK_SET)) == -1) {
		printf("%s lseek() failed. %d\n", path, errno);
		ret = -EIO;
		goto out_close;
	}

	/* read */
	if ((read(fd, &pagemap, sizeof(pagemap))) == -1) {
		printf("%s offset:%lx read() failed. %d\n", path, offset, errno);
		ret = -EIO;
		goto out_close;
	}

	info->phys = ((pagemap & PM_PFRAME_MASK) << PAGE_SHIFT) | (virt & PAGE_OFFSET);
	info->pgsize = 1UL << ((pagemap & PM_PSHIFT_MASK) >> PM_PSHIFT_OFFSET);
	info->present = !!(pagemap & PM_PRESENT);
	info->swap = !!(pagemap & PM_SWAP);
out_close:
	if (fd != -1) {
		close(fd);
	}
out:
	return ret;
}

int get_memory_info_self(unsigned long virt, struct memory_info* info)
{
	const char* path = "/proc/self/pagemap";
	return __get_memory_info(path, virt, info);
}

int get_memory_info(pid_t pid, unsigned long virt, struct memory_info* info)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/pagemap", pid);
	return __get_memory_info(path, virt, info);
}

int check_page_size(unsigned long va, unsigned long pagesize)
{
	struct memory_info info;
	int stat;

	stat = get_memory_info_self(va, &info);
	if (stat != 0) {
		printf("get memory info failed.\n");
		return 0;
	}
	if (info.pgsize != pagesize) {
		printf("pagesize = 0x%lx, Not as expected.\n", info.pgsize);
		return 0;
	}
	return 1;
}

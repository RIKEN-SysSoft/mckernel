/* test_mck.h COPYRIGHT FUJITSU LIMITED 2018 */
#ifndef __TEST_MCK_H__
#define __TEST_MCK_H__

#include <stdio.h>
#include <sys/types.h>
#include "arch_test_mck.h"

extern char *the_app;

/* test case interface */
#define SETUP_NAME(ts, num)    ts ## num ## _setup

#define RUN_NAME(ts, num)      ts ## num

#define TEARDOWN_NAME(ts, num) ts ## num ## _teardown

#define SETUP_FUNC(ts, num) \
	void *SETUP_NAME(ts, num)(int tc_num, int tc_argc, char **tc_argv)

#define RUN_FUNC(ts, num) \
	const char *RUN_NAME(ts, num)(int tc_num, void *tc_arg)

#define TEARDOWN_FUNC(ts, num) \
	void TEARDOWN_NAME(ts, num)(int tc_num, void *tc_arg)

#define SETUP_EMPTY(ts, num)    SETUP_FUNC(ts, num) {return NULL; }

#define RUN_EMPTY(ts, num)      RUN_FUNC(ts, num) { return NULL; }

#define TEARDOWN_EMPTY(ts, num) TEARDOWN_FUNC(ts, num) { }

/* util */
#define tp_assert(test, msg) \
	_tp_assert(TEST_SUITE, TEST_NUMBER, \
		   __LINE__, test, msg)

#define _tp_assert(ts, num, line, test, msg) \
	__tp_assert(ts, num, line, test, msg)

#define __tp_assert(ts, num, line, test, msg)	\
	do {					\
		if (!(test))			\
			return (msg);		\
	} while (0)

#define align_down(addr, size)  ((addr)&(~((size)-1)))
#define align_up(addr, size)    align_down((addr) + (size) - 1, size)

#define UNUSED_VARIABLE(v)  (void)(v)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

/* memory */
#define PAGE_SIZE    (1UL << PAGE_SHIFT)
#define PAGE_OFFSET  (PAGE_SIZE - 1UL)
#define PAGE_MASK    (~PAGE_OFFSET)

#define CONT_PAGE_SIZE    (1UL << CONT_PAGE_SHIFT)
#define CONT_PAGE_OFFSET  (CONT_PAGE_SIZE - 1UL)
#define CONT_PAGE_MASK    (~CONT_PAGE_OFFSET)

#define LARGE_PAGE_SIZE    (1UL << LARGE_PAGE_SHIFT)
#define LARGE_PAGE_OFFSET  (LARGE_PAGE_SIZE - 1UL)
#define LARGE_PAGE_MASK    (~LARGE_PAGE_OFFSET)

#define CONT_LARGE_PAGE_SIZE    (1UL << CONT_LARGE_PAGE_SHIFT)
#define CONT_LARGE_PAGE_OFFSET  (CONT_LARGE_PAGE_SIZE - 1UL)
#define CONT_LARGE_PAGE_MASK    (~CONT_LARGE_PAGE_OFFSET)

#define LARGEST_PAGE_SIZE    (1UL << LARGEST_PAGE_SHIFT)
#define LARGEST_PAGE_OFFSET  (LARGEST_PAGE_SIZE - 1UL)
#define LARGEST_PAGE_MASK    (~LARGEST_PAGE_OFFSET)

#define CONT_LARGEST_PAGE_SIZE    (1UL << CONT_LARGEST_PAGE_SHIFT)
#define CONT_LARGEST_PAGE_OFFSET  (CONT_LARGEST_PAGE_SIZE - 1UL)
#define CONT_LARGEST_PAGE_MASK    (~CONT_LARGEST_PAGE_OFFSET)

#define PAGE_ALIGN(addr)         align_up(addr, PAGE_SIZE)
#define LARGE_PAGE_ALIGN(addr)   align_up(addr, LARGE_PAGE_SIZE)
#define LARGEST_PAGE_ALIGN(addr) align_up(addr, LARGEST_PAGE_SIZE)

#define CONT_PAGE_ALIGN(addr)         align_up(addr, CONT_PAGE_SIZE)
#define CONT_LARGE_PAGE_ALIGN(addr)   align_up(addr, CONT_LARGE_PAGE_SIZE)
#define CONT_LARGEST_PAGE_ALIGN(addr) align_up(addr, CONT_LARGEST_PAGE_SIZE)

/* procfs */
struct memory_info {
	unsigned long phys;
	unsigned long pgsize;
	unsigned long present;
	unsigned long swap;
};
int get_memory_info_self(unsigned long virt, struct memory_info *info);
int get_memory_info(pid_t pid,
		    unsigned long virt,
		    struct memory_info *info);
int check_page_size(unsigned long va, unsigned long pagesize);

#endif /*__TEST_MCK_H__*/

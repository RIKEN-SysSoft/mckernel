/* common.h COPYRIGHT FUJITSU LIMITED 2017-2019 */
#ifndef __COMMON_H__
#define __COMMON_H__

#include "sve.h"

/* for migrate CPU */
#define SMP_MAX_CPUS 512

/* test */
#define TEST_NAME(num)		test_##num
#define TEST_ARG(arg)		arg
#define TEST_UI_ARG(arg)	unsigned int TEST_ARG(arg)
#define TEST_I_ARG(arg)		int TEST_ARG(arg)
#define TEST_CHAR_PP_ARG(arg)	char **TEST_ARG(arg)
#define TEST_FUNC(num, arg1, arg2, arg3, arg4)	\
	int TEST_NAME(num)(int tp_num, TEST_UI_ARG(arg1), TEST_UI_ARG(arg2), TEST_I_ARG(arg3), TEST_CHAR_PP_ARG(arg4))

extern char *usage_messages[];

#define cpu_pause()						\
	({							\
		__asm__ __volatile__("yield" ::: "memory");	\
	})

/* instruction code */
#define NOP_INST	0xd503201fUL
#define BRK_INST	0xd4200000UL

extern int wait_child_stop(pid_t cpid);
extern int wait_child_exit(pid_t cpid);
extern int rewrite_brk_inst(pid_t cpid, void *inst_addr);
extern void print_test_overview(int tp_num);

#endif /* !__COMMON_H__ */

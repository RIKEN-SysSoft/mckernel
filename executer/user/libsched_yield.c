#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/time.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#undef sched_yield

typedef int (*int_void_fn)(void);

#if 0
static int_void_fn orig_sched_yield = 0;
#endif

int sched_yield(void)
{
#if 0
	if (!orig_sched_yield) {
		orig_sched_yield = (int_void_fn)dlsym(RTLD_NEXT, "sched_yield");
	}

	printf("sched_yield() called\n");
#endif

	return 0;
}

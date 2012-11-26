#include <types.h>
#include <kmsg.h>
#include <aal/cpu.h>
#include <cpulocal.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <aal/ikc.h>
#include <errno.h>
#include <cls.h>
#include <syscall.h>
#include <page.h>
#include <amemcpy.h>
#include <uio.h>
#include <aal/lock.h>
#include <ctype.h>
#include <waitq.h>
#include <rlimit.h>
#include <affinity.h>
#include <time.h>

#define TIMER_CPU_ID	227

struct timer {
	uint64_t timeout;
	struct waitq processes;
	struct list_head list;
	struct process *proc;
};

uint64_t schedule_timeout(uint64_t timeout);

void init_timers(void);
void wake_timers_loop(void);


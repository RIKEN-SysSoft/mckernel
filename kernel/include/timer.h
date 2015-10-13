/**
 * \file timer.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Structure and functions of timer
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <cpulocal.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <errno.h>
#include <cls.h>
#include <syscall.h>
#include <page.h>
#include <amemcpy.h>
#include <uio.h>
#include <ihk/lock.h>
#include <ctype.h>
#include <waitq.h>
#include <rlimit.h>
#include <affinity.h>
#include <time.h>

//#define TIMER_CPU_ID	227

struct timer {
	uint64_t timeout;
	struct waitq processes;
	struct list_head list;
	struct thread *thread;
};

uint64_t schedule_timeout(uint64_t timeout);

void init_timers(void);
void wake_timers_loop(void);


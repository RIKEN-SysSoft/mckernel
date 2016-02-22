/**
 * \file time.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Format of time variables
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

/* 
 * time.h:
 *
 * excerpted from the cross-compiler's header folder 
 */

#ifndef __TIME_H
#define __TIME_H

#define NS_PER_SEC	1000000000UL
#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3

typedef long int __time_t;

/* POSIX.1b structure for a time value.  This is like a `struct timeval' but
   has nanoseconds instead of microseconds.  */
struct timespec
  {
    __time_t tv_sec;		/* Seconds.  */
    long int tv_nsec;		/* Nanoseconds.  */
  };


/* A time value that is accurate to the nearest
   microsecond but also has a range of years.  */
struct timeval
  {
    __time_t tv_sec;		/* Seconds.  */
    long tv_usec;			/* Microseconds.  */
  };


/* Structure crudely representing a timezone.
   This is obsolete and should never be used.  */
struct timezone
  {
    int tz_minuteswest;		/* Minutes west of GMT.  */
    int tz_dsttime;		/* Nonzero if DST is ever in effect.  */
  };

#define ITIMER_REAL	0
#define ITIMER_VIRTUAL	1
#define ITIMER_PROF	2

struct itimerval {
	struct timeval it_interval;
	struct timeval it_value;
};

static inline void
ts_add(struct timespec *ats, const struct timespec *bts)
{
	ats->tv_sec += bts->tv_sec;
	ats->tv_nsec += bts->tv_nsec;
	while(ats->tv_nsec >= 1000000000){
		ats->tv_sec++;
		ats->tv_nsec -= 1000000000;
	}
}

static inline void
ts_sub(struct timespec *ats, const struct timespec *bts)
{
	ats->tv_sec -= bts->tv_sec;
	ats->tv_nsec -= bts->tv_nsec;
	while(ats->tv_nsec < 0){
		ats->tv_sec--;
		ats->tv_nsec += 1000000000;
	}
}

static inline void
tv_add(struct timeval *ats, const struct timeval *bts)
{
	ats->tv_sec += bts->tv_sec;
	ats->tv_usec += bts->tv_usec;
	while(ats->tv_usec >= 1000000){
		ats->tv_sec++;
		ats->tv_usec -= 1000000;
	}
}

static inline void
tv_sub(struct timeval *ats, const struct timeval *bts)
{
	ats->tv_sec -= bts->tv_sec;
	ats->tv_usec -= bts->tv_usec;
	while(ats->tv_usec < 0){
		ats->tv_sec--;
		ats->tv_usec += 1000000;
	}
}

static inline void
tv_to_ts(struct timespec *ats, const struct timeval *bts)
{
	ats->tv_sec = bts->tv_sec;
	ats->tv_nsec = bts->tv_usec * 1000;
}

static inline void
ts_to_tv(struct timeval *ats, const struct timespec *bts)
{
	ats->tv_sec = bts->tv_sec;
	ats->tv_usec = bts->tv_nsec / 1000;
}

#endif // __TIME_H


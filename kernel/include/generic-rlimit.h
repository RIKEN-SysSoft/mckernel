/**
 * \file rlimit.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Kinds of resource limit
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __GENERIC_RLIMIT_H
#define __GENERIC_RLIMIT_H

typedef uint64_t rlim_t;

struct rlimit {
	rlim_t rlim_cur;  /* Soft limit */
	rlim_t rlim_max;  /* Hard limit (ceiling for rlim_cur) */
};

#endif

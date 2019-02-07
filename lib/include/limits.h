/**
 * \file limits.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Define max and min of 32-bit integer.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __HEADER_LIMITS
#define __HEADER_LIMITS

#define INT_MAX 0x7fffffff
#define INT_MIN -0x80000000
#define UINT_MAX 0xffffffff
#define LONG_MAX 0x7fffffffffffffffL
#define LONG_MIN -0x8000000000000000L
#define ULONG_MAX 0xffffffffffffffffL
#define IOV_MAX 1024

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#endif

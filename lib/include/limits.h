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

#define USHRT_MAX	((uint16_t)(~0U))
#define SHRT_MAX	((int16_t)(USHRT_MAX>>1))
#define SHRT_MIN	((int16_t)(-SHRT_MAX - 1))
#define INT_MAX		((int)(~0U>>1))
#define INT_MIN		(-INT_MAX - 1)
#define UINT_MAX	(~0U)
#define LONG_MAX	((long)(~0UL>>1))
#define LONG_MIN	(-LONG_MAX - 1)
#define ULONG_MAX	(~0UL)
#define LLONG_MAX	((long long)(~0ULL>>1))
#define LLONG_MIN	(-LLONG_MAX - 1)
#define ULLONG_MAX	(~0ULL)
#define SIZE_MAX	(~(size_t)0)
typedef uint64_t phys_addr_t;
#define PHYS_ADDR_MAX	(~(phys_addr_t)0)

#define U8_MAX		((uint8_t)~0U)
#define S8_MAX		((int8_t)(U8_MAX>>1))
#define S8_MIN		((int8_t)(-S8_MAX - 1))
#define U16_MAX		((uint16_t)~0U)
#define S16_MAX		((int16_t)(U16_MAX>>1))
#define S16_MIN		((int16_t)(-S16_MAX - 1))
#define U32_MAX		((uint32_t)~0U)
#define S32_MAX		((int32_t)(U32_MAX>>1))
#define S32_MIN		((int32_t)(-S32_MAX - 1))
#define U64_MAX		((uint64_t)~0ULL)
#define S64_MAX		((int64_t)(U64_MAX>>1))
#define S64_MIN		((int64_t)(-S64_MAX - 1))

#define IOV_MAX 1024

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#endif

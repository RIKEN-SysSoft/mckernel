/* types.h COPYRIGHT FUJITSU LIMITED 2018 */
/**
 * \file types.h
 *  Licence details are found in the file LICENSE.
 * \brief
 *  typedef stdint.h like integer types
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef X86_COMMON_TYPES_H
#define X86_COMMON_TYPES_H

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef signed char        int8_t;
typedef signed short       int16_t;
typedef signed int         int32_t;
typedef signed long long   int64_t;

typedef int64_t            ptrdiff_t;
typedef int64_t            intptr_t;
typedef uint64_t           uintptr_t;
typedef uint64_t           size_t;
typedef int64_t            ssize_t;
typedef int64_t            off_t;

#ifdef POSTK_DEBUG_ARCH_DEP_18 /* coredump arch separation. */
typedef int32_t            key_t;
typedef uint32_t           uid_t;
typedef uint32_t           gid_t;
typedef int64_t            time_t;
typedef int32_t            pid_t;
#endif /* POSTK_DEBUG_ARCH_DEP_18 */

#define NULL ((void *)0)

#endif


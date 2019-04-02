/**
 * \file types.h
 *  License details are found in the file LICENSE.
 * \brief
 *  typedef stdint.h like integer types
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */
/* types.h COPYRIGHT FUJITSU LIMITED 2015-2016 */

#ifndef TYPES_H
#define TYPES_H

#define BITS_PER_BYTE	8
#define BITS_PER_LONG	(sizeof(long) * BITS_PER_BYTE)

#ifndef __ASSEMBLY__
typedef _Bool bool;
#endif // __ASSEMBLY__

#include <ihk/types.h>

#endif

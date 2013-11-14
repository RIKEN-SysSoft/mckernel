/**
 * \file lock.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare functions implementing spin lock.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __HEADER_GENERIC_IHK_LOCK
#define __HEADER_GENERIC_IHK_LOCK

#include <arch-lock.h>

#ifndef IHK_STATIC_SPINLOCK_FUNCS
void ihk_mc_spinlock_init(ihk_spinlock_t *);
void ihk_mc_spinlock_lock(ihk_spinlock_t *, unsigned long *);
void ihk_mc_spinlock_unlock(ihk_spinlock_t *, unsigned long *);
#endif

#endif


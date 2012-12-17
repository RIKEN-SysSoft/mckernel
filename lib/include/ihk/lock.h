#ifndef __HEADER_GENERIC_IHK_LOCK
#define __HEADER_GENERIC_IHK_LOCK

#include <arch-lock.h>

#ifndef IHK_STATIC_SPINLOCK_FUNCS
void ihk_mc_spinlock_init(ihk_spinlock_t *);
void ihk_mc_spinlock_lock(ihk_spinlock_t *, unsigned long *);
void ihk_mc_spinlock_unlock(ihk_spinlock_t *, unsigned long *);
#endif

#endif


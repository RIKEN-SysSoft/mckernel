#ifndef __HEADER_GENERIC_AAL_LOCK
#define __HEADER_GENERIC_AAL_LOCK

#include <arch-lock.h>

#ifndef AAL_STATIC_SPINLOCK_FUNCS
void aal_mc_spinlock_init(aal_spinlock_t *);
void aal_mc_spinlock_lock(aal_spinlock_t *, unsigned long *);
void aal_mc_spinlock_unlock(aal_spinlock_t *, unsigned long *);
#endif

#endif


/*
 * kref.h - library routines for handling generic reference counted objects
 * (based on Linux implementation)
 *
 * This file is released under the GPLv2.
 *
 */

#ifndef _KREF_H_
#define _KREF_H_

#include <ihk/atomic.h>
#include <ihk/lock.h>

/*
 * Bit 30 marks a kref as McKernel internal.
 * This can be used to distinguish krefs from Linux and
 * it also ensures that a non deallocated kref will not
 * crash the Linux allocator.
 */
#define MCKERNEL_KREF_MARK	(1U << 30)

struct kref {
	ihk_atomic_t		refcount;
};

#define KREF_INIT(n)	{ .refcount = IHK_ATOMIC_INIT(MCKERNEL_KREF_MARK + n), }

/**
 * kref_init - initialize object.
 * @kref: object in question.
 */
static inline void kref_init(struct kref *kref)
{
	ihk_atomic_set(&kref->refcount, MCKERNEL_KREF_MARK + 1);
}

static inline unsigned int kref_read(const struct kref *kref)
{
	return (ihk_atomic_read(&kref->refcount) & ~(MCKERNEL_KREF_MARK));
}

static inline unsigned int kref_is_mckernel(const struct kref *kref)
{
	return (ihk_atomic_read(&kref->refcount) & (MCKERNEL_KREF_MARK));
}

/**
 * kref_get - increment refcount for object.
 * @kref: object.
 */
static inline void kref_get(struct kref *kref)
{
	ihk_atomic_inc(&kref->refcount);
}

/**
 * kref_put - decrement refcount for object.
 * @kref: object.
 * @release: pointer to the function that will clean up the object when the
 *	     last reference to the object is released.
 *	     This pointer is required, and it is not acceptable to pass kfree
 *	     in as this function.  If the caller does pass kfree to this
 *	     function, you will be publicly mocked mercilessly by the kref
 *	     maintainer, and anyone else who happens to notice it.  You have
 *	     been warned.
 *
 * Decrement the refcount, and if 0, call release().
 * Return 1 if the object was removed, otherwise return 0.  Beware, if this
 * function returns 0, you still can not count on the kref from remaining in
 * memory.  Only use the return value if you want to see if the kref is now
 * gone, not present.
 */
static inline int kref_put(struct kref *kref, void (*release)(struct kref *kref))
{
	//if (ihk_atomic_dec_and_test(&kref->refcount)) {
	if (ihk_atomic_sub_return(1, &kref->refcount) == MCKERNEL_KREF_MARK) {
		release(kref);
		return 1;
	}
	return 0;
}

#endif /* _KREF_H_ */

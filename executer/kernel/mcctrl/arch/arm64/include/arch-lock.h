/* This is copy of the necessary part from McKernel, for uti-futex */

/* arch-lock.h COPYRIGHT FUJITSU LIMITED 2015-2018 */
#ifndef __HEADER_ARM64_COMMON_ARCH_LOCK_H
#define __HEADER_ARM64_COMMON_ARCH_LOCK_H

#include <linux/preempt.h>
#include <cpu.h>

#define ihk_mc_spinlock_lock __ihk_mc_spinlock_lock
#define ihk_mc_spinlock_unlock __ihk_mc_spinlock_unlock

#define ihk_mc_spinlock_lock_noirq __ihk_mc_spinlock_lock_noirq
#define ihk_mc_spinlock_unlock_noirq __ihk_mc_spinlock_unlock_noirq

/* @ref.impl arch/arm64/include/asm/spinlock_types.h::TICKET_SHIFT */
#define TICKET_SHIFT	16

/* @ref.impl ./arch/arm64/include/asm/lse.h::ARM64_LSE_ATOMIC_INSN */
/* else defined(CONFIG_AS_LSE) && defined(CONFIG_ARM64_LSE_ATOMICS) */
#define _ARM64_LSE_ATOMIC_INSN(llsc, lse)    llsc

/* @ref.impl arch/arm64/include/asm/spinlock_types.h::arch_spinlock_t */
typedef struct {
#ifdef __AARCH64EB__
	uint16_t next;
	uint16_t owner;
#else /* __AARCH64EB__ */
	uint16_t owner;
	uint16_t next;
#endif /* __AARCH64EB__ */
} __attribute__((aligned(4))) _ihk_spinlock_t;

/* @ref.impl arch/arm64/include/asm/spinlock.h::arch_spin_lock */
/* spinlock lock */
static inline void
__ihk_mc_spinlock_lock_noirq(_ihk_spinlock_t *lock)
{
	unsigned int tmp;
	_ihk_spinlock_t lockval, newval;

	preempt_disable();

	asm volatile(
	/* Atomically increment the next ticket. */
	_ARM64_LSE_ATOMIC_INSN(
	/* LL/SC */
"	prfm	pstl1strm, %3\n"
"1:	ldaxr	%w0, %3\n"
"	add	%w1, %w0, %w5\n"
"	stxr	%w2, %w1, %3\n"
"	cbnz	%w2, 1b\n",
	/* LSE atomics */
"	mov	%w2, %w5\n"
"	ldadda	%w2, %w0, %3\n"
	__nops(3)
	)

	/* Did we get the lock? */
"	eor	%w1, %w0, %w0, ror #16\n"
"	cbz	%w1, 3f\n"
	/*
	 * No: spin on the owner. Send a local event to avoid missing an
	 * unlock before the exclusive load.
	 */
"	sevl\n"
"2:	wfe\n"
"	ldaxrh	%w2, %4\n"
"	eor	%w1, %w2, %w0, lsr #16\n"
"	cbnz	%w1, 2b\n"
	/* We got the lock. Critical section starts here. */
"3:"
	: "=&r" (lockval), "=&r" (newval), "=&r" (tmp), "+Q" (*lock)
	: "Q" (lock->owner), "I" (1 << TICKET_SHIFT)
	: "memory");
}

/* spinlock lock & interrupt disable & PSTATE.DAIF save */
static inline unsigned long
__ihk_mc_spinlock_lock(_ihk_spinlock_t *lock)
{
	unsigned long flags;

	flags = cpu_disable_interrupt_save();

	__ihk_mc_spinlock_lock_noirq(lock);

	return flags;
}

/* @ref.impl arch/arm64/include/asm/spinlock.h::arch_spin_unlock */
/* spinlock unlock */
static inline void
__ihk_mc_spinlock_unlock_noirq(_ihk_spinlock_t *lock)
{
	unsigned long tmp;

	asm volatile(_ARM64_LSE_ATOMIC_INSN(
	/* LL/SC */
	"	ldrh	%w1, %0\n"
	"	add	%w1, %w1, #1\n"
	"	stlrh	%w1, %0",
	/* LSE atomics */
	"	mov	%w1, #1\n"
	"	staddlh	%w1, %0\n"
	__nops(1))
	: "=Q" (lock->owner), "=&r" (tmp)
	:
	: "memory");

	preempt_enable();
}

static inline void
__ihk_mc_spinlock_unlock(_ihk_spinlock_t *lock, unsigned long flags)
{
	__ihk_mc_spinlock_unlock_noirq(lock);

	cpu_restore_interrupt(flags);
}

typedef struct mcs_rwlock_lock {
	_ihk_spinlock_t slock;
#ifndef ENABLE_UBSAN
} __aligned(64) mcs_rwlock_lock_t;
#else
} mcs_rwlock_lock_t;
#endif

static inline void
mcs_rwlock_writer_lock_noirq(struct mcs_rwlock_lock *lock)
{
	ihk_mc_spinlock_lock_noirq(&lock->slock);
}

static inline void
mcs_rwlock_writer_unlock_noirq(struct mcs_rwlock_lock *lock)
{
	ihk_mc_spinlock_unlock_noirq(&lock->slock);
}

#endif /* !__HEADER_ARM64_COMMON_ARCH_LOCK_H */

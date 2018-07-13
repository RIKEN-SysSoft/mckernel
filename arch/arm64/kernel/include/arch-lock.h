/* arch-lock.h COPYRIGHT FUJITSU LIMITED 2015-2018 */
#ifndef __HEADER_ARM64_COMMON_ARCH_LOCK_H
#define __HEADER_ARM64_COMMON_ARCH_LOCK_H

#define IHK_STATIC_SPINLOCK_FUNCS

#include <ihk/cpu.h>
#include <ihk/atomic.h>
#include "affinity.h"
#include <lwk/compiler.h>
#include "config.h"

//#define DEBUG_SPINLOCK
//#define DEBUG_MCS_RWLOCK

#if defined(DEBUG_SPINLOCK) || defined(DEBUG_MCS_RWLOCK)
int __kprintf(const char *format, ...);
#endif

/* @ref.impl arch/arm64/include/asm/spinlock_types.h::TICKET_SHIFT */
#define TICKET_SHIFT	16

/* @ref.impl arch/arm64/include/asm/spinlock_types.h::arch_spinlock_t */
typedef struct {
#ifdef __AARCH64EB__
	uint16_t next;
	uint16_t owner;
#else /* __AARCH64EB__ */
	uint16_t owner;
	uint16_t next;
#endif /* __AARCH64EB__ */
} __attribute__((aligned(4))) ihk_spinlock_t;

extern void preempt_enable(void);
extern void preempt_disable(void);

/* @ref.impl arch/arm64/include/asm/spinlock_types.h::__ARCH_SPIN_LOCK_UNLOCKED */
#define SPIN_LOCK_UNLOCKED	{ 0, 0 }

/* @ref.impl arch/arm64/include/asm/barrier.h::__nops */
#define __nops(n)	".rept	" #n "\nnop\n.endr\n"

/* @ref.impl ./arch/arm64/include/asm/lse.h::ARM64_LSE_ATOMIC_INSN */
/* else defined(CONFIG_AS_LSE) && defined(CONFIG_ARM64_LSE_ATOMICS) */
#define ARM64_LSE_ATOMIC_INSN(llsc, lse)	llsc

/* initialized spinlock struct */
static void ihk_mc_spinlock_init(ihk_spinlock_t *lock)
{
	*lock = (ihk_spinlock_t)SPIN_LOCK_UNLOCKED;
}

#ifdef DEBUG_SPINLOCK
#define ihk_mc_spinlock_trylock_noirq(l) { \
	int rc; \
	__kprintf("[%d] call ihk_mc_spinlock_trylock_noirq %p %s:%d\n", \
		  ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
	rc = __ihk_mc_spinlock_trylock_noirq(l); \
	__kprintf("[%d] ret ihk_mc_spinlock_trylock_noirq\n", \
		  ihk_mc_get_processor_id()); \
	rc; \
}
#else
#define ihk_mc_spinlock_trylock_noirq __ihk_mc_spinlock_trylock_noirq
#endif

/* @ref.impl arch/arm64/include/asm/spinlock.h::arch_spin_trylock */
/* spinlock trylock */
static int __ihk_mc_spinlock_trylock_noirq(ihk_spinlock_t *lock)
{
	unsigned int tmp;
	ihk_spinlock_t lockval;
	int success;

	preempt_disable();

	asm volatile(ARM64_LSE_ATOMIC_INSN(
	/* LL/SC */
	"	prfm	pstl1strm, %2\n"
	"1:	ldaxr	%w0, %2\n"
	"	eor	%w1, %w0, %w0, ror #16\n"
	"	cbnz	%w1, 2f\n"
	"	add	%w0, %w0, %3\n"
	"	stxr	%w1, %w0, %2\n"
	"	cbnz	%w1, 1b\n"
	"2:",
	/* LSE atomics */
	"	ldr	%w0, %2\n"
	"	eor	%w1, %w0, %w0, ror #16\n"
	"	cbnz	%w1, 1f\n"
	"	add	%w1, %w0, %3\n"
	"	casa	%w0, %w1, %2\n"
	"	sub	%w1, %w1, %3\n"
	"	eor	%w1, %w1, %w0\n"
	"1:")
	: "=&r" (lockval), "=&r" (tmp), "+Q" (*lock)
	: "I" (1 << TICKET_SHIFT)
	: "memory");

	success = !tmp;
	if (!success) {
		preempt_enable();
	}
	return success;
}

#ifdef DEBUG_SPINLOCK
#define ihk_mc_spinlock_trylock(l, result) ({ \
	unsigned long rc; \
	__kprintf("[%d] call ihk_mc_spinlock_trylock %p %s:%d\n", \
		  ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
	rc = __ihk_mc_spinlock_trylock(l, result); \
	__kprintf("[%d] ret ihk_mc_spinlock_trylock\n", \
		  ihk_mc_get_processor_id()); \
	rc; \
})
#else
#define ihk_mc_spinlock_trylock __ihk_mc_spinlock_trylock
#endif

/* spinlock trylock & interrupt disable & PSTATE.DAIF save */
static unsigned long __ihk_mc_spinlock_trylock(ihk_spinlock_t *lock,
					       int *result)
{
	unsigned long flags;

	flags = cpu_disable_interrupt_save();

	*result = __ihk_mc_spinlock_trylock_noirq(lock);

	return flags;
}

#ifdef DEBUG_SPINLOCK
#define ihk_mc_spinlock_lock_noirq(l) { \
__kprintf("[%d] call ihk_mc_spinlock_lock_noirq %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__ihk_mc_spinlock_lock_noirq(l); \
__kprintf("[%d] ret ihk_mc_spinlock_lock_noirq\n", ihk_mc_get_processor_id()); \
}
#else
#define ihk_mc_spinlock_lock_noirq __ihk_mc_spinlock_lock_noirq
#endif

/* @ref.impl arch/arm64/include/asm/spinlock.h::arch_spin_lock */
/* spinlock lock */
static void __ihk_mc_spinlock_lock_noirq(ihk_spinlock_t *lock)
{
	unsigned int tmp;
	ihk_spinlock_t lockval, newval;

	preempt_disable();

	asm volatile(
	/* Atomically increment the next ticket. */
	ARM64_LSE_ATOMIC_INSN(
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

#ifdef DEBUG_SPINLOCK
#define ihk_mc_spinlock_lock(l) ({ unsigned long rc;\
__kprintf("[%d] call ihk_mc_spinlock_lock %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
rc = __ihk_mc_spinlock_lock(l);\
__kprintf("[%d] ret ihk_mc_spinlock_lock\n", ihk_mc_get_processor_id()); rc;\
})
#else
#define ihk_mc_spinlock_lock __ihk_mc_spinlock_lock
#endif

/* spinlock lock & interrupt disable & PSTATE.DAIF save */
static unsigned long __ihk_mc_spinlock_lock(ihk_spinlock_t *lock)
{
	unsigned long flags;
	
	flags = cpu_disable_interrupt_save();

	__ihk_mc_spinlock_lock_noirq(lock);

	return flags;
}

#ifdef DEBUG_SPINLOCK
#define ihk_mc_spinlock_unlock_noirq(l) { \
__kprintf("[%d] call ihk_mc_spinlock_unlock_noirq %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__ihk_mc_spinlock_unlock_noirq(l); \
__kprintf("[%d] ret ihk_mc_spinlock_unlock_noirq\n", ihk_mc_get_processor_id()); \
}
#else
#define ihk_mc_spinlock_unlock_noirq __ihk_mc_spinlock_unlock_noirq
#endif

/* @ref.impl arch/arm64/include/asm/spinlock.h::arch_spin_unlock */
/* spinlock unlock */
static void __ihk_mc_spinlock_unlock_noirq(ihk_spinlock_t *lock)
{
	unsigned long tmp;

	asm volatile(ARM64_LSE_ATOMIC_INSN(
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

/* spinlock unlock & restore PSTATE.DAIF */
#ifdef DEBUG_SPINLOCK
#define ihk_mc_spinlock_unlock(l, f) { \
__kprintf("[%d] call ihk_mc_spinlock_unlock %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__ihk_mc_spinlock_unlock((l), (f)); \
__kprintf("[%d] ret ihk_mc_spinlock_unlock\n", ihk_mc_get_processor_id()); \
}
#else
#define ihk_mc_spinlock_unlock __ihk_mc_spinlock_unlock
#endif
static void __ihk_mc_spinlock_unlock(ihk_spinlock_t *lock, unsigned long flags)
{
	__ihk_mc_spinlock_unlock_noirq(lock);

	cpu_restore_interrupt(flags);
}

/* An implementation of the Mellor-Crummey Scott (MCS) lock */
typedef struct mcs_lock_node {
	unsigned long locked;
	struct mcs_lock_node *next;
	unsigned long irqsave;
#ifndef ENABLE_UBSAN
} __aligned(64) mcs_lock_node_t;
#else
} mcs_lock_node_t;
#endif

typedef mcs_lock_node_t mcs_lock_t;

static void mcs_lock_init(struct mcs_lock_node *node)
{
	node->locked = 0;
	node->next = NULL;
}

static void __mcs_lock_lock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	struct mcs_lock_node *pred;

	node->next = NULL;
	node->locked = 0;
	pred = xchg8(&(lock->next), node);

	if (pred) {
		node->locked = 1;
		pred->next = node;
		while (node->locked != 0) {
			cpu_pause();
		}
	}
}

static void __mcs_lock_unlock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	if (node->next == NULL) {
		struct mcs_lock_node *old = atomic_cmpxchg8(&(lock->next), node, 0);

		if (old == node) {
			return;
		}

		while (node->next == NULL) {
			cpu_pause();
		}
	}

	node->next->locked = 0;
}

static void mcs_lock_lock_noirq(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	preempt_disable();
	__mcs_lock_lock(lock, node);
}

static void mcs_lock_unlock_noirq(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	__mcs_lock_unlock(lock, node);
	preempt_enable();
}

static void mcs_lock_lock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	node->irqsave = cpu_disable_interrupt_save();
	mcs_lock_lock_noirq(lock, node);
}

static void mcs_lock_unlock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	mcs_lock_unlock_noirq(lock, node);
	cpu_restore_interrupt(node->irqsave);
}


#define SPINLOCK_IN_MCS_RWLOCK

// reader/writer lock
typedef struct mcs_rwlock_node {
	ihk_atomic_t count;	// num of readers (use only common reader)
	char type;		// lock type
#define MCS_RWLOCK_TYPE_COMMON_READER 0
#define MCS_RWLOCK_TYPE_READER 1
#define MCS_RWLOCK_TYPE_WRITER 2
	char locked;		// lock
#define MCS_RWLOCK_LOCKED	1
#define MCS_RWLOCK_UNLOCKED	0
	char dmy1;		// unused
	char dmy2;		// unused
	struct mcs_rwlock_node *next;
#ifndef ENABLE_UBSAN
} __aligned(64) mcs_rwlock_node_t;
#else
} mcs_rwlock_node_t;
#endif

typedef struct mcs_rwlock_node_irqsave {
#ifndef SPINLOCK_IN_MCS_RWLOCK
	struct mcs_rwlock_node node;
#endif
	unsigned long irqsave;
#ifndef ENABLE_UBSAN
} __aligned(64) mcs_rwlock_node_irqsave_t;
#else
} mcs_rwlock_node_irqsave_t;
#endif

typedef struct mcs_rwlock_lock {
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_spinlock_t slock;
#else
	struct mcs_rwlock_node reader;		/* common reader lock */
	struct mcs_rwlock_node *node;		/* base */
#endif
#ifndef ENABLE_UBSAN
} __aligned(64) mcs_rwlock_lock_t;
#else
} mcs_rwlock_lock_t;
#endif

static void
mcs_rwlock_init(struct mcs_rwlock_lock *lock)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_init(&lock->slock);
#else
	ihk_atomic_set(&lock->reader.count, 0);
	lock->reader.type = MCS_RWLOCK_TYPE_COMMON_READER;
	lock->node = NULL;
#endif
}

#ifdef DEBUG_MCS_RWLOCK
#define mcs_rwlock_writer_lock_noirq(l, n) { \
__kprintf("[%d] call mcs_rwlock_writer_lock_noirq %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__mcs_rwlock_writer_lock_noirq((l), (n)); \
__kprintf("[%d] ret mcs_rwlock_writer_lock_noirq\n", ihk_mc_get_processor_id()); \
}
#else
#define mcs_rwlock_writer_lock_noirq __mcs_rwlock_writer_lock_noirq
#endif
static void
__mcs_rwlock_writer_lock_noirq(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_lock_noirq(&lock->slock);
#else
	struct mcs_rwlock_node *pred;

	preempt_disable();

	node->type = MCS_RWLOCK_TYPE_WRITER;
	node->next = NULL;

	pred = xchg8(&(lock->node), node);

	if (pred) {
		node->locked = MCS_RWLOCK_LOCKED;
		pred->next = node;
		while (node->locked != MCS_RWLOCK_UNLOCKED) {
			cpu_pause();
		}
	}
#endif
}

#ifndef SPINLOCK_IN_MCS_RWLOCK
static void
mcs_rwlock_unlock_readers(struct mcs_rwlock_lock *lock)
{
	struct mcs_rwlock_node *p;
	struct mcs_rwlock_node *f = NULL;
	struct mcs_rwlock_node *n;
	int breakf = 0;

	ihk_atomic_inc(&lock->reader.count); // protect to unlock reader
	for(p = &lock->reader; p->next; p = n){
		n = p->next;
		if(p->next->type == MCS_RWLOCK_TYPE_READER){
			p->next = n->next;
			if(lock->node == n){
				struct mcs_rwlock_node *old;

				old = atomic_cmpxchg8(&(lock->node), n, p);

				if(old != n){ // couldn't change
					while (n->next == NULL) {
						cpu_pause();
					}
					p->next = n->next;
				}
				else{
					breakf = 1;
				}
			}
			else if(p->next == NULL){
				while (n->next == NULL) {
					cpu_pause();
				}
				p->next = n->next;
			}
			if(f){
				ihk_atomic_inc(&lock->reader.count);
				n->locked = MCS_RWLOCK_UNLOCKED;
			}
			else
				f = n;
			n = p;
			if(breakf)
				break;
		}
		if(n->next == NULL && lock->node != n){
			while (n->next == NULL && lock->node != n) {
				cpu_pause();
			}
		}
	}

	f->locked = MCS_RWLOCK_UNLOCKED;
}
#endif

#ifdef DEBUG_MCS_RWLOCK
#define mcs_rwlock_writer_unlock_noirq(l, n) { \
__kprintf("[%d] call mcs_rwlock_writer_unlock_noirq %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__mcs_rwlock_writer_unlock_noirq((l), (n)); \
__kprintf("[%d] ret mcs_rwlock_writer_unlock_noirq\n", ihk_mc_get_processor_id()); \
}
#else
#define mcs_rwlock_writer_unlock_noirq __mcs_rwlock_writer_unlock_noirq
#endif
static void
__mcs_rwlock_writer_unlock_noirq(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_unlock_noirq(&lock->slock);
#else
	if (node->next == NULL) {
		struct mcs_rwlock_node *old = atomic_cmpxchg8(&(lock->node), node, 0);

		if (old == node) {
			goto out;
		}

		while (node->next == NULL) {
			cpu_pause();
		}
	}

	if(node->next->type == MCS_RWLOCK_TYPE_READER){
		lock->reader.next = node->next;
		mcs_rwlock_unlock_readers(lock);
	}
	else{
		node->next->locked = MCS_RWLOCK_UNLOCKED;
	}

out:
	preempt_enable();
#endif
}

#ifdef DEBUG_MCS_RWLOCK
#define mcs_rwlock_reader_lock_noirq(l, n) { \
__kprintf("[%d] call mcs_rwlock_reader_lock_noirq %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__mcs_rwlock_reader_lock_noirq((l), (n)); \
__kprintf("[%d] ret mcs_rwlock_reader_lock_noirq\n", ihk_mc_get_processor_id()); \
}
#else
#define mcs_rwlock_reader_lock_noirq __mcs_rwlock_reader_lock_noirq
#endif

static inline unsigned int
atomic_inc_ifnot0(ihk_atomic_t *v)
{
	unsigned int *p = (unsigned int *)(&(v)->counter);
	unsigned int old;
	unsigned int new;
	unsigned int val;

	do{
		if(!(old = *p))
			break;
		new = old + 1;
		val = atomic_cmpxchg4(p, old, new);
	}while(val != old);
	return old;
}

static void
__mcs_rwlock_reader_lock_noirq(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_lock_noirq(&lock->slock);
#else
	struct mcs_rwlock_node *pred;

	preempt_disable();

	node->type = MCS_RWLOCK_TYPE_READER;
	node->next = NULL;
	node->dmy1 = ihk_mc_get_processor_id();

	pred = xchg8(&(lock->node), node);

	if (pred) {
		if(pred == &lock->reader){
			if(atomic_inc_ifnot0(&pred->count)){
				struct mcs_rwlock_node *old;

				old = atomic_cmpxchg8(&(lock->node), node, pred);

				if (old == node) {
					goto out;
				}

				while (node->next == NULL) {
					cpu_pause();
				}

				node->locked = MCS_RWLOCK_LOCKED;
				lock->reader.next = node;
				mcs_rwlock_unlock_readers(lock);
				ihk_atomic_dec(&pred->count);
				goto out;
			}
		}
		node->locked = MCS_RWLOCK_LOCKED;
		pred->next = node;
		while (node->locked != MCS_RWLOCK_UNLOCKED) {
			cpu_pause();
		}
	}
	else {
		lock->reader.next = node;
		mcs_rwlock_unlock_readers(lock);
	}
out:
	return;
#endif
}

#ifdef DEBUG_MCS_RWLOCK
#define mcs_rwlock_reader_unlock_noirq(l, n) { \
__kprintf("[%d] call mcs_rwlock_reader_unlock_noirq %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__mcs_rwlock_reader_unlock_noirq((l), (n)); \
__kprintf("[%d] ret mcs_rwlock_reader_unlock_noirq\n", ihk_mc_get_processor_id()); \
}
#else
#define mcs_rwlock_reader_unlock_noirq __mcs_rwlock_reader_unlock_noirq
#endif
static void
__mcs_rwlock_reader_unlock_noirq(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_unlock_noirq(&lock->slock);
#else
	if(ihk_atomic_dec_return(&lock->reader.count))
		goto out;

	if (lock->reader.next == NULL) {
		struct mcs_rwlock_node *old;

		old = atomic_cmpxchg8(&(lock->node), &(lock->reader), 0);

		if (old == &lock->reader) {
			goto out;
		}

		while (lock->reader.next == NULL) {
			cpu_pause();
		}
	}

	if(lock->reader.next->type == MCS_RWLOCK_TYPE_READER){
		mcs_rwlock_unlock_readers(lock);
	}
	else{
		lock->reader.next->locked = MCS_RWLOCK_UNLOCKED;
	}

out:
	preempt_enable();
#endif
}

#ifdef DEBUG_MCS_RWLOCK
#define mcs_rwlock_writer_lock(l, n) { \
__kprintf("[%d] call mcs_rwlock_writer_lock %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__mcs_rwlock_writer_lock((l), (n)); \
__kprintf("[%d] ret mcs_rwlock_writer_lock\n", ihk_mc_get_processor_id()); \
}
#else
#define mcs_rwlock_writer_lock __mcs_rwlock_writer_lock
#endif
static void
__mcs_rwlock_writer_lock(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node_irqsave *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	node->irqsave = ihk_mc_spinlock_lock(&lock->slock);
#else
	node->irqsave = cpu_disable_interrupt_save();
	__mcs_rwlock_writer_lock_noirq(lock, &node->node);
#endif
}

#ifdef DEBUG_MCS_RWLOCK
#define mcs_rwlock_writer_unlock(l, n) { \
__kprintf("[%d] call mcs_rwlock_writer_unlock %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__mcs_rwlock_writer_unlock((l), (n)); \
__kprintf("[%d] ret mcs_rwlock_writer_unlock\n", ihk_mc_get_processor_id()); \
}
#else
#define mcs_rwlock_writer_unlock __mcs_rwlock_writer_unlock
#endif
static void
__mcs_rwlock_writer_unlock(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node_irqsave *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_unlock(&lock->slock, node->irqsave);
#else
	__mcs_rwlock_writer_unlock_noirq(lock, &node->node);
	cpu_restore_interrupt(node->irqsave);
#endif
}

#ifdef DEBUG_MCS_RWLOCK
#define mcs_rwlock_reader_lock(l, n) { \
__kprintf("[%d] call mcs_rwlock_reader_lock %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__mcs_rwlock_reader_lock((l), (n)); \
__kprintf("[%d] ret mcs_rwlock_reader_lock\n", ihk_mc_get_processor_id()); \
}
#else
#define mcs_rwlock_reader_lock __mcs_rwlock_reader_lock
#endif
static void
__mcs_rwlock_reader_lock(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node_irqsave *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	node->irqsave = ihk_mc_spinlock_lock(&lock->slock);
#else
	node->irqsave = cpu_disable_interrupt_save();
	__mcs_rwlock_reader_lock_noirq(lock, &node->node);
#endif
}

#ifdef DEBUG_MCS_RWLOCK
#define mcs_rwlock_reader_unlock(l, n) { \
__kprintf("[%d] call mcs_rwlock_reader_unlock %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__mcs_rwlock_reader_unlock((l), (n)); \
__kprintf("[%d] ret mcs_rwlock_reader_unlock\n", ihk_mc_get_processor_id()); \
}
#else
#define mcs_rwlock_reader_unlock __mcs_rwlock_reader_unlock
#endif
static void
__mcs_rwlock_reader_unlock(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node_irqsave *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_unlock(&lock->slock, node->irqsave);
#else
	__mcs_rwlock_reader_unlock_noirq(lock, &node->node);
	cpu_restore_interrupt(node->irqsave);
#endif
}

#if defined(CONFIG_HAS_NMI)
#include <arm-gic-v3.h>
static inline int irqflags_can_interrupt(unsigned long flags)
{
	return (flags == ICC_PMR_EL1_UNMASKED);
}
#else /* CONFIG_HAS_NMI */
static inline int irqflags_can_interrupt(unsigned long flags)
{
	return !(flags & 0x2);
}
#endif /* CONFIG_HAS_NMI */


#endif /* !__HEADER_ARM64_COMMON_ARCH_LOCK_H */

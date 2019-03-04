/*
 * Excerpted from Linux 3.0: arch/x86/include/asm/spinlock.h
 */
#ifndef __HEADER_X86_COMMON_ARCH_LOCK
#define __HEADER_X86_COMMON_ARCH_LOCK

#include <ihk/cpu.h>
#include <ihk/atomic.h>
#include <lwk/compiler.h>
#include "config.h"

//#define DEBUG_SPINLOCK
//#define DEBUG_MCS_RWLOCK

#if defined(DEBUG_SPINLOCK) || defined(DEBUG_MCS_RWLOCK)
int __kprintf(const char *format, ...);
#endif

typedef unsigned short __ticket_t;
typedef unsigned int __ticketpair_t;

typedef struct ihk_spinlock {
	union {
		__ticketpair_t head_tail;
		struct __raw_tickets {
			__ticket_t head, tail;
		} tickets;
	};
} ihk_spinlock_t;

extern void preempt_enable(void);
extern void preempt_disable(void);

#define IHK_STATIC_SPINLOCK_FUNCS

static inline void ihk_mc_spinlock_init(ihk_spinlock_t *lock)
{
	lock->head_tail = 0;
}
#define SPIN_LOCK_UNLOCKED { .head_tail = 0 }


#ifdef DEBUG_SPINLOCK
#define ihk_mc_spinlock_trylock_noirq(l) { int rc;						\
__kprintf("[%d] call ihk_mc_spinlock_trylock_noirq %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
rc = __ihk_mc_spinlock_trylock_noirq(l); \
 __kprintf("[%d] ret ihk_mc_spinlock_trylock_noirq\n", ihk_mc_get_processor_id()); rc; \
}
#else
#define ihk_mc_spinlock_trylock_noirq __ihk_mc_spinlock_trylock_noirq
#endif

static inline int __ihk_mc_spinlock_trylock_noirq(ihk_spinlock_t *lock)
{
	ihk_spinlock_t cur = { .head_tail = lock->head_tail };
	ihk_spinlock_t next = { .tickets.head = cur.tickets.head, .tickets.tail = cur.tickets.tail + 2 };
	int success;

	if (cur.tickets.head != cur.tickets.tail) {
		return 0;
	}

	preempt_disable();

	/* Use the same increment amount as other functions! */
	success = __sync_bool_compare_and_swap((__ticketpair_t*)lock, cur.head_tail, next.head_tail);

	if (!success) {
		preempt_enable();
	}
	return success;
}

#ifdef DEBUG_SPINLOCK
#define ihk_mc_spinlock_trylock(l, result) ({ unsigned long rc;		\
__kprintf("[%d] call ihk_mc_spinlock_trylock %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
 rc = __ihk_mc_spinlock_trylock(l, result);									\
__kprintf("[%d] ret ihk_mc_spinlock_trylock\n", ihk_mc_get_processor_id()); rc;\
})
#else
#define ihk_mc_spinlock_trylock __ihk_mc_spinlock_trylock
#endif
static inline unsigned long __ihk_mc_spinlock_trylock(ihk_spinlock_t *lock,
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

static inline void __ihk_mc_spinlock_lock_noirq(ihk_spinlock_t *lock)
{
	register struct __raw_tickets inc = { .tail = 0x0002 };

	preempt_disable();

	asm volatile ("lock xaddl %0, %1\n"
			: "+r" (inc), "+m" (*(lock)) : : "memory", "cc");

	if (inc.head == inc.tail)
		goto out;

	for (;;) {
		if (*((volatile __ticket_t *)&lock->tickets.head) == inc.tail)
			goto out;
		cpu_pause();
	}

out:
	barrier();	/* make sure nothing creeps before the lock is taken */
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
static inline unsigned long __ihk_mc_spinlock_lock(ihk_spinlock_t *lock)
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
static inline void __ihk_mc_spinlock_unlock_noirq(ihk_spinlock_t *lock)
{
	__ticket_t inc = 0x0002;

	asm volatile ("lock addw %1, %0\n"
			: "+m" (lock->tickets.head) : "ri" (inc) : "memory", "cc");

	preempt_enable();
}

#ifdef DEBUG_SPINLOCK
#define ihk_mc_spinlock_unlock(l, f) { \
__kprintf("[%d] call ihk_mc_spinlock_unlock %p %s:%d\n", ihk_mc_get_processor_id(), (l), __FILE__, __LINE__); \
__ihk_mc_spinlock_unlock((l), (f)); \
__kprintf("[%d] ret ihk_mc_spinlock_unlock\n", ihk_mc_get_processor_id()); \
}
#else
#define ihk_mc_spinlock_unlock __ihk_mc_spinlock_unlock
#endif
static inline void __ihk_mc_spinlock_unlock(ihk_spinlock_t *lock,
					    unsigned long flags)
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

static inline void mcs_lock_init(struct mcs_lock_node *node)
{
	node->locked = 0;
	node->next = NULL;
}

static inline void __mcs_lock_lock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	struct mcs_lock_node *pred;

	node->next = NULL;
	node->locked = 0;
	pred = (struct mcs_lock_node *)xchg8((unsigned long *)&lock->next,
			(unsigned long)node);

	if (pred) {
		node->locked = 1;
		pred->next = node;
		while (node->locked != 0) {
			cpu_pause();
		}
	}
}

static inline void __mcs_lock_unlock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	if (node->next == NULL) {
		struct mcs_lock_node *old = (struct mcs_lock_node *)
			atomic_cmpxchg8((unsigned long *)&lock->next,
					(unsigned long)node, (unsigned long)0);

		if (old == node) {
			return;
		}

		while (node->next == NULL) {
			cpu_pause();
		}
	}

	node->next->locked = 0;
}

static inline void mcs_lock_lock_noirq(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	preempt_disable();
	__mcs_lock_lock(lock, node);
}

static inline void mcs_lock_unlock_noirq(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	__mcs_lock_unlock(lock, node);
	preempt_enable();
}

static inline void mcs_lock_lock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	node->irqsave = cpu_disable_interrupt_save();
	mcs_lock_lock_noirq(lock, node);
}

static inline void mcs_lock_unlock(struct mcs_lock_node *lock,
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

static inline void
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
static inline void
__mcs_rwlock_writer_lock_noirq(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_lock_noirq(&lock->slock);
#else
	struct mcs_rwlock_node *pred;

	preempt_disable();

	node->type = MCS_RWLOCK_TYPE_WRITER;
	node->next = NULL;

	pred = (struct mcs_rwlock_node *)xchg8((unsigned long *)&lock->node,
			(unsigned long)node);

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
static inline void
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

				old = (struct mcs_rwlock_node *)atomic_cmpxchg8(
				       (unsigned long *)&lock->node,
				       (unsigned long)n,
				       (unsigned long)p);

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
static inline void
__mcs_rwlock_writer_unlock_noirq(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_unlock_noirq(&lock->slock);
#else
	if (node->next == NULL) {
		struct mcs_rwlock_node *old = (struct mcs_rwlock_node *)
			atomic_cmpxchg8((unsigned long *)&lock->node,
					(unsigned long)node, (unsigned long)0);

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

static inline void
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

	pred = (struct mcs_rwlock_node *)xchg8((unsigned long *)&lock->node,
			(unsigned long)node);

	if (pred) {
		if(pred == &lock->reader){
			if(atomic_inc_ifnot0(&pred->count)){
				struct mcs_rwlock_node *old;

				old = (struct mcs_rwlock_node *)atomic_cmpxchg8(
				       (unsigned long *)&lock->node,
				       (unsigned long)node,
				       (unsigned long)pred);

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
static inline void
__mcs_rwlock_reader_unlock_noirq(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_unlock_noirq(&lock->slock);
#else
	if(ihk_atomic_dec_return(&lock->reader.count))
		goto out;

	if (lock->reader.next == NULL) {
		struct mcs_rwlock_node *old;

		old = (struct mcs_rwlock_node *)atomic_cmpxchg8(
		       (unsigned long *)&lock->node,
		       (unsigned long)&lock->reader,
		       (unsigned long)0);

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
static inline void
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
static inline void
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
static inline void
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
static inline void
__mcs_rwlock_reader_unlock(struct mcs_rwlock_lock *lock, struct mcs_rwlock_node_irqsave *node)
{
#ifdef SPINLOCK_IN_MCS_RWLOCK
	ihk_mc_spinlock_unlock(&lock->slock, node->irqsave);
#else
	__mcs_rwlock_reader_unlock_noirq(lock, &node->node);
	cpu_restore_interrupt(node->irqsave);
#endif
}

static inline int irqflags_can_interrupt(unsigned long flags)
{
	return !!(flags & 0x200);
}

#endif

/*
 * Excerpted from Linux 3.0: arch/x86/include/asm/spinlock.h
 */
#ifndef __HEADER_X86_COMMON_ARCH_LOCK
#define __HEADER_X86_COMMON_ARCH_LOCK

#include <ihk/cpu.h>
#include <ihk/atomic.h>

//#define DEBUG_SPINLOCK

#ifdef DEBUG_SPINLOCK
int __kprintf(const char *format, ...);
#endif

typedef int ihk_spinlock_t;

extern void preempt_enable(void);
extern void preempt_disable(void);

#define IHK_STATIC_SPINLOCK_FUNCS

static void ihk_mc_spinlock_init(ihk_spinlock_t *lock)
{
	*lock = 0;
}
#define SPIN_LOCK_UNLOCKED 0

static void ihk_mc_spinlock_lock_noirq(ihk_spinlock_t *lock)
{
	int inc = 0x00010000;
	int tmp;

#if 0
	asm volatile("lock ; xaddl %0, %1\n"
	             "movzwl %w0, %2\n\t"
	             "shrl $16, %0\n\t"
	             "1:\t"
	             "cmpl %0, %2\n\t"
	             "je 2f\n\t"
	             "rep ; nop\n\t"
	             "movzwl %1, %2\n\t"
	             "jmp 1b\n"
	             "2:"
	             : "+Q" (inc), "+m" (*lock), "=r" (tmp) : : "memory", "cc");
#endif

#ifdef DEBUG_SPINLOCK
	__kprintf("[%d] trying to grab lock: 0x%lX\n", 
	          ihk_mc_get_processor_id(), lock);
#endif

	preempt_disable();

	asm volatile("lock; xaddl %0, %1\n"
			"movzwl %w0, %2\n\t"
			"shrl $16, %0\n\t"
			"1:\t"
			"cmpl %0, %2\n\t"
			"je 2f\n\t"
			"rep ; nop\n\t"
			"movzwl %1, %2\n\t"
			/* don't need lfence here, because loads are in-order */
			"jmp 1b\n"
			"2:"
			: "+r" (inc), "+m" (*lock), "=&r" (tmp)
			:
			: "memory", "cc");

#ifdef DEBUG_SPINLOCK
	__kprintf("[%d] holding lock: 0x%lX\n", ihk_mc_get_processor_id(), lock);
#endif
}

static unsigned long ihk_mc_spinlock_lock(ihk_spinlock_t *lock)
{
	unsigned long flags;
	
	flags = cpu_disable_interrupt_save();

	ihk_mc_spinlock_lock_noirq(lock);

	return flags;
}

static void ihk_mc_spinlock_unlock_noirq(ihk_spinlock_t *lock)
{
	asm volatile ("lock incw %0" : "+m"(*lock) : : "memory", "cc");
	
	preempt_enable();
}

static void ihk_mc_spinlock_unlock(ihk_spinlock_t *lock, unsigned long flags)
{
	ihk_mc_spinlock_unlock_noirq(lock);

	cpu_restore_interrupt(flags);
#ifdef DEBUG_SPINLOCK
	__kprintf("[%d] released lock: 0x%lX\n", ihk_mc_get_processor_id(), lock);
#endif
}

/* An implementation of the Mellor-Crummey Scott (MCS) lock */
typedef struct mcs_lock_node {
	unsigned long locked;
	struct mcs_lock_node *next;
} __attribute__((aligned(64))) mcs_lock_node_t;

static void mcs_lock_init(struct mcs_lock_node *node)
{
	node->locked = 0;
	node->next = NULL;
}

static void mcs_lock_lock(struct mcs_lock_node *lock,
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

static void mcs_lock_unlock(struct mcs_lock_node *lock,
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

// reader/writer lock
typedef struct rwlock_node {
	ihk_atomic_t count;	// num of readers (use only common reader)
	char type;		// lock type
#define RWLOCK_TYPE_COMMON_READER 0
#define RWLOCK_TYPE_READER 1
#define RWLOCK_TYPE_WRITER 2
	char locked;		// lock
#define RWLOCK_LOCKED	1
#define RWLOCK_UNLOCKED	0
	char dmy1;		// unused
	char dmy2;		// unused
	struct rwlock_node *next;
} __attribute__((aligned(64))) rwlock_node_t;

typedef struct rwlock_node_irqsave {
	struct rwlock_node node;
	unsigned long irqsave;
} __attribute__((aligned(64))) rwlock_node_irqsave_t;

typedef struct rwlock_lock {
	struct rwlock_node reader;		/* common reader lock */
	struct rwlock_node *node;		/* base */
} __attribute__((aligned(64))) rwlock_lock_t;

static void
rwlock_init(struct rwlock_lock *lock)
{
	ihk_atomic_set(&lock->reader.count, 0);
	lock->reader.type = RWLOCK_TYPE_COMMON_READER;
	lock->node = NULL;
}

static void
rwlock_writer_lock_noirq(struct rwlock_lock *lock, struct rwlock_node *node)
{
	struct rwlock_node *pred;

	preempt_disable();

	node->type = RWLOCK_TYPE_WRITER;
	node->next = NULL;

	pred = (struct rwlock_node *)xchg8((unsigned long *)&lock->node,
			(unsigned long)node);

	if (pred) {
		node->locked = RWLOCK_LOCKED;
		pred->next = node;
		while (node->locked != RWLOCK_UNLOCKED) {
			cpu_pause();
		}
	}
}

static void
rwlock_unlock_readers(struct rwlock_lock *lock)
{
	struct rwlock_node *p;
	struct rwlock_node *f = NULL;
	struct rwlock_node *n;

	ihk_atomic_inc(&lock->reader.count); // protect to unlock reader
	for(p = &lock->reader; p->next; p = n){
		n = p->next;
		if(p->next->type == RWLOCK_TYPE_READER){
			p->next = n->next;
			if(lock->node == n){
				struct rwlock_node *old;

				old = (struct rwlock_node *)atomic_cmpxchg8(
				       (unsigned long *)&lock->node,
				       (unsigned long)n,
				       (unsigned long)p);

				if(old != n){ // couldn't change
					while (n->next == NULL) {
						cpu_pause();
					}
					p->next = n->next;
				}
			}
			if(f){
				ihk_atomic_inc(&lock->reader.count);
				n->locked = RWLOCK_UNLOCKED;
			}
			else
				f = n;
			n = p;
		}
		if(n->next == NULL && lock->node != n){
			while (n->next == NULL) {
				cpu_pause();
			}
		}
	}

	f->locked = RWLOCK_UNLOCKED;
}

static void
rwlock_writer_unlock_noirq(struct rwlock_lock *lock, struct rwlock_node *node)
{
	if (node->next == NULL) {
		struct rwlock_node *old = (struct rwlock_node *)
			atomic_cmpxchg8((unsigned long *)&lock->node,
					(unsigned long)node, (unsigned long)0);

		if (old == node) {
			goto out;
		}

		while (node->next == NULL) {
			cpu_pause();
		}
	}

	if(node->next->type == RWLOCK_TYPE_READER){
		lock->reader.next = node->next;
		rwlock_unlock_readers(lock);
	}
	else{
		node->next->locked = RWLOCK_UNLOCKED;
	}

out:
	preempt_enable();
}

static void
rwlock_reader_lock_noirq(struct rwlock_lock *lock, struct rwlock_node *node)
{
	struct rwlock_node *pred;

	preempt_disable();

	node->type = RWLOCK_TYPE_READER;
	node->next = NULL;

	pred = (struct rwlock_node *)xchg8((unsigned long *)&lock->node,
			(unsigned long)node);

	if (pred) {
		if(pred == &lock->reader){
			if(ihk_atomic_inc_return(&pred->count) != 1){
				struct rwlock_node *old;

				old = (struct rwlock_node *)atomic_cmpxchg8(
				       (unsigned long *)&lock->node,
				       (unsigned long)node,
				       (unsigned long)pred);

				if (old == pred) {
					goto out;
				}

				while (node->next == NULL) {
					cpu_pause();
				}

				pred->next = node->next;
				if(node->next->type == RWLOCK_TYPE_READER)
					rwlock_unlock_readers(lock);
				goto out;
			}
			ihk_atomic_dec(&pred->count);
		}
		node->locked = RWLOCK_LOCKED;
		pred->next = node;
		while (node->locked != RWLOCK_UNLOCKED) {
			cpu_pause();
		}
	}
	else {
		lock->reader.next = node;
		rwlock_unlock_readers(lock);
	}
out:
	return;
}

static void
rwlock_reader_unlock_noirq(struct rwlock_lock *lock, struct rwlock_node *node)
{
	if(ihk_atomic_dec_return(&lock->reader.count))
		goto out;

	if (lock->reader.next == NULL) {
		struct rwlock_node *old;

		old = (struct rwlock_node *)atomic_cmpxchg8(
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

	if(lock->reader.next->type == RWLOCK_TYPE_READER){
		rwlock_unlock_readers(lock);
	}
	else{
		lock->reader.next->locked = RWLOCK_UNLOCKED;
	}

out:
	preempt_enable();
}

static void
rwlock_writer_lock(struct rwlock_lock *lock, struct rwlock_node_irqsave *node)
{
	node->irqsave = cpu_disable_interrupt_save();
	rwlock_writer_lock_noirq(lock, &node->node);
}

static void
rwlock_writer_unlock(struct rwlock_lock *lock, struct rwlock_node_irqsave *node)
{
	rwlock_writer_unlock_noirq(lock, &node->node);
	cpu_restore_interrupt(node->irqsave);
}

static void
rwlock_reader_lock(struct rwlock_lock *lock, struct rwlock_node_irqsave *node)
{
	node->irqsave = cpu_disable_interrupt_save();
	rwlock_reader_lock_noirq(lock, &node->node);
}

static void
rwlock_reader_unlock(struct rwlock_lock *lock, struct rwlock_node_irqsave *node)
{
	rwlock_reader_unlock_noirq(lock, &node->node);
	cpu_restore_interrupt(node->irqsave);
}

#endif

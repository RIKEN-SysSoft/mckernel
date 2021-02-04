#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/version.h>
#include <linux/semaphore.h>
#include <linux/interrupt.h>
#include <linux/cpumask.h>
#include <linux/rbtree.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/io.h>
#include <linux/syscalls.h>
#include <trace/events/sched.h>
#include <config.h>
#include "mcctrl.h"
#include <ihk/ihk_host_user.h>
#include <rusage.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <uapi/linux/sched/types.h>
#endif
#include <archdeps.h>
#include <arch-lock.h>
#include <uti.h>

#include <futex.h>
#include <mc_jhash.h>
#include <arch-futex.h>

#ifdef DEBUG
#define dprintk printk
#else
#define dprintk(...)
#endif

#define NS_PER_SEC  1000000000UL

static long uti_wait_event(void *_resp, unsigned long nsec_timeout)
{
	struct uti_futex_resp *resp = _resp;

	if (nsec_timeout) {
		return wait_event_interruptible_timeout(resp->wq, resp->done,
				nsecs_to_jiffies(nsec_timeout));
	} else {
		return wait_event_interruptible(resp->wq, resp->done);
	}
}

static int uti_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	int ret = 0;
	struct timespec64 ts64;

	dprintk("%s: clk_id=%x,REALTIME=%x,MONOTONIC=%x\n", __func__,
			clk_id, CLOCK_REALTIME, CLOCK_MONOTONIC);
	switch (clk_id) {
	case CLOCK_REALTIME:
		getnstimeofday64(&ts64);
		tp->tv_sec = ts64.tv_sec;
		tp->tv_nsec = ts64.tv_nsec;
		dprintk("%s: CLOCK_REALTIME,%ld.%09ld\n", __func__,
				tp->tv_sec, tp->tv_nsec);
		break;
	case CLOCK_MONOTONIC:
		/* Do not use getrawmonotonic() because it returns different value than clock_gettime() */
		ktime_get_ts64(&ts64);
		tp->tv_sec = ts64.tv_sec;
		tp->tv_nsec = ts64.tv_nsec;
		dprintk("%s: CLOCK_MONOTONIC,%ld.%09ld\n", __func__,
				tp->tv_sec, tp->tv_nsec);
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}
/*
 * Hash buckets are shared by all the futex_keys that hash to the same
 * location.  Each key may have multiple futex_q structures, one for each task
 * waiting on a futex.
 */
struct futex_hash_bucket {
	_ihk_spinlock_t lock;
	struct mc_plist_head chain;
};

/*
 * Take a reference to the resource addressed by a key.
 * Can be called while holding spinlocks.
 *
 */
static void get_futex_key_refs(union futex_key *key)
{
	/* RIKEN: no swapping in McKernel */
	return;
}

/*
 * Drop a reference to the resource addressed by a key.
 * The hash bucket spinlock must not be held.
 */
static void drop_futex_key_refs(union futex_key *key)
{
	/* RIKEN: no swapping in McKernel */
	return;
}

static inline
void put_futex_key(int fshared, union futex_key *key)
{
	drop_futex_key_refs(key);
}

/*
 * We hash on the keys returned from get_futex_key (see below).
 */
static struct futex_hash_bucket *hash_futex(
		union futex_key *key,
		struct futex_hash_bucket *futex_queue)
{
	uint32_t hash = mc_jhash2((uint32_t *)&key->both.word,
			  (sizeof(key->both.word)+sizeof(key->both.ptr))/4,
			  key->both.offset);
	return &futex_queue[hash & ((1 << FUTEX_HASHBITS)-1)];
}

/* The key must be already stored in q->key. */
static inline struct futex_hash_bucket *queue_lock(
		struct futex_q *q,
		struct futex_hash_bucket *futex_queue)
{
	struct futex_hash_bucket *hb;

	get_futex_key_refs(&q->key);
	hb = hash_futex(&q->key, futex_queue);
	q->lock_ptr = &hb->lock;

	ihk_mc_spinlock_lock_noirq(&hb->lock);

	return hb;
}

static inline void
queue_unlock(struct futex_q *q, struct futex_hash_bucket *hb)
{
	ihk_mc_spinlock_unlock_noirq(&hb->lock);
	drop_futex_key_refs(&q->key);
}

/*
 * Express the locking dependencies for lockdep:
 */
static inline void
double_lock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
{
	if (hb1 <= hb2) {
		ihk_mc_spinlock_lock_noirq(&hb1->lock);
		if (hb1 < hb2)
			ihk_mc_spinlock_lock_noirq(&hb2->lock);
	} else { /* hb1 > hb2 */
		ihk_mc_spinlock_lock_noirq(&hb2->lock);
		ihk_mc_spinlock_lock_noirq(&hb1->lock);
	}
}

static inline void
double_unlock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
{
	ihk_mc_spinlock_unlock_noirq(&hb1->lock);
	if (hb1 != hb2)
		ihk_mc_spinlock_unlock_noirq(&hb2->lock);
}

/* remote_page_fault for uti-futex */
static int uti_remote_page_fault(struct mcctrl_usrdata *usrdata,
			void *fault_addr, uint64_t reason,
			struct mcctrl_per_proc_data *ppd, int tid, int cpu)
{
	int error;
	struct mcctrl_wakeup_desc *desc;
	int do_frees = 1;
	struct ikc_scd_packet packet;

	/* Request page fault */
	packet.msg = SCD_MSG_REMOTE_PAGE_FAULT;
	packet.fault_address = (unsigned long)fault_addr;
	packet.fault_reason = reason;
	packet.fault_tid = tid;

	/* we need to alloc desc ourselves because GFP_ATOMIC */
retry_alloc:
	desc = kmalloc(sizeof(*desc), GFP_ATOMIC);
	if (!desc) {
		pr_warn("WARNING: coudln't alloc remote page fault wait desc, retrying..\n");
		goto retry_alloc;
	}

	/* packet->target_cpu was set in rus_vm_fault if a thread was found */
	error = mcctrl_ikc_send_wait(usrdata->os, cpu, &packet,
				     0, desc, &do_frees, 0);
	if (do_frees) {
		kfree(desc);
	}
	if (error < 0) {
		pr_warn("%s: WARNING: failed to request uti remote page fault :%d\n",
			__func__, error);
	}

	return error;
}

struct rva_to_rpa_cache_node {
	struct rb_node node;
	unsigned long rva;
	unsigned long rpa;
};

void futex_remove_process(struct mcctrl_per_proc_data *ppd)
{
	struct rb_node *node;

	while ((node = rb_first(&ppd->rva_to_rpa_cache))) {
		struct rva_to_rpa_cache_node *cache_node;

		cache_node = container_of(node, struct rva_to_rpa_cache_node,
					  node);
		rb_erase(node, &ppd->rva_to_rpa_cache);
		kfree(cache_node);
	}
}

struct rva_to_rpa_cache_node *rva_to_rpa_cache_search(struct rb_root *root,
						      unsigned long rva)
{
	struct rb_node **iter = &root->rb_node, *parent = NULL;

	while (*iter) {
		struct rva_to_rpa_cache_node *inode =
			container_of(*iter, struct rva_to_rpa_cache_node, node);

		parent = *iter;

		if (rva == inode->rva) {
			return inode;
		}

		if (rva < inode->rva)
			iter = &((*iter)->rb_left);
		else
			iter = &((*iter)->rb_right);
	}

	return NULL;
}

int rva_to_rpa_cache_insert(struct rb_root *root,
			    struct rva_to_rpa_cache_node *cache_node)
{
	struct rb_node **iter = &root->rb_node, *parent = NULL;

	while (*iter) {
		struct rva_to_rpa_cache_node *inode =
			container_of(*iter, struct rva_to_rpa_cache_node, node);

		parent = *iter;

		if (cache_node->rva == inode->rva)
			return -EINVAL;

		if (cache_node->rva < inode->rva)
			iter = &((*iter)->rb_left);
		else
			iter = &((*iter)->rb_right);
	}

	rb_link_node(&cache_node->node, parent, iter);
	rb_insert_color(&cache_node->node, root);

	return 0;
}

/**
 * get_futex_key() - Get parameters which are the keys for a futex
 * @uaddr:	virtual address of the futex
 * @fshared:	0 for a PROCESS_PRIVATE futex, 1 for PROCESS_SHARED
 * @key:	address where result is stored.
 *
 * Returns a negative error code or 0
 * The key words are stored in *key on success.
 *
 * For shared mappings, it's (page->index, vma->vm_file->f_path.dentry->d_inode,
 * offset_within_page).  For private mappings, it's (uaddr, current->mm).
 * We can usually work out the index without swapping in the page.
 *
 * lock_page() might sleep, the caller should not hold a spinlock.
 */
static int
get_futex_key(uint32_t *uaddr, int fshared, union futex_key *key,
		struct uti_info *uti_info)
{
	unsigned long address = (unsigned long)uaddr;
	unsigned long phys, pgsize;
	void *mm = uti_info->vm;
	struct mcctrl_usrdata *usrdata;
	struct mcctrl_per_proc_data *ppd;
	int ret = 0, error = 0;
	struct rva_to_rpa_cache_node *cache_node;

	/*
	 * The futex address must be "naturally" aligned.
	 */
	key->both.offset = address % PAGE_SIZE;
	if (((address % sizeof(uint32_t)) != 0)) {
		ret = -EINVAL;
		goto out;
	}
	address -= key->both.offset;

	/*
	 * PROCESS_PRIVATE futexes are fast.
	 * As the mm cannot disappear under us and the 'key' only needs
	 * virtual address, we dont even have to find the underlying vma.
	 * Note : We do have to check 'uaddr' is a valid user address,
	 *        but access_ok() should be faster than find_vma()
	 */
	if (!fshared) {
		key->private.mm = mm;
		key->private.address = address;
		get_futex_key_refs(key);
		ret = 0;
		goto out;
	}

	key->both.offset |= FUT_OFF_MMSHARED;

	usrdata = ihk_host_os_get_usrdata((ihk_os_t)uti_info->os);
	if (!usrdata) {
		pr_err("%s: ERROR: mcctrl_usrdata not found\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));
	if (!ppd) {
		pr_err("%s: ERROR: no per-process structure for PID %d\n",
				__func__, task_tgid_vnr(current));
		ret = -EINVAL;
		goto out;
	}

	/* cache because translate_rva_to_rpa calls smp_ihk_arch_dcache_flush
	 * via ihk_device_unmap_virtual
	 */
	cache_node = rva_to_rpa_cache_search(&ppd->rva_to_rpa_cache,
					     (unsigned long)uaddr);
	if (cache_node) {
		phys = cache_node->rpa;
		dprintk("%s: cache hit, rva: %lx, rpa: %lx\n",
			__func__, (unsigned long)uaddr, phys);
		goto found;
	}
retry_v2p:
	error = translate_rva_to_rpa((ihk_os_t)uti_info->os, ppd->rpgtable,
			(unsigned long)uaddr, &phys, &pgsize);
	if (error) {
		/* Check if we can fault in page */
		error = uti_remote_page_fault(usrdata, (void *)address,
				PF_POPULATE | PF_WRITE | PF_USER,
				ppd, uti_info->tid, uti_info->cpu);
		if (error) {
			pr_err("%s: ERROR: virt to phys translation failed\n",
					__func__);
			ret = -EFAULT;
			goto put_out;
		}

		goto retry_v2p;
	}

	cache_node = kmalloc(sizeof(struct rva_to_rpa_cache_node), GFP_KERNEL);
	if (!cache_node) {
		ret = -ENOMEM;
		goto put_out;
	}
	cache_node->rva = (unsigned long)uaddr;
	cache_node->rpa = phys;
	dprintk("%s: cache insert, rva: %lx, rpa: %lx\n",
		__func__, (unsigned long)uaddr, phys);
	ret = rva_to_rpa_cache_insert(&ppd->rva_to_rpa_cache, cache_node);
	if (ret) {
		pr_err("%s: error: cache entry found, rva: %lx, rpa: %lx\n",
		       __func__, (unsigned long)uaddr, phys);
		goto put_out;
	}

 found:
	key->shared.phys = (void *)phys;
	key->shared.pgoff = 0;

put_out:
	mcctrl_put_per_proc_data(ppd);

out:
	return ret;
}

/**
 * queue_me() - Enqueue the futex_q on the futex_hash_bucket
 * @q:	The futex_q to enqueue
 * @hb:	The destination hash bucket
 *
 * The hb->lock must be held by the caller, and is released here. A call to
 * queue_me() is typically paired with exactly one call to unqueue_me().  The
 * exceptions involve the PI related operations, which may use unqueue_me_pi()
 * or nothing if the unqueue is done as part of the wake process and the unqueue
 * state is implicit in the state of woken task (see futex_wait_requeue_pi() for
 * an example).
 */
static inline void queue_me(struct futex_q *q, struct futex_hash_bucket *hb,
			struct uti_info *uti_info)
{
	int prio;

	/*
	 * The priority used to register this element is
	 * - either the real thread-priority for the real-time threads
	 * (i.e. threads with a priority lower than MAX_RT_PRIO)
	 * - or MAX_RT_PRIO for non-RT threads.
	 * Thus, all RT-threads are woken first in priority order, and
	 * the others are woken last, in FIFO order.
	 *
	 * RIKEN: no priorities at the moment, everyone is 10.
	 */
	prio = 10;

	mc_plist_node_init(&q->list, prio);
#ifdef CONFIG_DEBUG_PI_LIST
	q->list.plist.spinlock = &hb->lock;
#endif
	mc_plist_add(&q->list, &hb->chain);
	q->task = (void *)uti_info->thread_va;
	ihk_mc_spinlock_unlock_noirq(&hb->lock);
}

/**
 * unqueue_me() - Remove the futex_q from its futex_hash_bucket
 * @q:	The futex_q to unqueue
 *
 * The q->lock_ptr must not be held by the caller. A call to unqueue_me() must
 * be paired with exactly one earlier call to queue_me().
 *
 * Returns:
 *   1 - if the futex_q was still queued (and we removed unqueued it)
 *   0 - if the futex_q was already removed by the waking thread
 */
static int unqueue_me(struct futex_q *q)
{
	_ihk_spinlock_t *lock_ptr;
	int ret = 0;

	/* In the common case we don't take the spinlock, which is nice. */
retry:
	lock_ptr = q->lock_ptr;
	barrier();
	if (lock_ptr != NULL) {
		ihk_mc_spinlock_lock_noirq(lock_ptr);
		/*
		 * q->lock_ptr can change between reading it and
		 * spin_lock(), causing us to take the wrong lock.  This
		 * corrects the race condition.
		 *
		 * Reasoning goes like this: if we have the wrong lock,
		 * q->lock_ptr must have changed (maybe several times)
		 * between reading it and the spin_lock().  It can
		 * change again after the spin_lock() but only if it was
		 * already changed before the spin_lock().  It cannot,
		 * however, change back to the original value.  Therefore
		 * we can detect whether we acquired the correct lock.
		 */
		if (lock_ptr != q->lock_ptr) {
			ihk_mc_spinlock_unlock_noirq(lock_ptr);
			goto retry;
		}
		mc_plist_del(&q->list, &q->list.plist);

		ihk_mc_spinlock_unlock_noirq(lock_ptr);
		ret = 1;
	}

	drop_futex_key_refs(&q->key);
	return ret;
}

/*
 * Return 1 if two futex_keys are equal, 0 otherwise.
 */
static inline int match_futex(union futex_key *key1, union futex_key *key2)
{
	return (key1 && key2
		&& key1->both.word == key2->both.word
		&& key1->both.ptr == key2->both.ptr
		&& key1->both.offset == key2->both.offset);
}

/* Convert phys_addr to virt_addr on Linux */
static void futex_q_p2v(struct futex_q *q)
{
	q->th_spin_sleep = (void *)phys_to_virt(q->th_spin_sleep_pa);
	q->th_status = (void *)phys_to_virt(q->th_status_pa);
	q->th_spin_sleep_lock = (void *)phys_to_virt(q->th_spin_sleep_lock_pa);
	q->proc_status = (void *)phys_to_virt(q->proc_status_pa);
	q->proc_update_lock = (void *)phys_to_virt(q->proc_update_lock_pa);
	q->runq_lock = (void *)phys_to_virt(q->runq_lock_pa);
	q->clv_flags = (void *)phys_to_virt(q->clv_flags_pa);
}

#define CPU_FLAG_NEED_RESCHED	0x1U
#define CPU_FLAG_NEED_MIGRATE	0x2U
#define PS_RUNNING           0x1
#define PS_INTERRUPTIBLE     0x2
#define PS_UNINTERRUPTIBLE   0x4
#define PS_ZOMBIE            0x8
#define PS_EXITED            0x10
#define PS_STOPPED           0x20
#define PS_TRACED            0x40 /* Set to "not running" by a ptrace related event */
#define PS_STOPPING          0x80
#define PS_TRACING           0x100
#define PS_DELAY_STOPPED     0x200
#define PS_DELAY_TRACED      0x400

#define PS_NORMAL	(PS_INTERRUPTIBLE | PS_UNINTERRUPTIBLE)
static int uti_sched_wakeup_thread(struct futex_q *q, int valid_states,
		struct uti_info *uti_info)
{
	int status;
	unsigned long irqstate;

	futex_q_p2v(q);
	irqstate = ihk_mc_spinlock_lock(
			(_ihk_spinlock_t *)q->th_spin_sleep_lock);
	if (*(int *)q->th_spin_sleep == 1) {
		dprintk("%s: spin wakeup: cpu_id: %d\n", __func__, uti_info->cpu);
		status = 0;
	}
	*(int *)q->th_spin_sleep = 0;
	ihk_mc_spinlock_unlock(
			(_ihk_spinlock_t *)q->th_spin_sleep_lock, irqstate);

	irqstate = ihk_mc_spinlock_lock((_ihk_spinlock_t *)q->runq_lock);

	if (*(int *)q->th_status & valid_states) {
		mcs_rwlock_writer_lock_noirq(
			(mcs_rwlock_lock_t *)q->proc_update_lock);

		if (*(int *)q->proc_status != PS_EXITED) {
			*(int *)q->proc_status = PS_RUNNING;
		}

		mcs_rwlock_writer_unlock_noirq((mcs_rwlock_lock_t *)q->proc_update_lock);

		xchg4((int *)q->th_status, PS_RUNNING);
		status = 0;

		/* Make interrupt_exit() call schedule() */
		*(unsigned int *)q->clv_flags |= CPU_FLAG_NEED_RESCHED;
	}
	else {
		status = -EINVAL;
	}

	ihk_mc_spinlock_unlock((_ihk_spinlock_t *)q->runq_lock, irqstate);

	if (!status) {
		dprintk("%s: issuing IPI, thread->cpu_id=%d, intr_id: %d\n",
			__func__, uti_info->cpu, q->intr_id);

		ihk_os_issue_interrupt(uti_info->os, q->intr_id,
				       q->intr_vector);
	}

	return status;
}

/*
 * The hash bucket lock must be held when this is called.
 * Afterwards, the futex_q must not be accessed.
 */
static void wake_futex(struct futex_q *q, struct uti_info *uti_info)
{
	/*
	 * We set q->lock_ptr = NULL _before_ we wake up the task. If
	 * a non futex wake up happens on another CPU then the task
	 * might exit and p would dereference a non existing task
	 * struct. Prevent this by holding a reference on p across the
	 * wake up.
	 */

	mc_plist_del(&q->list, &q->list.plist);
	if (q->uti_futex_resp) {
		/* TODO: Add the case when a Linux thread waking up another Linux thread */
		pr_err("%s: ERROR: A Linux thread is waking up migrated-to-Linux thread\n", __func__);
	} else {
		dprintk("%s: waking up McKernel thread (tid %d)\n",
				__func__, uti_info->tid);
		uti_sched_wakeup_thread(q, PS_NORMAL, uti_info);
	}

	/*
	 * The waiting task can free the futex_q as soon as
	 * q->lock_ptr = NULL is written, without taking any locks. A
	 * memory barrier is required here to prevent the following
	 * store to lock_ptr from getting ahead of the plist_del.
	 */
	barrier();
	q->lock_ptr = NULL;
}

/*
 * Wake up waiters matching bitset queued on this futex (uaddr).
 */
static int futex_wake(uint32_t *uaddr, int fshared, int nr_wake,
		uint32_t bitset, struct uti_info *uti_info)
{
	struct futex_hash_bucket *hb;
	struct futex_q *this, *next;
	struct mc_plist_head *head;
	union futex_key key = FUTEX_KEY_INIT;
	int ret;
	unsigned long irqstate;

	if (!bitset) {
		return -EINVAL;
	}

	ret = get_futex_key(uaddr, fshared, &key, uti_info);
	if ((ret != 0)) {
		goto out;
	}

	hb = hash_futex(&key, uti_info->futex_queue);
	irqstate = ihk_mc_spinlock_lock(&hb->lock);
	head = &hb->chain;

	mc_plist_for_each_entry_safe(this, next, head, list) {
		if (match_futex(&this->key, &key)) {
			/* RIKEN: no pi state... */
			/* Check if one of the bits is set in both bitsets */
			if (!(this->bitset & bitset))
				continue;

			wake_futex(this, uti_info);
			if (++ret >= nr_wake)
				break;
		}
	}

	ihk_mc_spinlock_unlock(&hb->lock, irqstate);
	put_futex_key(fshared, &key);
out:
	return ret;
}

/**
 * futex_wait_queue_me() - queue_me() and wait for wakeup, timeout, or signal
 * @hb:		the futex hash bucket, must be locked by the caller
 * @q:		the futex_q to queue up on
 * @timeout:	the prepared hrtimer_sleeper, or null for no timeout
 */

/* RIKEN: this function has been rewritten so that it returns the remaining
 * time in case we are waken.
 */

static int64_t futex_wait_queue_me(struct futex_hash_bucket *hb, struct futex_q *q,
				   uint64_t timeout, struct uti_info *uti_info)
{
	int64_t time_remain = 0;
	unsigned long irqstate;

	/*
	 * The task state is guaranteed to be set before another task can
	 * wake it.
	 * queue_me() calls spin_unlock() upon completion, serializing
	 * access to the hash list and forcing a memory barrier.
	 */
	xchg4((int *)uti_info->status, PS_INTERRUPTIBLE);

	/* Indicate spin sleep. Note that schedule_timeout() with
	 * idle_halt should use spin sleep because sleep with timeout
	 * is not implemented.
	 */
	if (!uti_info->mc_idle_halt || timeout) {
		irqstate = ihk_mc_spinlock_lock(
				(_ihk_spinlock_t *)uti_info->spin_sleep_lock);
		*(int *)uti_info->spin_sleep = 1;
		ihk_mc_spinlock_unlock(
				(_ihk_spinlock_t *)uti_info->spin_sleep_lock,
				irqstate);
	}

	queue_me(q, hb, uti_info);

	if (!mc_plist_node_empty(&q->list)) {
		dprintk("%s: tid: %d is trying to sleep, cpu: %d\n",
			__func__, uti_info->tid, ihk_ikc_get_processor_id());
		/* Note that the unit of timeout is nsec */
		time_remain = uti_wait_event(q->uti_futex_resp, timeout);

		/* Note that time_remain == 0 indicates contidion evaluated to false after the timeout elapsed */
		if (time_remain < 0) {
			if (time_remain == -ERESTARTSYS) { /* Interrupted by signal */
				dprintk("%s: DEBUG: wait_event returned -ERESTARTSYS\n", __func__);
			} else {
				pr_err("%s: ERROR: wait_event returned %lld\n", __func__, time_remain);
			}
		}
		dprintk("%s: tid: %d woken up, cpu: %d\n",
			__func__, uti_info->tid, ihk_ikc_get_processor_id());
	}

	/* This does not need to be serialized */
	*(int *)uti_info->status = PS_RUNNING;
	*(int *)uti_info->spin_sleep = 0;

	return time_remain;
}

/**
 * futex_wait_setup() - Prepare to wait on a futex
 * @uaddr:	the futex userspace address
 * @val:	the expected value
 * @fshared:	whether the futex is shared (1) or not (0)
 * @q:		the associated futex_q
 * @hb:		storage for hash_bucket pointer to be returned to caller
 *
 * Setup the futex_q and locate the hash_bucket.  Get the futex value and
 * compare it with the expected value.  Handle atomic faults internally.
 * Return with the hb lock held and a q.key reference on success, and unlocked
 * with no q.key reference on failure.
 *
 * Returns:
 *  0 - uaddr contains val and hb has been locked
 * <1 - -EFAULT or -EWOULDBLOCK (uaddr does not contain val) and hb is unlcoked
 */
static int futex_wait_setup(uint32_t __user *uaddr, uint32_t val, int fshared,
			    struct futex_q *q, struct futex_hash_bucket **hb,
			    struct uti_info *uti_info)
{
	uint32_t uval;
	int ret;

	/*
	 * Access the page AFTER the hash-bucket is locked.
	 * Order is important:
	 *
	 *   Userspace waiter: val = var; if (cond(val)) futex_wait(&var, val);
	 *   Userspace waker:  if (cond(var)) { var = new; futex_wake(&var); }
	 *
	 * The basic logical guarantee of a futex is that it blocks ONLY
	 * if cond(var) is known to be true at the time of blocking, for
	 * any cond.  If we queued after testing *uaddr, that would open
	 * a race condition where we could block indefinitely with
	 * cond(var) false, which would violate the guarantee.
	 *
	 * A consequence is that futex_wait() can return zero and absorb
	 * a wakeup when *uaddr != val on entry to the syscall.  This is
	 * rare, but normal.
	 */
	q->key = FUTEX_KEY_INIT;
	ret = get_futex_key(uaddr, fshared, &q->key, uti_info);
	if (ret != 0)
		return ret;

	*hb = queue_lock(q, (struct futex_hash_bucket *)uti_info->futex_queue);

	ret = get_futex_value_locked(&uval, uaddr);
	if (ret) {
		queue_unlock(q, *hb);
		put_futex_key(fshared, &q->key);
		return ret;
	}

	if (uval != val) {
		queue_unlock(q, *hb);
		ret = -EWOULDBLOCK;
	}

	if (ret)
		put_futex_key(fshared, &q->key);

	return ret;
}

static int futex_wait(uint32_t __user *uaddr, int fshared,
		uint32_t val, uint64_t timeout, uint32_t bitset,
		int clockrt, struct uti_info *uti_info)
{
	struct futex_hash_bucket *hb;
	int64_t time_remain;
	struct futex_q *q = NULL;
	int ret;

	if (!bitset)
		return -EINVAL;

	q = (struct futex_q *)uti_info->futex_q;

	q->bitset = bitset;
	q->requeue_pi_key = NULL;
	q->uti_futex_resp = uti_info->uti_futex_resp;

retry:
	/* Prepare to wait on uaddr. */
	ret = futex_wait_setup(uaddr, val, fshared, q, &hb, uti_info);
	if (ret) {
		goto out;
	}

	/* queue_me and wait for wakeup, timeout, or a signal. */
	time_remain = futex_wait_queue_me(hb, q, timeout, uti_info);

	/* If we were woken (and unqueued), we succeeded, whatever. */
	ret = 0;
	if (!unqueue_me(q)) {
		dprintk("%s: tid=%d unqueued\n", __func__, uti_info->tid);
		goto out_put_key;
	}
	ret = -ETIMEDOUT;

	/* RIKEN: timer expired case (indicated by !time_remain) */
	if (timeout && !time_remain) {
		dprintk("%s: tid=%d timer expired\n", __func__, uti_info->tid);
		goto out_put_key;
	}

	/* RIKEN: futex_wait_queue_me() returns -ERESTARTSYS when waiting on Linux CPU and woken up by signal */
	if (time_remain == -ERESTARTSYS) {
		ret = -EINTR;
		dprintk("%s: tid=%d woken up by signal\n", __func__,
				uti_info->tid);
		goto out_put_key;
	}

	/* RIKEN: no signals */
	put_futex_key(fshared, &q->key);

	goto retry;

out_put_key:
	put_futex_key(fshared, &q->key);
out:
	return ret;
}

/**
 * requeue_futex() - Requeue a futex_q from one hb to another
 * @q:		the futex_q to requeue
 * @hb1:	the source hash_bucket
 * @hb2:	the target hash_bucket
 * @key2:	the new key for the requeued futex_q
 */
static inline
void requeue_futex(struct futex_q *q, struct futex_hash_bucket *hb1,
		   struct futex_hash_bucket *hb2, union futex_key *key2)
{

	/*
	 * If key1 and key2 hash to the same bucket, no need to
	 * requeue.
	 */
	if (&hb1->chain != &hb2->chain) {
		mc_plist_del(&q->list, &hb1->chain);
		mc_plist_add(&q->list, &hb2->chain);
		q->lock_ptr = &hb2->lock;
#ifdef CONFIG_DEBUG_PI_LIST
		q->list.plist.spinlock = &hb2->lock;
#endif
	}
	get_futex_key_refs(key2);
	q->key = *key2;
}

/**
 * futex_requeue() - Requeue waiters from uaddr1 to uaddr2
 * uaddr1:	source futex user address
 * uaddr2:	target futex user address
 * nr_wake:	number of waiters to wake (must be 1 for requeue_pi)
 * nr_requeue:	number of waiters to requeue (0-INT_MAX)
 * requeue_pi:	if we are attempting to requeue from a non-pi futex to a
 * 		pi futex (pi to pi requeue is not supported)
 *
 * Requeue waiters on uaddr1 to uaddr2. In the requeue_pi case, try to acquire
 * uaddr2 atomically on behalf of the top waiter.
 *
 * Returns:
 * >=0 - on success, the number of tasks requeued or woken
 *  <0 - on error
 */
static int futex_requeue(uint32_t *uaddr1, int fshared, uint32_t *uaddr2,
		int nr_wake, int nr_requeue, uint32_t *cmpval,
		int requeue_pi, struct uti_info *uti_info)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	int drop_count = 0, task_count = 0, ret;
	struct futex_hash_bucket *hb1, *hb2;
	struct mc_plist_head *head1;
	struct futex_q *this, *next;

	ret = get_futex_key(uaddr1, fshared, &key1, uti_info);
	if ((ret != 0))
		goto out;
	ret = get_futex_key(uaddr2, fshared, &key2, uti_info);
	if ((ret != 0))
		goto out_put_key1;

	hb1 = hash_futex(&key1, uti_info->futex_queue);
	hb2 = hash_futex(&key2, uti_info->futex_queue);

	double_lock_hb(hb1, hb2);

	if (cmpval != NULL) {
		uint32_t curval;

		ret = get_futex_value_locked(&curval, uaddr1);

		if (curval != *cmpval) {
			ret = -EAGAIN;
			goto out_unlock;
		}
	}

	head1 = &hb1->chain;
	mc_plist_for_each_entry_safe(this, next, head1, list) {
		if (task_count - nr_wake >= nr_requeue)
			break;

		if (!match_futex(&this->key, &key1))
			continue;

		/*
		 * Wake nr_wake waiters.  For requeue_pi, if we acquired the
		 * lock, we already woke the top_waiter.  If not, it will be
		 * woken by futex_unlock_pi().
		 */
		/* RIKEN: no requeue_pi at this moment */
		if (++task_count <= nr_wake) {
			wake_futex(this, uti_info);
			continue;
		}

		requeue_futex(this, hb1, hb2, &key2);
		drop_count++;
	}

out_unlock:
	double_unlock_hb(hb1, hb2);

	/*
	 * drop_futex_key_refs() must be called outside the spinlocks. During
	 * the requeue we moved futex_q's from the hash bucket at key1 to the
	 * one at key2 and updated their key pointer.  We no longer need to
	 * hold the references to key1.
	 */
	while (--drop_count >= 0)
		drop_futex_key_refs(&key1);

	put_futex_key(fshared, &key2);
out_put_key1:
	put_futex_key(fshared, &key1);
out:
	return ret ? ret : task_count;
}

/*
 * Wake up all waiters hashed on the physical page that is mapped
 * to this virtual address:
 */
static int
futex_wake_op(uint32_t *uaddr1, int fshared, uint32_t *uaddr2,
			  int nr_wake, int nr_wake2, int op,
			  struct uti_info *uti_info)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	struct futex_hash_bucket *hb1, *hb2;
	struct mc_plist_head *head;
	struct futex_q *this, *next;
	int ret, op_ret;

retry:
	ret = get_futex_key(uaddr1, fshared, &key1, uti_info);
	if ((ret != 0))
		goto out;
	ret = get_futex_key(uaddr2, fshared, &key2, uti_info);
	if ((ret != 0))
		goto out_put_key1;

	hb1 = hash_futex(&key1, uti_info->futex_queue);
	hb2 = hash_futex(&key2, uti_info->futex_queue);

retry_private:
	double_lock_hb(hb1, hb2);
	op_ret = futex_atomic_op_inuser(op, (int *)uaddr2);
	if ((op_ret < 0)) {

		double_unlock_hb(hb1, hb2);

		if ((op_ret != -EFAULT)) {
			ret = op_ret;
			goto out_put_keys;
		}

		/* RIKEN: set ret to 0 as if fault_in_user_writeable() returned it */
		ret = 0;

		if (!fshared)
			goto retry_private;

		put_futex_key(fshared, &key2);
		put_futex_key(fshared, &key1);
		goto retry;
	}

	head = &hb1->chain;

	mc_plist_for_each_entry_safe(this, next, head, list) {
		if (match_futex(&this->key, &key1)) {
			wake_futex(this, uti_info);
			if (++ret >= nr_wake)
				break;
		}
	}

	if (op_ret > 0) {
		head = &hb2->chain;

		op_ret = 0;
		mc_plist_for_each_entry_safe(this, next, head, list) {
			if (match_futex(&this->key, &key2)) {
				wake_futex(this, uti_info);
				if (++op_ret >= nr_wake2)
					break;
			}
		}
		ret += op_ret;
	}

	double_unlock_hb(hb1, hb2);
out_put_keys:
	put_futex_key(fshared, &key2);
out_put_key1:
	put_futex_key(fshared, &key1);
out:
	return ret;
}

static int futex(uint32_t *uaddr, int op, uint32_t val, uint64_t timeout,
		uint32_t *uaddr2, uint32_t val2, uint32_t val3, int fshared,
		struct uti_info *uti_info)
{
	int clockrt, ret = -ENOSYS;
	int cmd = op & FUTEX_CMD_MASK;


	clockrt = op & FUTEX_CLOCK_REALTIME;
	if (clockrt && cmd != FUTEX_WAIT_BITSET && cmd != FUTEX_WAIT_REQUEUE_PI)
		return -ENOSYS;

	switch (cmd) {
	case FUTEX_WAIT:
		val3 = FUTEX_BITSET_MATCH_ANY;
	case FUTEX_WAIT_BITSET:
		ret = futex_wait(uaddr, fshared, val, timeout,
				val3, clockrt, uti_info);
		break;
	case FUTEX_WAKE:
		val3 = FUTEX_BITSET_MATCH_ANY;
	case FUTEX_WAKE_BITSET:
		ret = futex_wake(uaddr, fshared, val, val3, uti_info);
		break;
	case FUTEX_REQUEUE:
		ret = futex_requeue(uaddr, fshared, uaddr2, val,
				val2, NULL, 0, uti_info);
		break;
	case FUTEX_CMP_REQUEUE:
		ret = futex_requeue(uaddr, fshared, uaddr2, val,
				val2, NULL, 0, uti_info);
		break;
	case FUTEX_WAKE_OP:
		ret = futex_wake_op(uaddr, fshared, uaddr2, val,
				val2, val3, uti_info);
		break;
	/* RIKEN: these calls are not supported for now.
	case FUTEX_LOCK_PI:
		if (futex_cmpxchg_enabled)
			ret = futex_lock_pi(uaddr, fshared, val, timeout, 0);
		break;
	case FUTEX_UNLOCK_PI:
		if (futex_cmpxchg_enabled)
			ret = futex_unlock_pi(uaddr, fshared);
		break;
	case FUTEX_TRYLOCK_PI:
		if (futex_cmpxchg_enabled)
			ret = futex_lock_pi(uaddr, fshared, 0, timeout, 1);
		break;
	case FUTEX_WAIT_REQUEUE_PI:
		val3 = FUTEX_BITSET_MATCH_ANY;
		ret = futex_wait_requeue_pi(uaddr, fshared, val, timeout, val3,
						clockrt, uaddr2);
		break;
	case FUTEX_CMP_REQUEUE_PI:
		ret = futex_requeue(uaddr, fshared, uaddr2, val, val2, &val3,
					1);
		break;
	*/
	default:
		pr_warn("%s: invalid cmd: %d\n", __func__, cmd);
		ret = -ENOSYS;
	}
	return ret;
}

long do_futex(int n, unsigned long arg0, unsigned long arg1,
			  unsigned long arg2, unsigned long arg3,
			  unsigned long arg4, unsigned long arg5,
			  struct uti_info *uti_info,
			  void *uti_futex_resp)
{
	uint64_t timeout = 0; // No timeout
	uint32_t val2 = 0;
	int fshared = 1;
	int ret = 0;

	uint32_t *uaddr = (uint32_t *)arg0;
	int op = (int)arg1;
	uint32_t val = (uint32_t)arg2;
	struct timespec *utime = (struct timespec *)arg3;
	struct timespec ts;
	uint32_t *uaddr2 = (uint32_t *)arg4;
	uint32_t val3 = (uint32_t)arg5;
	int flags = op;

	/* Fill in uti_futex_resp */
	uti_info->uti_futex_resp = uti_futex_resp;

	/* Cross-address space futex? */
	if (op & FUTEX_PRIVATE_FLAG) {
		fshared = 0;
	}
	op = (op & FUTEX_CMD_MASK);

	dprintk("futex op=[%x, %s],uaddr=%lx, val=%x, utime=%p, uaddr2=%p, val3=%x, shared: %d\n",
			flags,
			(op == FUTEX_WAIT) ? "FUTEX_WAIT" :
			(op == FUTEX_WAIT_BITSET) ? "FUTEX_WAIT_BITSET" :
			(op == FUTEX_WAKE) ? "FUTEX_WAKE" :
			(op == FUTEX_WAKE_OP) ? "FUTEX_WAKE_OP" :
			(op == FUTEX_WAKE_BITSET) ? "FUTEX_WAKE_BITSET" :
			(op == FUTEX_CMP_REQUEUE) ? "FUTEX_CMP_REQUEUE" :
			(op == FUTEX_REQUEUE) ? "FUTEX_REQUEUE (NOT IMPL!)" : "unknown",
			(unsigned long)uaddr, val, utime, uaddr2, val3, fshared);

	if (utime && (op == FUTEX_WAIT_BITSET || op == FUTEX_WAIT)) {
		if (copy_from_user(&ts, utime, sizeof(ts)) != 0) {
			return -EFAULT;
		}

		dprintk("%s: utime=%ld.%09ld\n", __func__, ts.tv_sec, ts.tv_nsec);
		if (!timespec_valid(&ts)) {
			return -EINVAL;
		}

		if (op == FUTEX_WAIT_BITSET) { /* User passed absolute time */
			struct timespec ats;

			ret = uti_clock_gettime((flags & FUTEX_CLOCK_REALTIME) ?
					CLOCK_REALTIME : CLOCK_MONOTONIC, &ats);
			if (ret) {
				return ret;
			}
			dprintk("%s: ats=%ld.%09ld\n", __func__, ats.tv_sec, ats.tv_nsec);
			/* Use nsec for UTI case */
			timeout = (ts.tv_sec * NS_PER_SEC + ts.tv_nsec) -
				(ats.tv_sec * NS_PER_SEC + ats.tv_nsec);
		} else { /* User passed relative time */
			/* Use nsec for UTI case */
			timeout = (ts.tv_sec * NS_PER_SEC + ts.tv_nsec);
		}
	}

	/* Requeue parameter in 'utime' if op == FUTEX_CMP_REQUEUE.
	 * number of waiters to wake in 'utime' if op == FUTEX_WAKE_OP. */
	if (op == FUTEX_CMP_REQUEUE || op == FUTEX_WAKE_OP) {
		val2 = (uint32_t) (unsigned long) arg3;
	}

	ret = futex(uaddr, op, val, timeout, uaddr2,
			val2, val3, fshared, uti_info);

	dprintk("futex op=[%x, %s],uaddr=%lx, val=%x, utime=%p, uaddr2=%p, val3=%x, shared: %d, ret: %d\n",
			op,
			(op == FUTEX_WAIT) ? "FUTEX_WAIT" :
			(op == FUTEX_WAIT_BITSET) ? "FUTEX_WAIT_BITSET" :
			(op == FUTEX_WAKE) ? "FUTEX_WAKE" :
			(op == FUTEX_WAKE_OP) ? "FUTEX_WAKE_OP" :
			(op == FUTEX_WAKE_BITSET) ? "FUTEX_WAKE_BITSET" :
			(op == FUTEX_CMP_REQUEUE) ? "FUTEX_CMP_REQUEUE" :
			(op == FUTEX_REQUEUE) ? "FUTEX_REQUEUE (NOT IMPL!)" : "unknown",
			(unsigned long)uaddr, val, utime, uaddr2, val3, fshared, ret);

	return ret;
}

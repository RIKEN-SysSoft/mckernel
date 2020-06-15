/**
 * \file procfs.c
 *  License details are found in the file LICENSE.
 * \brief
 *  McKernel procfs
 * \author Naoki Hamada <nao@axe.bz> \par
 * 	Copyright (C) 2014  AXE, Inc.
 */
/*
 * HISTORY:
 */
/* procfs.c COPYRIGHT FUJITSU LIMITED 2015-2017 */

#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <ikc/master.h>
#include <cls.h>
#include <syscall.h>
#include <kmalloc.h>
#include <process.h>
#include <page.h>
#include <mman.h>
#include <bitmap.h>
#include <init.h>

//#define DEBUG_PRINT_PROCFS

#ifdef DEBUG_PRINT_PROCFS
#define	dprintf(...) kprintf(__VA_ARGS__)
#else
#define dprintf(...)
#endif

extern int snprintf(char *buf, size_t size, const char *fmt, ...);
extern int sscanf(const char * buf, const char * fmt, ...);
extern int scnprintf(char * buf, size_t size, const char *fmt, ...);
static int do_procfs_backlog(void *arg);

struct mckernel_procfs_buffer {
	unsigned long next_pa;
	unsigned long pos;
	unsigned long size;
	char buf[0];
};

#define PA_NULL (-1L)

static struct mckernel_procfs_buffer *buf_alloc(unsigned long *phys, long pos)
{
	struct mckernel_procfs_buffer *buf;

	buf = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
	if (!buf)
		return NULL;
	buf->next_pa = PA_NULL;
	buf->pos = pos;
	buf->size = 0;
	if (phys)
		*phys = virt_to_phys(buf);
	return buf;
}

static void buf_free(unsigned long phys)
{
	struct mckernel_procfs_buffer *pbuf;
	unsigned long next;

	while (phys != PA_NULL) {
		pbuf = phys_to_virt(phys);
		next = pbuf->next_pa;
		ihk_mc_free_pages(pbuf, 1);
		phys = next;
	}
}

static int buf_add(struct mckernel_procfs_buffer **top,
		   struct mckernel_procfs_buffer **cur,
		   const void *buf, int l)
{
	int pos = 0;
	int r;
	int bufmax = PAGE_SIZE - sizeof(struct mckernel_procfs_buffer);
	const char *chr = buf;

	if (!*top) {
		*top = *cur = buf_alloc(NULL, 0);
		if (!*top)
			return -ENOMEM;
	}
	while (l) {
		r = bufmax - (*cur)->size;
		if (!r) {
			*cur = buf_alloc(&(*cur)->next_pa, (*cur)->pos +
							   bufmax);
			if (!*cur) {
				buf_free(virt_to_phys(*top));
				return -ENOMEM;
			}
			r = bufmax;
		}
		if (r > l) {
			r = l;
		}
		memcpy((*cur)->buf + (*cur)->size, chr + pos, r);
		l -= r;
		pos += r;
		(*cur)->size += r;
	}
	return 0;
}

static void
procfs_thread_ctl(struct thread *thread, int msg)
{
	struct ihk_ikc_channel_desc *syscall_channel;
	struct ikc_scd_packet packet;
	int done = 0;

	syscall_channel = cpu_local_var(ikc2linux);
	memset(&packet, '\0', sizeof packet);
	packet.arg = thread->tid;
	packet.msg = msg;
	packet.osnum = ihk_mc_get_osnum();
	packet.ref = thread->cpu_id;
	packet.pid = thread->proc->pid;
	packet.resp_pa = virt_to_phys(&done);
	packet.err = 0;

	ihk_ikc_send(syscall_channel, &packet, 0);
	if (msg == SCD_MSG_PROCFS_TID_CREATE) {
		while (!done)
			cpu_pause();
	}
}

void
procfs_create_thread(struct thread *thread)
{
	procfs_thread_ctl(thread, SCD_MSG_PROCFS_TID_CREATE);
}

void
procfs_delete_thread(struct thread *thread)
{
	procfs_thread_ctl(thread, SCD_MSG_PROCFS_TID_DELETE);
}

static int procfs_backlog(struct process_vm *vm, struct ikc_scd_packet *rpacket)
{
	void *arg;
	int err;

	if (!(arg = kmalloc(sizeof(struct ikc_scd_packet), IHK_MC_AP_NOWAIT))) {
		return -ENOMEM;
	}
	memcpy(arg, rpacket, sizeof(struct ikc_scd_packet));
	if ((err = add_backlog(do_procfs_backlog, arg))) {
		kfree(arg);
		return err;
	}
	return 0;
}

/**
 * \brief The callback function for mckernel procfs files.
 *
 * \param rarg returned argument
 */
static int _process_procfs_request(struct ikc_scd_packet *rpacket, int *result)
{
	unsigned long rarg = rpacket->arg;
	unsigned long parg, pbuf;
	struct thread *thread = NULL;
	struct process *proc = NULL;
	struct process_vm *vm = NULL;
	struct procfs_read *r;
	int osnum = ihk_mc_get_osnum();
	int rosnum, ret, pid, tid, ans = -EIO, eof = 0;
	char *buf, *p = NULL;
	char *vbuf = NULL;
	char *tmp = NULL;
	struct mcs_rwlock_node_irqsave lock;
	unsigned long offset;
	int count;
	int npages;
	int readwrite = 0;
	int err = -EIO;
	struct mckernel_procfs_buffer *buf_top = NULL;
	struct mckernel_procfs_buffer *buf_cur = NULL;

	dprintf("process_procfs_request: invoked.\n");

	dprintf("rarg: %x\n", rarg);
	parg = ihk_mc_map_memory(NULL, rarg, sizeof(struct procfs_read));
	dprintf("parg: %x\n", parg);
	r = ihk_mc_map_virtual(parg, 1, PTATTR_WRITABLE | PTATTR_ACTIVE);
	if (r == NULL) {
		ihk_mc_unmap_memory(NULL, parg, sizeof(struct procfs_read));
		kprintf("ERROR: process_procfs_request: got a null procfs_read structure.\n");
		goto err;
	}
	dprintf("r: %p\n", r);

	if (rpacket->msg == SCD_MSG_PROCFS_RELEASE) {
		struct mckernel_procfs_buffer *pbuf;
		unsigned long phys;
		unsigned long next;

		for (phys = r->pbuf; phys != PA_NULL; phys = next) {
			pbuf = phys_to_virt(phys);
			next = pbuf->next_pa;
			ihk_mc_free_pages(pbuf, 1);
		}
		r->ret = 0;
		err = 0;
		goto err;
	}

	if (r->pbuf == PA_NULL) {
		tmp = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
		if (!tmp)
			goto err;
		buf = tmp;
		count = PAGE_SIZE;
	}
	else {
		dprintf("remote pbuf: %x\n", r->pbuf);
		pbuf = ihk_mc_map_memory(NULL, r->pbuf, r->count);
		dprintf("pbuf: %x\n", pbuf);
		count = r->count + ((uintptr_t)pbuf & (PAGE_SIZE - 1));
		npages = (count + (PAGE_SIZE - 1)) / PAGE_SIZE;
		vbuf = ihk_mc_map_virtual(pbuf, npages,
					  PTATTR_WRITABLE|PTATTR_ACTIVE);
		dprintf("buf: %p\n", vbuf);
		if (vbuf == NULL) {
			ihk_mc_unmap_memory(NULL, pbuf, r->count);
			kprintf("ERROR: %s: got a null buffer.\n", __func__);
			goto err;
		}
		buf = vbuf;
		readwrite = r->readwrite;
		count = r->count;
		dprintf("fname: %s, offset: %lx, count:%d.\n", r->fname,
			r->offset, r->count);
	}
	offset = r->offset;

	/*
	 * check for "mcos%d/"
	 */
	ret = sscanf(r->fname, "mcos%d/", &rosnum);
	if (ret == 1) {
		if (osnum != rosnum) {
			kprintf("ERROR: process_procfs_request osnum mismatch "
				"(we are %d != requested %d)\n",
				osnum, rosnum);
			goto end;
		}
		dprintf("matched mcos%d.\n", osnum);
	} else {
		goto end;
	}
	p = strchr(r->fname, '/') + 1;

	/* Processing for pattern "mcos%d/xxx" files should be here.
	   Its template is something like what follows:

	   if (pattern matches) {
	   	   get the data (at 'r->offset')
		   and write it to 'buf'
		   up to 'r->count' bytes.
		ans = written bytes;
		goto end;
	   }
	*/

	/*
	 * check for "mcos%d/PID/"
	 */
	ret = sscanf(p, "%d/", &pid);
	if (ret == 1) {
		struct mcs_rwlock_node_irqsave tlock;
		int tids;
		struct thread *thread1 = NULL;

		proc = find_process(pid, &lock);
		if(proc == NULL){
			kprintf("process_procfs_request: no such pid %d\n", pid);
			goto end;
		}
		p = strchr(p, '/') + 1;
		if((tids = sscanf(p, "task/%d/", &tid)) == 1){
			p = strchr(p, '/') + 1;
			p = strchr(p, '/') + 1;
		}
		else
			tid = pid;

		mcs_rwlock_reader_lock(&proc->threads_lock, &tlock);
		list_for_each_entry(thread, &proc->threads_list, siblings_list){
			if(thread->tid == tid)
				break;
			if(!thread1)
				thread1 = thread;
		}
		if(thread == NULL){
			kprintf("process_procfs_request: no such tid %d-%d\n", pid, tid);
			if(tids){
				mcs_rwlock_reader_unlock(&proc->threads_lock, &tlock);
				process_unlock(proc, &lock);
				goto end;
			}
			thread = thread1;
		}
		if(thread)
			hold_thread(thread);
		mcs_rwlock_reader_unlock(&proc->threads_lock, &tlock);
		hold_process(proc);
		vm = proc->vm;
		if(vm)
			hold_process_vm(vm);
		process_unlock(proc, &lock);
	}
	else if (!strcmp(p, "mckernel")) {
		ans = snprintf(buf, count, "%s-%s\n",
				MCKERNEL_VERSION, BUILDID);

		if (buf_add(&buf_top, &buf_cur, buf, ans) < 0)
			goto err;
		ans = 0;
		goto end;
	}
	else if (!strcmp(p, "stat")) {	/* "/proc/stat" */
		extern int num_processors;	/* kernel/ap.c */
		int cpu;

		for (cpu = 0; cpu < num_processors; ++cpu) {
			ans = snprintf(buf, count, "cpu%d\n", cpu);
			if (ans < 0 || ans > count)
				goto err;
			if (buf_add(&buf_top, &buf_cur, buf, ans) < 0)
				goto err;
		}
		ans = 0;
		goto end;
	}
#ifdef POSTK_DEBUG_ARCH_DEP_42 /* /proc/cpuinfo support added. */
	else if (!strcmp(p, "cpuinfo")) { /* "/proc/cpuinfo" */
		ans = ihk_mc_show_cpuinfo(buf, count, 0, &eof);
		if (ans < 0 || ans > count)
			goto err;
		if (buf_add(&buf_top, &buf_cur, buf, ans) < 0)
			goto err;
		ans = 0;
		goto end;
	}
#endif /* POSTK_DEBUG_ARCH_DEP_42 */
	else {
		kprintf("unsupported procfs entry: %s\n", p);
		goto end;
	}

	/* 
	 * mcos%d/PID/mem
	 *
	 * The offset is treated as the beginning of the virtual address area
	 * of the process. The count is the length of the area.
	 */
	if (strcmp(p, "mem") == 0) {
		uint64_t reason = PF_POPULATE | PF_WRITE | PF_USER;
		unsigned long offset = r->offset;
		unsigned long left = r->count;
		int ret;
		struct page_table *pt = vm->address_space->page_table;

		ans = 0;
		if(left == 0)
			goto end;

#if 0
		if(!(proc->ptrace & PT_TRACED) ||
		   !(proc->status & (PS_STOPPED | PS_TRACED))){
			ans = -EIO;
			goto end;
		}
#endif

		if(readwrite == 0)
			reason = PF_POPULATE | PF_USER;

		while(left){
			unsigned long pa;
			char *va;
			int pos = offset & (PAGE_SIZE - 1);
			int size = PAGE_SIZE - pos;

			if(size > left)
				size = left;
			ret = page_fault_process_vm(vm, (void *)offset, reason);
			if(ret){
				if(ans == 0)
					ans = -EIO;
				goto end;
			}
			ret = ihk_mc_pt_virt_to_phys(pt, (void *)offset, &pa);
			if(ret){
				if(ans == 0)
					ans = -EIO;
				goto end;
			}

			if (!is_mckernel_memory(pa, pa + size)) {
				ans = -EIO;
				goto end;
			}

			va = phys_to_virt(pa);
			if(readwrite)
				memcpy(va, buf + ans, size);
			else
				memcpy(buf + ans, va, size);
			offset += size;
			left -= size;
			ans += size;
		}
		goto end;
	}

	/*
	 * mcos%d/PID/maps
	 */
	if (strcmp(p, "maps") == 0) {
		struct vm_range *range;

		if (!ihk_rwspinlock_read_trylock_noirq(&vm->memory_range_lock)) {
			if (!result) {
				if ((err = procfs_backlog(vm, rpacket))) {
					goto err;
				}
			}
			else {
				*result = -EAGAIN;
			}
			goto out;
		}

		range = lookup_process_memory_range(vm, 0, -1);
		while (range) {
			/* format is (from man proc):
			 *  address           perms offset  dev   inode   pathname
			 *  08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
			 */
			ans = snprintf(buf, count,
				 "%012lx-%012lx %s%s%s%s %lx %lx:%lx %d\t\t\t%s\n",
				 range->start, range->end,
				 range->flag & VR_PROT_READ ? "r" : "-",
				 range->flag & VR_PROT_WRITE ? "w" : "-",
				 range->flag & VR_PROT_EXEC ? "x" : "-",
				 range->flag & VR_PRIVATE ? "p" : "s",
				 /* TODO: fill in file details! */
				 0UL,
				 0UL,
				 0UL,
				 0,
				 range->memobj && range->memobj->path ?
					range->memobj->path :
				 range->start == (unsigned long)vm->vdso_addr ?
					"[vdso]" :
				 range->start == (unsigned long)vm->vvar_addr ?
					"[vsyscall]" :
				 range->flag & VR_STACK ?
					"[stack]" :
				 range->start >= vm->region.brk_start &&
				    range->end <= vm->region.brk_end_allocated ?
					"[heap]" :
					""
				);

			if (ans < 0 || ans > count ||
			    buf_add(&buf_top, &buf_cur, buf, ans) < 0) {
				ihk_rwspinlock_read_unlock_noirq(
							&vm->memory_range_lock);
				goto err;
			}
			range = next_process_memory_range(vm, range);
		}

		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);

		ans = 0;
		goto end;
	}
	
	/*
	 * mcos%d/PID/pagemap
	 */
	if (strcmp(p, "pagemap") == 0) {
		uint64_t *_buf = (uint64_t *)buf;
		uint64_t start, end;

		/* Check alignment */
		if ((offset % sizeof(uint64_t) != 0) || 
		    (count % sizeof(uint64_t) != 0)) {
			ans = -EINVAL;
			goto end;
		}

		start = (offset / sizeof(uint64_t)) << PAGE_SHIFT;
		end = start + ((count / sizeof(uint64_t)) << PAGE_SHIFT);

		if (!ihk_rwspinlock_read_trylock_noirq(&vm->memory_range_lock)) {
			if (!result) {
				if ((err = procfs_backlog(vm, rpacket))) {
					goto err;
				}
			}
			else {
				*result = -EAGAIN;
			}
			goto out;
		}

		while (start < end) {
			*_buf = ihk_mc_pt_virt_to_pagemap(proc->vm->address_space->page_table, start);
			dprintf("PID: %d, /proc/pagemap: 0x%lx -> %lx\n",  proc->proc->pid, 
					start, *_buf);
			start += PAGE_SIZE;
			++_buf;
		}

		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);

		dprintf("/proc/pagemap: 0x%lx - 0x%lx, count: %d\n", 
			start, end, count);
		
		ans = count;
		goto end;
	}

	/* 
	 * mcos%d/PID/status
	 */
#define BITMASKS_BUF_SIZE	2048
	if (strcmp(p, "status") == 0) {
		extern int num_processors;	/* kernel/ap.c */
		struct vm_range *range;
		unsigned long lockedsize = 0;
		char *bitmasks;
		int bitmasks_offset = 0;
		char *cpu_bitmask, *cpu_list, *numa_bitmask, *numa_list;
		char *state;
		struct mcs_rwlock_node_irqsave lock;
		struct thread *thread_iter;
		int nr_threads = 0;

		bitmasks = kmalloc(BITMASKS_BUF_SIZE, IHK_MC_AP_CRITICAL);
		if (!bitmasks) {
			kprintf("%s: error allocating /proc/self/status bitmaks buffer\n",
				__FUNCTION__);
			goto err;
		}

		if (!ihk_rwspinlock_read_trylock_noirq(&vm->memory_range_lock)) {
			if (!result) {
				if ((err = procfs_backlog(vm, rpacket))) {
					goto err;
				}
			}
			else {
				*result = -EAGAIN;
			}
			goto out;
		}
		range = lookup_process_memory_range(vm, 0, -1);
		while (range) {
			if(range->flag & VR_LOCKED)
				lockedsize += range->end - range->start;
			range = next_process_memory_range(vm, range);
		}
		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);

		cpu_bitmask = &bitmasks[bitmasks_offset];
		bitmasks_offset += bitmap_scnprintf(cpu_bitmask,
				BITMASKS_BUF_SIZE - bitmasks_offset,
				thread->cpu_set.__bits, num_processors);
		bitmasks_offset++;

		cpu_list = &bitmasks[bitmasks_offset];
		bitmasks_offset += bitmap_scnlistprintf(cpu_list,
				BITMASKS_BUF_SIZE - bitmasks_offset,
				thread->cpu_set.__bits, __CPU_SETSIZE);
		bitmasks_offset++;

		numa_bitmask = &bitmasks[bitmasks_offset];
		bitmasks_offset += bitmap_scnprintf(numa_bitmask,
				BITMASKS_BUF_SIZE - bitmasks_offset,
				proc->vm->numa_mask, PROCESS_NUMA_MASK_BITS);
		bitmasks_offset++;

		numa_list = &bitmasks[bitmasks_offset];
		bitmasks_offset += bitmap_scnlistprintf(numa_list,
				BITMASKS_BUF_SIZE - bitmasks_offset,
				proc->vm->numa_mask, PROCESS_NUMA_MASK_BITS);
		bitmasks_offset++;

		mcs_rwlock_reader_lock(&proc->threads_lock, &lock);
		list_for_each_entry(thread_iter, &proc->threads_list,
				siblings_list) {
			++nr_threads;
		}
		mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);

		state = "R (running)";
		if (proc->status == PS_STOPPED)
			state = "T (stopped)";
		else if (proc->status == PS_TRACED)
			state = "T (tracing stop)";
		else if (proc->status == PS_EXITED)
			state = "Z (zombie)";
		ans = snprintf(buf, count,
			"Pid:\t%d\n"
			"Uid:\t%d\t%d\t%d\t%d\n"
			"Gid:\t%d\t%d\t%d\t%d\n"
			"State:\t%s\n"
			"VmLck:\t%9lu kB\n"
			"Threads:	%d\n",
			proc->pid,
			proc->ruid, proc->euid, proc->suid, proc->fsuid,
			proc->rgid, proc->egid, proc->sgid, proc->fsgid,
			state,
			(lockedsize + 1023) >> 10,
			nr_threads);
		if (ans < 0 || ans > count ||
		    buf_add(&buf_top, &buf_cur, buf, ans) < 0) {
			goto err;
		}

		ans = snprintf(buf, count, "Cpus_allowed:\t%s\n", cpu_bitmask);
		if (ans < 0 || ans > count ||
		    buf_add(&buf_top, &buf_cur, buf, ans) < 0) {
			kfree(bitmasks);
			goto err;
		}
		ans = snprintf(buf, count, "Cpus_allowed_list:\t%s\n",
			       cpu_list);
		if (ans < 0 || ans > count ||
		    buf_add(&buf_top, &buf_cur, buf, ans) < 0) {
			kfree(bitmasks);
			goto err;
		}
		ans = snprintf(buf, count, "Mems_allowed:\t%s\n",
			       numa_bitmask);
		if (ans < 0 || ans > count ||
		    buf_add(&buf_top, &buf_cur, buf, ans) < 0) {
			kfree(bitmasks);
			goto err;
		}
		ans = snprintf(buf, count, "Mems_allowed_list:\t%s\n",
			       numa_list);
		if (ans < 0 || ans > count ||
		    buf_add(&buf_top, &buf_cur, buf, ans) < 0) {
			kfree(bitmasks);
			goto err;
		}
		kfree(bitmasks);
		ans = 0;
		goto end;
	}

	/* 
	 * mcos%d/PID/auxv
	 */
	if (strcmp(p, "auxv") == 0) {
		unsigned int limit = AUXV_LEN * sizeof(unsigned long);

		if (buf_add(&buf_top, &buf_cur, proc->saved_auxv, limit) < 0)
			goto err;
		ans = 0;
		goto end;
	}

	/* 
	 * mcos%d/PID/cmdline
	 */
	if (strcmp(p, "cmdline") == 0) {
		unsigned int limit = proc->saved_cmdline_len;

		if(!proc->saved_cmdline){
			if (buf_add(&buf_top, &buf_cur, "", 0) < 0)
				goto err;
			ans = 0;
			goto end;
		}

		if (buf_add(&buf_top, &buf_cur, proc->saved_cmdline, limit) < 0)
			goto err;
		ans = 0;
		goto end;
	}

	/* 
	 * mcos%d/PID/taks/PID/mem
	 *
	 * The offset is treated as the beginning of the virtual address area
	 * of the process. The count is the length of the area.
	 */

	if (!strcmp(p, "comm")) {
		const char *comm = "exe";

		if (proc->saved_cmdline) {
			comm = strrchr(proc->saved_cmdline, '/');
			if (comm)
				comm++;
			else
				comm = proc->saved_cmdline;
		}

		ans = snprintf(buf, count, "%s\n", comm);
		if (buf_add(&buf_top, &buf_cur, buf, ans) < 0)
			goto err;
		ans = 0;
		goto end;
	}

	if (!strcmp(p, "stat")) {
		const char *comm = "exe";
		char state;
		struct mcs_rwlock_node_irqsave lock;
		struct thread *thread_iter;
		int nr_threads = 0;

		if (proc->saved_cmdline) {
			comm = strrchr(proc->saved_cmdline, '/');
			if (comm)
				comm++;
			else
				comm = proc->saved_cmdline;
		}

		switch (thread->status & (0x3f)) {
		case PS_INTERRUPTIBLE:
			state = 'S';
			break;
		case PS_UNINTERRUPTIBLE:
			state = 'D';
			break;
		case PS_ZOMBIE:
			state = 'Z';
			break;
		case PS_EXITED:
			state = 'X';
			break;
		case PS_STOPPED:
			state = 'T';
			break;
		case PS_RUNNING:
		default:
			if (thread->in_syscall_offload > 0) {
				state = 'S';
			}
			else {
				state = 'R';
			}
		}

		mcs_rwlock_reader_lock(&proc->threads_lock, &lock);
		list_for_each_entry(thread_iter, &proc->threads_list,
				siblings_list) {
			++nr_threads;
		}
		mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);

		/*
		 * pid (comm) state ppid
		 * pgrp session tty_nr tpgid
		 * flags minflt cminflt majflt
		 * cmajflt utime stime cutime
		 * cstime priority nice num_threads
		 * itrealvalue starttime vsize rss
		 * rsslim startcode endcode startstack
		 * kstkesp kstkeip signal blocked
		 * sigignore sigcatch wchan nswap
		 * cnswap exit_signal processor rt_priority
		 * policy delayacct_blkio_ticks guest_time cguest_time
		 */
		ans = snprintf(buf, count,
		    "%d (%s) %c %d "	      // pid...
		    "%d %d %d %d "	      // pgrp...
		    "%u %lu %lu %lu "	      // flags...
		    "%lu %lu %lu %ld "	      // cmajflt...
		    "%ld %ld %ld %ld "	      // cstime...
		    "%ld %llu %lu %ld "	      // itrealvalue...
		    "%lu %lu %lu %lu "	      // rsslim...
		    "%lu %lu %lu %lu "	      // kstkesp...
		    "%lu %lu %lu %lu "	      // sigignore...
		    "%lu %d %d %u "	      // cnswap...
		    "%u %llu %lu %ld\n",      // policy...
		    thread->tid, comm, state,
		    thread->proc->ppid_parent->pid, // pid...
		    thread->proc->pid, 0, 0, 0, // pgrp...
		    0, 0L, 0L, 0L,	      // flags...
		    0L, 0L, 0L, 0L,	      // cmajflt...
		    0L, 0L, 0L, (long int)nr_threads, // cstime...
		    0L, 0LL, 0L, 0L,	      // itrealvalue...
		    0L, 0L, 0L, 0L,	      // rsslim...
		    0L, 0L, 0L, 0L,	      // kstkesp...
		    0L, 0L, 0L, 0L,	      // sigignore...
		    0L, 0, thread->cpu_id, 0, // cnswap...
		    0, 0LL, 0L, 0L	      // policy...
		);

		if (ans < 0 || ans > count ||
		    buf_add(&buf_top, &buf_cur, buf, ans) < 0)
			goto err;
		ans = 0;
		goto end;
	}

	if(thread)
		kprintf("unsupported procfs entry: %d/task/%d/%s\n", pid, tid, p);
	else
		kprintf("unsupported procfs entry: %d/%s\n", pid, p);

end:
	dprintf("ret: %d, eof: %d\n", ans, eof);
	r->ret = ans;
	r->eof = eof;
	err = 0;
	if (r->pbuf == PA_NULL && buf_top)
		r->pbuf = virt_to_phys(buf_top);
err:
	send_procfs_answer(rpacket, err);

out:
	if (vbuf) {
		ihk_mc_unmap_virtual(vbuf, npages);
		ihk_mc_unmap_memory(NULL, pbuf, r->count);
	}
	if (r) {
		ihk_mc_unmap_virtual(r, 1);
		ihk_mc_unmap_memory(NULL, parg, sizeof(struct procfs_read));
	}
	if (tmp) {
		ihk_mc_free_pages(tmp, 1);
	}

	if(proc)
		release_process(proc);
	if(thread)
		release_thread(thread);
	if(vm)
		release_process_vm(vm);

	return err;
}

int process_procfs_request(struct ikc_scd_packet *rpacket)
{
	return _process_procfs_request(rpacket, NULL);
}

static int do_procfs_backlog(void *arg)
{
	struct ikc_scd_packet *rpacket = arg;
	int result = 0;

	_process_procfs_request(rpacket, &result);
	if (!result) {
		kfree(arg);
	}
	return result;
}

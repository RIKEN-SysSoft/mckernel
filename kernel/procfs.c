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

extern int snprintf(char * buf, size_t size, const char *fmt, ...);
extern int sprintf(char * buf, const char *fmt, ...);
extern int sscanf(const char * buf, const char * fmt, ...);
extern int scnprintf(char * buf, size_t size, const char *fmt, ...);

extern int osnum;

static void
procfs_thread_ctl(struct thread *thread, int msg)
{
	struct ihk_ikc_channel_desc *syscall_channel;
	struct ikc_scd_packet packet;

	syscall_channel = cpu_local_var(ikc2linux);
	memset(&packet, '\0', sizeof packet);
	packet.arg = thread->tid;
	packet.msg = msg;
	packet.osnum = osnum;
	packet.ref = thread->cpu_id;
	packet.pid = thread->proc->pid;
	packet.err = 0;

	ihk_ikc_send(syscall_channel, &packet, 0);
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

/**
 * \brief The callback function for mckernel procfs files.
 *
 * \param rarg returned argument
 */
void process_procfs_request(struct ikc_scd_packet *rpacket)
{
	unsigned long rarg = rpacket->arg;
	unsigned long parg, pbuf;
	struct thread *thread = NULL;
	struct process *proc = NULL;
	struct process_vm *vm = NULL;
	struct procfs_read *r;
	struct ikc_scd_packet packet;
	int rosnum, ret, pid, tid, ans = -EIO, eof = 0;
	char *buf, *p;
	struct ihk_ikc_channel_desc *syscall_channel;
	struct mcs_rwlock_node_irqsave lock;
	unsigned long offset;
	int count;
	int npages;
	int readwrite = 0;

	dprintf("process_procfs_request: invoked.\n");

	syscall_channel = get_cpu_local_var(0)->ikc2linux;

	dprintf("rarg: %x\n", rarg);
	parg = ihk_mc_map_memory(NULL, rarg, sizeof(struct procfs_read));
	dprintf("parg: %x\n", parg);
	r = ihk_mc_map_virtual(parg, 1, PTATTR_WRITABLE | PTATTR_ACTIVE);
	if (r == NULL) {
		kprintf("ERROR: process_procfs_request: got a null procfs_read structure.\n");
		packet.err = -EIO;
		goto dataunavail;
	}
	dprintf("r: %p\n", r);

	dprintf("remote pbuf: %x\n", r->pbuf);
	pbuf = ihk_mc_map_memory(NULL, r->pbuf, r->count);
	dprintf("pbuf: %x\n", pbuf);
	count = r->count + ((uintptr_t)pbuf & (PAGE_SIZE - 1));
	npages = (count + (PAGE_SIZE - 1)) / PAGE_SIZE;
	buf = ihk_mc_map_virtual(pbuf, npages, PTATTR_WRITABLE | PTATTR_ACTIVE);
	dprintf("buf: %p\n", buf);
	if (buf == NULL) {
		kprintf("ERROR: process_procfs_request: got a null buffer.\n");
		packet.err = -EIO;
		goto bufunavail;
	}

	readwrite = r->readwrite;
	count = r->count;
	offset = r->offset;
	dprintf("fname: %s, offset: %lx, count:%d.\n", r->fname, r->offset, r->count);

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
	else if (!strcmp(p, "stat")) {	/* "/proc/stat" */
		extern int num_processors;	/* kernel/ap.c */
		char *p;
		size_t remain;
		int cpu;

		if (offset > 0) {
			ans = 0;
			eof = 1;
			goto end;
		}
		p = buf;
		remain = count;
		for (cpu = 0; cpu < num_processors; ++cpu) {
			size_t  n;

			n = snprintf(p, remain, "cpu%d\n", cpu);
			if (n >= remain) {
				ans = -ENOSPC;
				eof = 1;
				goto end;
			}
			p += n;
		}
		ans = p - buf;
		eof = 1;
		goto end;
	}
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

			if (pa < ihk_mc_get_memory_address(IHK_MC_GMA_MAP_START, 0) ||
					pa >= ihk_mc_get_memory_address(IHK_MC_GMA_MAP_END, 0)) {
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
		int left = r->count - 1; /* extra 1 for terminating NULL */
		int written = 0;
		char *_buf = buf;
		
		/* Starting from the middle of a proc file is not supported for maps */
		if (offset > 0) {
			ans = 0;
			eof = 1;
			goto end;
		}

		ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);

		list_for_each_entry(range, &vm->vm_range_list, list) {
			int written_now;

			/* format is (from man proc):
			 *  address           perms offset  dev   inode   pathname
			 *  08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
			 */
			written_now = snprintf(_buf, left, 
					"%lx-%lx %s%s%s%s %lx %lx:%lx %d %s\n",
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
					""
					);
			
			left -= written_now;
			_buf += written_now;
			written += written_now;

			if (left == 0) {
				kprintf("%s(): WARNING: buffer too small to fill proc/maps\n", 
						__FUNCTION__);
				break;
			}
		}
		
		ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
		
		ans = written + 1;
		eof = 1;
		goto end;
	}
	
	/*
	 * mcos%d/PID/pagemap
	 */
	if (strcmp(p, "pagemap") == 0) {
		uint64_t *_buf = (uint64_t *)buf;
		uint64_t start, end;
		
		if (offset < PAGE_SIZE) {
			kprintf("WARNING: /proc/pagemap queried for NULL page\n");
			ans = 0;
			goto end;
		}

		/* Check alignment */
		if ((offset % sizeof(uint64_t) != 0) || 
		    (count % sizeof(uint64_t) != 0)) {
			ans = 0;
			eof = 1;
			goto end;
		}

		start = (offset / sizeof(uint64_t)) << PAGE_SHIFT;
		end = start + ((count / sizeof(uint64_t)) << PAGE_SHIFT);
		
		ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);

		while (start < end) {
			*_buf = ihk_mc_pt_virt_to_pagemap(proc->vm->address_space->page_table, start);
			dprintf("PID: %d, /proc/pagemap: 0x%lx -> %lx\n",  proc->proc->pid, 
					start, *_buf);
			start += PAGE_SIZE;
			++_buf;
		}

		ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
		
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
		char *tmp;
		char *bitmasks;
		int bitmasks_offset = 0;
		char *cpu_bitmask, *cpu_list, *numa_bitmask, *numa_list;
		int len;

		tmp = kmalloc(8192, IHK_MC_AP_CRITICAL);
		if (!tmp) {
			kprintf("%s: error allocating /proc/self/status buffer\n",
				__FUNCTION__);
			ans = 0;
			goto end;
		}

		bitmasks = kmalloc(BITMASKS_BUF_SIZE, IHK_MC_AP_CRITICAL);
		if (!tmp) {
			kprintf("%s: error allocating /proc/self/status bitmaks buffer\n",
				__FUNCTION__);
			kfree(tmp);
			ans = 0;
			goto end;
		}

		ihk_mc_spinlock_lock_noirq(&proc->vm->memory_range_lock);
		list_for_each_entry(range, &proc->vm->vm_range_list, list) {
			if(range->flag & VR_LOCKED)
				lockedsize += range->end - range->start;
		}
		ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);

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

		sprintf(tmp,
		        "Uid:\t%d\t%d\t%d\t%d\n"
		        "Gid:\t%d\t%d\t%d\t%d\n"
		        "VmLck:\t%9lu kB\n"
				"Cpus_allowed:\t%s\n"
				"Cpus_allowed_list:\t%s\n"
				"Mems_allowed:\t%s\n"
				"Mems_allowed_list:\t%s\n",
		        proc->ruid, proc->euid, proc->suid, proc->fsuid,
		        proc->rgid, proc->egid, proc->sgid, proc->fsgid,
		        (lockedsize + 1023) >> 10,
				cpu_bitmask, cpu_list, numa_bitmask, numa_list);
		len = strlen(tmp);
		if (r->offset < len) {
			if (r->offset + r->count < len) {
				ans = r->count;
			} else {
				eof = 1;
				ans = len;
			}
			strncpy(buf, tmp + r->offset, ans);
		} else if (r->offset == len) {
			ans = 0;
			eof = 1;
		}
		kfree(tmp);
		kfree(bitmasks);
		goto end;
	}

	/* 
	 * mcos%d/PID/auxv
	 */
	if (strcmp(p, "auxv") == 0) {
		unsigned int limit = AUXV_LEN * sizeof(unsigned long);
		unsigned int len = r->count;
		if (r->offset < limit) {
			if (limit < r->offset + r->count) {
				len = limit - r->offset;
			}
			memcpy((void *)buf, ((char *) proc->saved_auxv) + r->offset, len);
			ans = len;
			if (r->offset + len == limit) {
				eof = 1;
			}
		} else if (r->offset == limit) {
			ans = 0;
			eof = 1;
		}
		goto end;
	}

	/* 
	 * mcos%d/PID/cmdline
	 */
	if (strcmp(p, "cmdline") == 0) {
		unsigned int limit = proc->saved_cmdline_len;
		unsigned int len = r->count;

		if(!proc->saved_cmdline){
			ans = 0;
			eof = 1;
			goto end;
		}

		if (r->offset < limit) {
			if (limit < r->offset + r->count) {
				len = limit - r->offset;
			}
			memcpy((void *)buf, ((char *) proc->saved_cmdline) + r->offset, len);
			ans = len;
			if (r->offset + len == limit) {
				eof = 1;
			}
		} else if (r->offset == limit) {
			ans = 0;
			eof = 1;
		}
		goto end;
	}

	/* 
	 * mcos%d/PID/taks/PID/mem
	 *
	 * The offset is treated as the beginning of the virtual address area
	 * of the process. The count is the length of the area.
	 */

	if (!strcmp(p, "stat")) {
		char tmp[1024];
		int len;

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
		ans = sprintf(tmp,
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
		    0, "exe", 'R', 0,	      // pid...
		    0, 0, 0, 0,      	      // pgrp...
		    0, 0L, 0L, 0L,	      // flags...
		    0L, 0L, 0L, 0L,	      // cmajflt...
		    0L, 0L, 0L, 0L,	      // cstime...
		    0L, 0LL, 0L, 0L,	      // itrealvalue...
		    0L, 0L, 0L, 0L,	      // rsslim...
		    0L, 0L, 0L, 0L,	      // kstkesp...
		    0L, 0L, 0L, 0L,	      // sigignore...
		    0L, 0, thread->cpu_id, 0, // cnswap...
		    0, 0LL, 0L, 0L	      // policy...
		);
		dprintf("tmp=%s\n", tmp);

		len = strlen(tmp);
		if (r->offset < len) {
			if (r->offset + r->count < len) {
				ans = r->count;
			} else {
				eof = 1;
				ans = len;
			}
			strncpy(buf, tmp + r->offset, ans);
		} else if (r->offset == len) {
			ans = 0;
			eof = 1;
		}
		goto end;
	}

	if(thread)
		kprintf("unsupported procfs entry: %d/task/%d/%s\n", pid, tid, p);
	else
		kprintf("unsupported procfs entry: %d/%s\n", pid, p);

end:
	ihk_mc_unmap_virtual(buf, npages, 0);
	dprintf("ret: %d, eof: %d\n", ans, eof);
	r->ret = ans;
	r->eof = eof;
	r->status = 1; /* done */
	packet.err = 0;
bufunavail:
	ihk_mc_unmap_memory(NULL, pbuf, r->count);
	ihk_mc_unmap_virtual(r, 1, 0);
dataunavail:
	ihk_mc_unmap_memory(NULL, parg, sizeof(struct procfs_read));

	packet.msg = SCD_MSG_PROCFS_ANSWER;
	packet.arg = rarg;
	packet.pid = rpacket->pid;

	ret = ihk_ikc_send(syscall_channel, &packet, 0);
	if (ret < 0) {
		kprintf("ERROR: sending IKC msg, ret: %d\n", ret);
	}
	if(proc)
		release_process(proc);
	if(thread)
		release_thread(thread);
	if(vm)
		release_process_vm(vm);
	return;

}

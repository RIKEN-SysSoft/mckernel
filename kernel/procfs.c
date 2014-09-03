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
#include <syscall.h>
#include <cls.h>
#include <kmalloc.h>
#include <process.h>
#include <page.h>
#include <mman.h>

#define DEBUG_PRINT_PROCFS

#ifdef DEBUG_PRINT_PROCFS
#define	dprintf(...) kprintf(__VA_ARGS__)
#else
#define dprintf(...)
#endif

extern int snprintf(char * buf, size_t size, const char *fmt, ...);
extern int sscanf(const char * buf, const char * fmt, ...);

extern int osnum;

void create_proc_procfs_files(int pid, int cpuid);
void delete_proc_procfs_files(int pid);
void create_os_procfs_files(void);
void delete_os_procfs_files(void);

static void create_proc_procfs_file(int pid, char *fname, int mode, int cpuid);
static void delete_proc_procfs_file(int pid, char *fname);
static void operate_proc_procfs_file(int pid, char *fname, int msg, int mode, int cpuid);

void create_proc_procfs_files(int pid, int cpuid)
{
	char fname[PROCFS_NAME_MAX];

	dprintf("create procfs files:\n");

	snprintf(fname, PROCFS_NAME_MAX, "mcos%d/%d/task/%d/mem", osnum, pid, pid);
	create_proc_procfs_file(pid, fname, 0400, cpuid);

	dprintf("create procfs files: done\n");
}

static void create_proc_procfs_file(int pid, char *fname, int mode, int cpuid)
{
	dprintf("create procfs file: %s, mode: %o, cpuid: %d\n", fname, mode, cpuid);
	operate_proc_procfs_file(pid, fname, SCD_MSG_PROCFS_CREATE, mode, cpuid);
}

void delete_proc_procfs_files(int pid)
{
	char fname[PROCFS_NAME_MAX];

	dprintf("delete procfs files\n");
	snprintf(fname, PROCFS_NAME_MAX, "mcos%d/%d/task/%d/mem", osnum, pid, pid);
	delete_proc_procfs_file(pid, fname);

	snprintf(fname, PROCFS_NAME_MAX, "mcos%d/%d/task/%d", osnum, pid, pid);
	delete_proc_procfs_file(pid, fname);

	snprintf(fname, PROCFS_NAME_MAX, "mcos%d/%d/task", osnum, pid);
	delete_proc_procfs_file(pid, fname);

	snprintf(fname, PROCFS_NAME_MAX, "mcos%d/%d", osnum, pid);
	delete_proc_procfs_file(pid, fname);

	/* CAVEAT: deleting mcos%d level procfs directory should be located 
	   in delete_mckernel_procfs_files().*/
	snprintf(fname, PROCFS_NAME_MAX, "mcos%d", osnum);
	delete_proc_procfs_file(pid, fname);

	dprintf("delete procfs files: done\n");
}

static void delete_proc_procfs_file(int pid, char *fname)
{
	dprintf("delete procfs file: %s\n", fname);
	operate_proc_procfs_file(pid, fname, SCD_MSG_PROCFS_DELETE, 0, 0);
	dprintf("delete procfs file: %s done\n", fname);
}

static void operate_proc_procfs_file(int pid, char *fname, int msg, int mode, int cpuid)
{
	struct ihk_ikc_channel_desc *syscall_channel;
	struct ikc_scd_packet pckt;
	struct procfs_file *f;
	int ret;

	syscall_channel = get_cpu_local_var(0)->syscall_channel;

	f = kmalloc(sizeof(struct procfs_file), IHK_MC_AP_NOWAIT);
	if (!f) {
		kprintf("ERROR: not enough memory for dealing procfs file %s!",
			fname);
		return;
	}
	f->status = 0;
	f->mode = mode;
	strncpy(f->fname, fname, PROCFS_NAME_MAX);
	pckt.arg = virt_to_phys(f);
	pckt.msg = msg;
	pckt.osnum = osnum;
	pckt.ref = cpuid;
	pckt.pid = pid;
	pckt.err = 0;

	ret = ihk_ikc_send(syscall_channel, &pckt, 0);
	if (ret < 0) {
		kprintf("ERROR: sending IKC msg, ret: %d\n", ret);
	}

	while (f->status != 1) {
		cpu_pause();
	}
	kfree(f);
}

void process_procfs_request(unsigned long rarg)
{
	unsigned long parg, pbuf;
        struct process *proc = cpu_local_var(current);
	struct procfs_read *r;
	struct ikc_scd_packet packet;
	int rosnum, ret, pid, tid, ans = -ENOENT, eof = 0;
	char *buf;
	struct ihk_ikc_channel_desc *syscall_channel;

	dprintf("process_procfs_request: invoked.\n");

	syscall_channel = get_cpu_local_var(0)->syscall_channel;

	parg = ihk_mc_map_memory(NULL, rarg, sizeof(struct procfs_read));
	r = ihk_mc_map_virtual(parg, sizeof(struct procfs_read), 
			       PTATTR_WRITABLE | PTATTR_ACTIVE);

	pbuf = ihk_mc_map_memory(NULL, r->pbuf, r->count);
	buf = ihk_mc_map_virtual(pbuf, r->count, PTATTR_WRITABLE | PTATTR_ACTIVE);

	dprintf("fname: %s, offset: %lx, count:%d.\n", r->fname, r->offset, r->count);

	/* mcos0/PID/taks/PID/mem
	 *
	 * The offset is treated as the beginning of the virtual address area
	 * of the process. The count is the length of the area.
	 */
	ret = sscanf(r->fname, "mcos%d/%d/task/%d/mem", &rosnum, &pid, &tid);
	if ((ret == 3) && (pid == tid) && (osnum == rosnum)) {
		if (cpu_local_var(current)->pid != pid) {
			/* The target process has gone by migration. */
#ifdef FIXME
			r->newcpu = ...
#endif
			ans = 0;
		} else {
			struct vm_range *range;
			struct process_vm *vm = proc->vm;
			ans = -EIO; /* default to an I/O error */
			list_for_each_entry(range, &vm->vm_range_list, list) {
				dprintf("range: %lx - %lx\n", range->start, range->end);
				if ((range->start <= r->offset) && 
				    (r->offset < range->end)) {
					unsigned int len = r->count;
					if (range->end < r->offset + r->count) {
						len = range->end - r->offset;
					}
					memcpy((void *) buf, (void *)range->start, len);
					ans = len;
					break;
				}
			}
		}
		goto end;
	}

	/* Processing of other kinds of procfs files should be located here.
	   Its template is something like what follows:

	   ret = scanf(r->fname, "mcos%d/PATTERN", ...)
	   if ((ret == x) && pattern has matched) {
	   	get the data and write it to the buffer;
		ans = written bytes;
		goto end;
	   }
	*/

end:
	dprintf("read: %d, eof: %d\n", ans, eof);
	r->ret = ans;
	r->eof = eof;
	packet.msg = SCD_MSG_PROCFS_ANSWER;
	packet.arg = rarg;
	
	ihk_mc_unmap_virtual(buf, r->count, 0);
	ihk_mc_unmap_memory(NULL, pbuf, r->count);

	ihk_mc_unmap_virtual(r, sizeof(struct procfs_read), 0);
	ihk_mc_unmap_memory(NULL, parg, sizeof(struct procfs_read));

	ret = ihk_ikc_send(syscall_channel, &packet, 0);
	if (ret < 0) {
		kprintf("ERROR: sending IKC msg, ret: %d\n", ret);
	}
}

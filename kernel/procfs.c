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
#define dkprintf kprintf
#else
#define dkprintf(...)
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

	snprintf(fname, PROCFS_NAME_MAX, "/proc/mcos%d/%d/mem", osnum, pid);
	create_proc_procfs_file(pid, fname, 0400, cpuid);
}

static void create_proc_procfs_file(int pid, char *fname, int mode, int cpuid)
{
	operate_proc_procfs_file(pid, fname, SCD_MSG_PROCFS_CREATE, mode, cpuid);
}

void delete_proc_procfs_files(int pid)
{
	char fname[PROCFS_NAME_MAX];

	snprintf(fname, PROCFS_NAME_MAX, "/proc/mcos%d/%d/mem", osnum, pid);
	delete_proc_procfs_file(pid, fname);
}

static void delete_proc_procfs_file(int pid, char *fname)
{
	operate_proc_procfs_file(pid, fname, SCD_MSG_PROCFS_DELETE, 0, 0);
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

	syscall_channel = get_cpu_local_var(0)->syscall_channel;

	parg = ihk_mc_map_memory(NULL, rarg, sizeof(struct procfs_read));
	r = ihk_mc_map_virtual(parg, sizeof(struct procfs_read), 
			       PTATTR_WRITABLE | PTATTR_ACTIVE);

	pbuf = ihk_mc_map_memory(NULL, r->pbuf, r->count);
	buf = ihk_mc_map_virtual(pbuf, r->count, PTATTR_WRITABLE | PTATTR_ACTIVE);

	/* mcos0/PID/taks/PID/mem */
	ret = sscanf(r->fname, "mcos%d/%d/task/%d/mem", &rosnum, &pid, &tid);
	if ((ret == 3) && (pid == tid) && (osnum == rosnum)) {
		if (cpu_local_var(current)->pid != pid) {
			/* A hit-miss caused by migration */ 
			ans = 0;
		} else {
			struct vm_range *range;
			struct process_vm *vm = proc->vm;
			ans = -EIO; /* default to an I/O error */
			list_for_each_entry(range, &vm->vm_range_list, list) {
				if ((range->start <= r->offset) && 
				    (r->offset <= range->end)) {
					if (r->offset + r->count <= range->end) {
						memcpy((void *) buf, (void *) range->start, r->count);
						ans = r->count;
					} else {
						unsigned int remain;
						remain = range->end - r->offset;
						memcpy((void *) buf, (void *)range->start, remain);
						ans = remain;
					}
					break;
				}
			}
		}
		goto skip;
	}

skip:
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

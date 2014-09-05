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

//#define DEBUG_PRINT_PROCFS

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

/**
 * \brief Create all procfs files for process.
 *
 * \param pid pid of the process
 * \param cpuid cpuid of the process
 */

void create_proc_procfs_files(int pid, int cpuid)
{
	char fname[PROCFS_NAME_MAX];

	dprintf("create procfs files:\n");

	snprintf(fname, PROCFS_NAME_MAX, "mcos%d/%d/auxv", osnum, pid);
	create_proc_procfs_file(pid, fname, 0400, cpuid);

	snprintf(fname, PROCFS_NAME_MAX, "mcos%d/%d/task/%d/mem", osnum, pid, pid);
	create_proc_procfs_file(pid, fname, 0400, cpuid);

	dprintf("create procfs files: done\n");
}

/**
 * \brief Create a procfs file for process.
 *
 * \param pid pid of the process
 * \param fname file name of the procfs file
 * \param mode file mode
 * \param cpuid cpuid of the process
 */

static void create_proc_procfs_file(int pid, char *fname, int mode, int cpuid)
{
	dprintf("create procfs file: %s, mode: %o, cpuid: %d\n", fname, mode, cpuid);
	operate_proc_procfs_file(pid, fname, SCD_MSG_PROCFS_CREATE, mode, cpuid);
}

/**
 * \brief Delete all procfs files for process.
 *
 * \param pid pid of the process
 */

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

	snprintf(fname, PROCFS_NAME_MAX, "mcos%d/%d/auxv", osnum, pid);
	delete_proc_procfs_file(pid, fname);

	snprintf(fname, PROCFS_NAME_MAX, "mcos%d/%d", osnum, pid);
	delete_proc_procfs_file(pid, fname);

	/* CAVEAT: deleting mcos%d level procfs directory should be located 
	   in delete_mckernel_procfs_files().*/
	snprintf(fname, PROCFS_NAME_MAX, "mcos%d", osnum);
	delete_proc_procfs_file(pid, fname);

	dprintf("delete procfs files: done\n");
}

/**
 * \brief Delete a procfs file for process.
 *
 * \param pid pid of the process
 * \param fname file name of the procfs file
 */

static void delete_proc_procfs_file(int pid, char *fname)
{
	dprintf("delete procfs file: %s\n", fname);
	operate_proc_procfs_file(pid, fname, SCD_MSG_PROCFS_DELETE, 0, 0);
	dprintf("delete procfs file: %s done\n", fname);
}

/**
 * \brief Create/delete a procfs file for process.
 *
 * \param pid pid of the process
 * \param fname file name of the procfs file
 * \param msg message (create/delete) 
 * \param mode file mode
 * \param cpuid cpuid of the process
 */

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

/**
 * \brief The callback function for mckernel procfs files.
 *
 * \param rarg returned argument
 */

void process_procfs_request(unsigned long rarg)
{
	unsigned long parg, pbuf;
        struct process *proc = cpu_local_var(current);
	struct procfs_read *r;
	struct ikc_scd_packet packet;
	int rosnum, ret, pid, tid, ans = -EIO, eof = 0;
	char *buf, *p;
	struct ihk_ikc_channel_desc *syscall_channel;

	dprintf("process_procfs_request: invoked.\n");

	syscall_channel = get_cpu_local_var(0)->syscall_channel;

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
	buf = ihk_mc_map_virtual(pbuf, 1, PTATTR_WRITABLE | PTATTR_ACTIVE);
	dprintf("buf: %p\n", buf);
	if (buf == NULL) {
		kprintf("ERROR: process_procfs_request: got a null buffer.\n");
		packet.err = -EIO;
		goto bufunavail;
	}

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
		if (pid != cpu_local_var(current)->pid) {
			/* We are not located in the proper cpu for some reason. */
			void *savelock;
			unsigned long irqstate;
			struct process *proc;

			dprintf("mismatched pid. We are %d, but requested pid is %d.\n",
				pid, cpu_local_var(current)->pid);
			if ((proc = findthread_and_lock(pid, tid, &savelock, &irqstate))){
				/* The target process has gone by migration. */
				r->newcpu = proc->cpu_id;
				dprintf("expected cpu id is %d.\n", proc->cpu_id);
				process_unlock(savelock, irqstate);
				ans = 0;
			} else {
				dprintf("We cannot find the proper cpu for requested pid.\n");
			}
			goto end;
		}
	} else {
		goto end;
	}
	dprintf("matched PID: %d.\n", pid);
	p = strchr(p, '/') + 1;

	/* 
	 * mcos%d/PID/auxv
	 */
	if (strcmp(p, "auxv") == 0) {
		unsigned int limit = AUXV_LEN * sizeof(int);
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
		}
		goto end;
	}

	/* 
	 * mcos%d/PID/taks/PID/mem
	 *
	 * The offset is treated as the beginning of the virtual address area
	 * of the process. The count is the length of the area.
	 */
	ret = sscanf(p, "task/%d/mem", &tid);
	if (ret == 1) {
		struct vm_range *range;
		struct process_vm *vm = proc->vm;

		if (pid != tid) {
			/* We are not multithreaded yet. */
			goto end;
		} 
		list_for_each_entry(range, &vm->vm_range_list, list) {
			dprintf("range: %lx - %lx\n", range->start, range->end);
			if ((range->start <= r->offset) && 
			    (r->offset < range->end)) {
				unsigned int len = r->count;
				if (range->end < r->offset + r->count) {
					len = range->end - r->offset;
				}
				memcpy((void *)buf, (void *)range->start, len);
				ans = len;
				break;
			}
		}
		goto end;
	}

	/* 
	 * Processing for pattern "mcos%d/PID/xxx" files should be here.
	*/
	dprintf("could not find a matching entry for %s.\n", p); 
end:
	ihk_mc_unmap_virtual(buf, 1, 0);
	dprintf("ret: %d, eof: %d\n", ans, eof);
	r->ret = ans;
	r->eof = eof;
	packet.err = 0;
bufunavail:
	ihk_mc_unmap_memory(NULL, pbuf, r->count);
	ihk_mc_unmap_virtual(r, 1, 0);
dataunavail:
	ihk_mc_unmap_memory(NULL, parg, sizeof(struct procfs_read));

	packet.msg = SCD_MSG_PROCFS_ANSWER;
	packet.arg = rarg;

	ret = ihk_ikc_send(syscall_channel, &packet, 0);
	if (ret < 0) {
		kprintf("ERROR: sending IKC msg, ret: %d\n", ret);
	}
	return;

}

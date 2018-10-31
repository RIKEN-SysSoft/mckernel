/* mckernel.c - crash extension for mckernel
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "defs.h"

static int mck_loaded;
static struct mck_symbol_table {
	ulong clv;
	ulong init_pt;
	ulong mck_num_processors;
	ulong num_processors;
	ulong boot_param_pa;
	ulong boot_param;
	ulong kmsg_buf;
	ulong boot_param_boot_sec;
	ulong boot_param_boot_nsec;
} mck_symbol_table;
static struct mck_offset_table {
	long clv_idle;
	long clv_current;
	long clv_runq;
	long clv_resource_set;
	long boot_param_msg_buffer;
	long boot_param_boot_sec;
	long boot_param_boot_nsec;
	long resource_set_thread_hash;
	long thread_tid;
	long thread_status;
	long thread_vm;
	long thread_proc;
	long thread_hash_list;
	long thread_sched_list;
	long process_pid;
	long process_ppid_parent;
	long process_saved_cmdline;
	long process_saved_cmdline_len;
	long address_space_page_table;
	long process_vm_address_space;
	long process_vm_region;
	long process_vm_vdso_addr;
	long process_vm_vvar_addr;
	long process_vm_vm_range_tree;
	long vm_regions_brk_start;
	long vm_regions_brk_end_allocated;
	long vm_range_vm_rb_node;
	long vm_range_start;
	long vm_range_end;
	long vm_range_flag;
	long vm_range_memobj;
	long memobj_path;
	long kmsg_buf_str;
	long kmsg_buf_head;
	long kmsg_buf_tail;
	long kmsg_buf_len;
} mck_offset_table;
static struct mck_size_table {
	long clv;
} mck_size_table;

#define MCK_SYMBOL(X) (SYMBOL_verify(mck_symbol_table.X, \
		       (char *)__func__, __FILE__, __LINE__, #X))
#define MCK_MEMBER_OFFSET(X) (OFFSET_verify(mck_offset_table.X, \
			      (char *)__func__, __FILE__, __LINE__, #X))
#define MCK_SIZE(X) (SIZE_verify(mck_size_table.X, \
		     (char *)__func__, __FILE__, __LINE__, #X))
#define MCK_ASSIGN_SYMBOL(X) (mck_symbol_table.X)
#define MCK_ASSIGN_OFFSET(X) (mck_offset_table.X)
#define MCK_ASSIGN_SIZE(X) (mck_size_table.X)
#define MCK_SYMBOL_INIT(X) (MCK_ASSIGN_SYMBOL(X) = get_symbol_value(#X))
#define MCK_MEMBER_OFFSET_INIT(X, Y, Z) (MCK_ASSIGN_OFFSET(X) = MEMBER_OFFSET(Y, Z))
#define MCK_SIZE_INIT(X, Y) (MCK_ASSIGN_SIZE(X) = STRUCT_SIZE(Y))


/* helpers - symbol helpers */

/* Get symbol from gdb, do this once at init
 * Inspired from anon_member_offset
 */
static ulong
get_symbol_value(char *name)
{
	char buf[BUFSIZE];
	ulong value;

	value = -1;
	sprintf(buf, "printf \"%%p\", &%s", name);
	open_tmpfile2();
	if (gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR|QUIET)) {
		rewind(pc->tmpfile2);
		if (fgets(buf, BUFSIZE, pc->tmpfile2)) {
			if (hexadecimal(buf, 0))
				value = htol(buf, RETURN_ON_ERROR|QUIET, NULL);
			else if (STRNEQ(buf, "(nil)"))
				value = 0;
		}
		if (value > 0 &&
		    !readmem(value, KVADDR, &value, sizeof(value),
			     "symbol value", RETURN_ON_ERROR|QUIET)) {
			value = -1;
		}
	}

	close_tmpfile2();

	/* adjust symbols in MAP_ST_START */
	if (value < 0xffff810000000000UL && value >= 0xffff800000000000UL) {
		value += 0x80000000000UL;
	}

	return value;
}

/* copy of datatype_error - cannot use static function */
static void
datatype_error(void **retaddr, char *errmsg, char *func, char *file, int line)
{
	char buf[BUFSIZE];
	int fd;

	fprintf(stderr, "\n%s: %s\n", pc->curcmd, errmsg);
	fprintf(stderr, "%s  FILE: %s  LINE: %d  FUNCTION: %s()\n\n",
			space(strlen(pc->curcmd)), file, line, func);
	fflush(stderr);

	dump_trace(retaddr);

	if (pc->flags & TTY) {
		if ((fd = open("/dev/tty", O_RDONLY)) >= 0) {
			tcsetattr(fd, TCSANOW, &pc->termios_orig);
			close(fd);
		}
	}

	if (pc->flags & DROP_CORE)
		drop_core("DROP_CORE flag set: forcing a segmentation fault\n");

	if (CRASHDEBUG(1))
		gdb_readnow_warning();

	if (pc->flags & RUNTIME) {
		sprintf(buf, "%s\n%s  FILE: %s  LINE: %d  FUNCTION: %s()\n",
				errmsg, space(strlen(pc->curcmd)), file, line, func);
		error(FATAL, "%s\n", buf);
	}

	exit(1);
}

#define LINUX_PAGE_OFFSET 0xffff880000000000UL
static inline ulong phys_to_virt(ulong phys)
{
	return phys + LINUX_PAGE_OFFSET;
}

/* basically copy of OFFSET_verify */
static ulong
SYMBOL_verify(ulong value, char *func, char *file, int line, char *item)
{
	char errmsg[BUFSIZE];

	if (!(pc->flags & DATADEBUG))
		return value;

	if (value == (ulong)(-1L)) {
		void *retaddr[NUMBER_STACKFRAMES] = { 0 };

		SAVE_RETURN_ADDRESS(retaddr);
		sprintf(errmsg, "invalid symbol value: %s",
				item);
		datatype_error(retaddr, errmsg, func, file, line);
	}
	return value;
}


/* helper - mck_str_to_context: find thread from pid */

#define HASH_SIZE 73
struct mck_str_to_context_listcb_wrapper {
	ulong pid;
	ulong thread;
};

static int
mck_str_to_context_listcb(void *_thread, void *data)
{
	ulong thread = (ulong)_thread;
	int tid;
	struct mck_str_to_context_listcb_wrapper *wrap = data;

	if (readmem(thread + MCK_MEMBER_OFFSET(thread_tid), KVADDR,
		    &tid, sizeof(int), "thread_tid",
		    RETURN_ON_ERROR|QUIET) && tid == wrap->pid) {
		wrap->thread = thread;
		return TRUE;
	}
	return FALSE;
}

static int
lookup_pid(ulong pid, ulong thash, ulong *thread)
{
	struct mck_str_to_context_listcb_wrapper wrap = { 0 };
	struct list_data ld = {
		.flags = LIST_HEAD_FORMAT | LIST_HEAD_POINTER |
			LIST_CALLBACK | CALLBACK_RETURN,
		.list_head_offset = MCK_MEMBER_OFFSET(thread_hash_list),
		.callback_func = mck_str_to_context_listcb,
		.callback_data = &wrap,
	};
	wrap.pid = pid;
	ld.end = thash + (pid % HASH_SIZE) * SIZE(list_head);
	if (readmem(ld.end, KVADDR, &ld.start, sizeof(ld.start), "first list element",
				RETURN_ON_ERROR|QUIET) && ld.start != ld.end) {
		do_list(&ld);
		if (wrap.thread) {
			if (thread)
				*thread = wrap.thread;
			return TRUE;
		}
	}
	return FALSE;
}

static int
mck_str_to_context(char *string, ulong *pid, ulong *thread)
{
	ulong dvalue, hvalue;
	ulong rset, thash;
	char *s;

	if (string == NULL) {
		error(INFO, "received NULL string\n");
		return STR_INVALID;
	}

	s = string;
	dvalue = hvalue = BADADDR;

	if (decimal(s, 0))
		dvalue = dtol(s, RETURN_ON_ERROR|QUIET, NULL);

	if (hexadecimal(s, 0))
		hvalue = htol(s, RETURN_ON_ERROR|QUIET, NULL);

	if (readmem(MCK_SYMBOL(clv) + MCK_MEMBER_OFFSET(clv_resource_set),
		    KVADDR, &rset, sizeof(rset), "clv resource_set",
		    RETURN_ON_ERROR|QUIET) &&
	    readmem(rset + MCK_MEMBER_OFFSET(resource_set_thread_hash), KVADDR,
		    &thash, sizeof(thash), "rset thread hash",
		    RETURN_ON_ERROR|QUIET)) {
		if (dvalue != BADADDR) {
			if (lookup_pid(dvalue, thash, thread)) {
				if (pid)
					*pid = dvalue;
				return STR_PID;
			}
		}
		if (hvalue != BADADDR) {
			if (lookup_pid(hvalue, thash, thread)) {
				if (pid)
					*pid = hvalue;
				return STR_PID;
			}
		}
	}

	if (hvalue != BADADDR) {
		int tid;

		if (readmem(hvalue + MCK_MEMBER_OFFSET(thread_tid), KVADDR,
			    &tid, sizeof(int), "thread tid",
			    RETURN_ON_ERROR|QUIET)) {
			if (thread)
				*thread = hvalue;
			if (pid)
				*pid = tid;
			return STR_TASK;
		}
	}

	return STR_INVALID;
}


/* helper - Check if mckernel rebooted */

static void
mckernel_refresh_symbols(int fatal)
{
	ulong boot_param_pa, boot_param;
	ulong boot_param_boot_sec, boot_param_boot_nsec;

	boot_param_pa = get_symbol_value("boot_param_pa");
	if (boot_param_pa == -1UL) {
		if (!fatal)
			return;
		error(FATAL,
		      "Could not read mckernel symbol values - is it booted?\n");
	}
	MCK_MEMBER_OFFSET_INIT(boot_param_boot_sec, "struct smp_boot_param",
			       "boot_sec");
	MCK_MEMBER_OFFSET_INIT(boot_param_boot_nsec, "struct smp_boot_param",
			       "boot_nsec");
	boot_param = phys_to_virt(boot_param_pa);
	if (!readmem(boot_param + MCK_MEMBER_OFFSET(boot_param_boot_sec),
		     KVADDR, &boot_param_boot_sec, sizeof(ulong),
		     "boot_sec", RETURN_ON_ERROR|QUIET) ||
	    !readmem(boot_param + MCK_MEMBER_OFFSET(boot_param_boot_nsec),
		     KVADDR, &boot_param_boot_nsec, sizeof(ulong),
		     "boot_nsec", RETURN_ON_ERROR|QUIET)) {
		if (!fatal)
			return;
		error(FATAL,
		      "Could not read mckernel symbol values - is it booted?\n");
	}

	MCK_MEMBER_OFFSET_INIT(clv_idle, "struct cpu_local_var", "idle");
	MCK_MEMBER_OFFSET_INIT(clv_current, "struct cpu_local_var", "current");
	MCK_MEMBER_OFFSET_INIT(clv_runq, "struct cpu_local_var", "runq");
	MCK_MEMBER_OFFSET_INIT(clv_resource_set, "struct cpu_local_var",
			       "resource_set");
	MCK_MEMBER_OFFSET_INIT(boot_param_msg_buffer, "struct smp_boot_param",
			       "msg_buffer");
	MCK_MEMBER_OFFSET_INIT(resource_set_thread_hash, "struct resource_set",
			       "thread_hash");
	MCK_MEMBER_OFFSET_INIT(thread_tid, "struct thread", "tid");
	MCK_MEMBER_OFFSET_INIT(thread_status, "struct thread", "status");
	MCK_MEMBER_OFFSET_INIT(thread_vm, "struct thread", "vm");
	MCK_MEMBER_OFFSET_INIT(thread_proc, "struct thread", "proc");
	MCK_MEMBER_OFFSET_INIT(thread_hash_list, "struct thread",
			       "hash_list");
	MCK_MEMBER_OFFSET_INIT(thread_sched_list, "struct thread",
			       "sched_list");
	MCK_MEMBER_OFFSET_INIT(process_pid, "struct process", "pid");
	MCK_MEMBER_OFFSET_INIT(process_ppid_parent, "struct process",
			       "ppid_parent");
	MCK_MEMBER_OFFSET_INIT(process_saved_cmdline, "struct process",
			       "saved_cmdline");
	MCK_MEMBER_OFFSET_INIT(process_saved_cmdline_len, "struct process",
			       "saved_cmdline_len");
	/* struct address_space conflicts with a linux type, hardcode */
	MCK_ASSIGN_OFFSET(address_space_page_table) = 0;
	MCK_MEMBER_OFFSET_INIT(process_vm_address_space, "struct process_vm",
			       "address_space");
	MCK_MEMBER_OFFSET_INIT(process_vm_region, "struct process_vm",
			       "region");
	MCK_MEMBER_OFFSET_INIT(process_vm_vdso_addr, "struct process_vm",
			       "vdso_addr");
	MCK_MEMBER_OFFSET_INIT(process_vm_vvar_addr, "struct process_vm",
			       "vvar_addr");
	MCK_MEMBER_OFFSET_INIT(process_vm_vm_range_tree, "struct process_vm",
			       "vm_range_tree");
	MCK_MEMBER_OFFSET_INIT(vm_regions_brk_start, "struct vm_regions",
			       "brk_start");
	MCK_MEMBER_OFFSET_INIT(vm_regions_brk_end_allocated, "struct vm_regions",
			       "brk_end_allocated");
	MCK_MEMBER_OFFSET_INIT(vm_range_vm_rb_node, "struct vm_range", "vm_rb_node");
	MCK_MEMBER_OFFSET_INIT(vm_range_start, "struct vm_range", "start");
	MCK_MEMBER_OFFSET_INIT(vm_range_end, "struct vm_range", "end");
	MCK_MEMBER_OFFSET_INIT(vm_range_flag, "struct vm_range", "flag");
	MCK_MEMBER_OFFSET_INIT(vm_range_memobj, "struct vm_range", "memobj");
	MCK_MEMBER_OFFSET_INIT(memobj_path, "struct memobj", "path");
	MCK_MEMBER_OFFSET_INIT(kmsg_buf_str, "struct ihk_kmsg_buf", "str");
	MCK_MEMBER_OFFSET_INIT(kmsg_buf_head, "struct ihk_kmsg_buf", "head");
	MCK_MEMBER_OFFSET_INIT(kmsg_buf_tail, "struct ihk_kmsg_buf", "tail");
	MCK_MEMBER_OFFSET_INIT(kmsg_buf_len, "struct ihk_kmsg_buf", "len");

	MCK_SIZE_INIT(clv, "struct cpu_local_var");

	/* use assign to avoid error the first time (unset) */
	if (MCK_ASSIGN_SYMBOL(boot_param_pa) == boot_param_pa &&
	    MCK_ASSIGN_SYMBOL(boot_param_boot_sec) == boot_param_boot_sec &&
	    MCK_ASSIGN_SYMBOL(boot_param_boot_nsec) == boot_param_boot_nsec)
		return;

	MCK_ASSIGN_SYMBOL(boot_param_pa) = boot_param_pa;
	MCK_ASSIGN_SYMBOL(boot_param) = boot_param;
	MCK_ASSIGN_SYMBOL(boot_param_boot_sec) = boot_param_boot_sec;
	MCK_ASSIGN_SYMBOL(boot_param_boot_nsec) = boot_param_boot_nsec;

	MCK_SYMBOL_INIT(clv);
	MCK_SYMBOL_INIT(init_pt);
	MCK_SYMBOL_INIT(mck_num_processors);
	if (!readmem(MCK_SYMBOL(mck_num_processors), KVADDR,
		     &MCK_ASSIGN_SYMBOL(num_processors), sizeof(int),
		     "mck_num_processors", RETURN_ON_ERROR|QUIET)) {
		error(FATAL, "Could not read mckernel num_processors value");
	}
	if (!readmem(MCK_SYMBOL(boot_param) +
				MCK_MEMBER_OFFSET(boot_param_msg_buffer),
		     KVADDR, &MCK_ASSIGN_SYMBOL(kmsg_buf), sizeof(ulong),
		     "kmsg_buf", RETURN_ON_ERROR|QUIET)) {
		error(FATAL, "Could not read kmsg_buf address");
	}
	MCK_ASSIGN_SYMBOL(kmsg_buf) = phys_to_virt(MCK_SYMBOL(kmsg_buf));
}


/* mcsymbols */

static void
cmd_mcsymbols(void)
{
	char buf[BUFSIZ], *filename;
	int c;
	int verbose = 0;

	while ((c = getopt(argcnt, args, "v")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	filename = args[optind];
	if (!filename)
		error(FATAL, "No file given");
	if (lstat(filename, (struct stat *)buf) < 0)
		error(FATAL, "Error on lstat(%s): %m", filename);

	snprintf(buf, BUFSIZ, "add-symbol-file %s 0", filename);

	fprintf(fp, "Loading symbols from %s...", filename);
	st->flags |= ADD_SYMBOL_FILE;
	c = gdb_pass_through(buf, verbose ? NULL : pc->nullfp,
			     GNU_RETURN_ON_ERROR|QUIET);
	st->flags &= ~ADD_SYMBOL_FILE;

	/* gdb command failed */
	if (c == FALSE) {
		fprintf(fp, " FAILED - rerun with -v for error\n");
		return;
	}

	mckernel_refresh_symbols(0);

	mck_loaded = TRUE;
	fprintf(fp, " OK.\n");
}

static char *help_mcsymbols[] = {
	"mcsymbols",
	"Load mckernel symbols from kernel file",
	"[-v] path",

	"  This command loads symbols from the mckernel kernel file",
	"\nEXAMPLE\n",
	"    crash> mcsymbols /path/to/mckernel.img",
	"    add symbol table from file \"/path/to/mckernel.img\" at",
	"            .text_addr = 0x0",
	"    Reading symbols from /path/to/mckernel.img...done.",
	"    ",
	"    McKernel symbols loaded A-OK!",
	NULL
};


/* mcps */

#define PS_RUNNING           0x1
#define PS_INTERRUPTIBLE     0x2
#define PS_UNINTERRUPTIBLE   0x4
#define PS_ZOMBIE            0x8
#define PS_EXITED            0x10
#define PS_STOPPED           0x20

static int
mcps_print_one(ulong thread, int cpu, int is_active, int is_idle)
{
	ulong proc, parent_proc, tmp;
	int tid = 0, ppid = 0, status;
	long saved_cmdline_len;
	char *saved_cmdline, *comm = is_idle ? "idle" : "";
	char *status_st;

	if (!is_idle)
		readmem(thread + MCK_MEMBER_OFFSET(thread_tid), KVADDR,
			&tid, sizeof(int), "thread_tid",
			RETURN_ON_ERROR);
	readmem(thread + MCK_MEMBER_OFFSET(thread_status), KVADDR,
		&status, sizeof(ulong), "thread_status",
		RETURN_ON_ERROR);
	switch (status) {
	case PS_RUNNING:
		status_st = "RU";
		break;
	case PS_INTERRUPTIBLE:
		status_st = "IN";
		break;
	case PS_UNINTERRUPTIBLE:
		status_st = "UN";
		break;
	case PS_ZOMBIE:
		status_st = "Z";
		break;
	case PS_STOPPED:
		status_st = "T";
		break;
	default:
		status_st = "??";
		break;
	}
	readmem(thread + MCK_MEMBER_OFFSET(thread_proc), KVADDR,
		&proc, sizeof(ulong), "thread_proc",
		RETURN_ON_ERROR);
	readmem(proc + MCK_MEMBER_OFFSET(process_saved_cmdline_len),
		KVADDR, &saved_cmdline_len, sizeof(long),
		"process saved_cmdline_len", RETURN_ON_ERROR);
	if (saved_cmdline_len) {
		saved_cmdline = GETBUF(saved_cmdline_len);
		readmem(proc + MCK_MEMBER_OFFSET(process_saved_cmdline),
			KVADDR, &tmp, sizeof(ulong),
			"process saved_cmdline address",
			RETURN_ON_ERROR);
		readmem(tmp, KVADDR,
			saved_cmdline, saved_cmdline_len,
			"process saved_cmdline", RETURN_ON_ERROR);
		comm = strrchr(saved_cmdline, '/');
		if (comm)
			comm++;
		else
			comm = saved_cmdline;
	}
	readmem(proc + MCK_MEMBER_OFFSET(process_ppid_parent), KVADDR,
		&parent_proc, sizeof(ulong), "process_ppid_parent",
		RETURN_ON_ERROR);
	if (parent_proc) {
		readmem(parent_proc + MCK_MEMBER_OFFSET(process_pid), KVADDR,
			&ppid, sizeof(int), "parent process_pid",
			RETURN_ON_ERROR);
	}

	fprintf(fp, "%s%6d %6d %3d %016lx %2s %s\n",
		is_active ? ">" : " ",
		tid, ppid, cpu, thread,
		status_st, comm);
	if (saved_cmdline_len)
		FREEBUF(saved_cmdline);

	return 0;
}

struct mcps_listcb_wrapper {
	ulong running_thr;
	int cpu;
};

static int
mcps_print_one_listcb(void *_thread, void *_data)
{
	struct mcps_listcb_wrapper *data = _data;
	ulong thread = (ulong)_thread;

	if (thread == data->running_thr)
		return 0;

	return mcps_print_one(thread, data->cpu, 0, 0);
}

static void
cmd_mcps(void)
{
	int c, cpu;

	if (!mck_loaded)
		error(FATAL, "You must run mcsymbols first");
	mckernel_refresh_symbols(1);

	while ((c = getopt(argcnt, args, "")) != EOF) {
		switch (c) {
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	fprintf(fp, " %6s %6s %3s %-16s %2s %s\n",
	       "PID", "PPID", "CPU", "THREAD", "ST", "COMM");
	for (cpu = 0; cpu < MCK_SYMBOL(num_processors); cpu++) {
		ulong clv = MCK_SYMBOL(clv) + cpu * MCK_SIZE(clv);
		ulong thread, idle_thread;
		struct list_data ld = {
			.flags = LIST_HEAD_FORMAT | LIST_HEAD_POINTER |
				 LIST_CALLBACK,
			.end = clv + MCK_MEMBER_OFFSET(clv_runq),
			.list_head_offset = MCK_MEMBER_OFFSET(thread_sched_list),
			.callback_func = mcps_print_one_listcb,
		};
		struct mcps_listcb_wrapper cb_data;

		idle_thread = clv + MCK_MEMBER_OFFSET(clv_idle);
		readmem(clv + MCK_MEMBER_OFFSET(clv_current), KVADDR,
			&thread, sizeof(ulong), "clv_current",
			RETURN_ON_ERROR);

		mcps_print_one(idle_thread, cpu, thread == idle_thread, 1);
		if (thread != idle_thread)
			mcps_print_one(thread, cpu, 1, 0);

		cb_data.cpu = cpu;
		cb_data.running_thr = thread;
		ld.callback_data = &cb_data;
		readmem(clv + MCK_MEMBER_OFFSET(clv_runq), KVADDR,
			&ld.start, sizeof(void *), "first list element",
			RETURN_ON_ERROR);
		if (ld.start != ld.end)
			do_list(&ld);

	}
}

static char *help_mcps[] = {
	"mcps",
	"mckernel side ps",
	"[pid]",

	"  This command looks at processes defined on the mckernel side",
	"\nEXAMPLE\n",
	"    crash> mcps",
	"        PID   PPID CPU THREAD           ST COMM",
	"    >     0      0   0 ffff880002f03040 IN idle",
	"       6270      1   0 ffff880002f28000 IN test_fork",
	"          0      0   1 ffff880002f03c00  T idle",
	"    >  6276   6270   1 ffff880003a59000 RU test_fork",
	"    >     0      0   2 ffff880002f047c0 IN idle",
	NULL
};


/* mcmem */

#define VR_STACK           0x1
#define VR_PRIVATE         0x2000
#define VR_PROT_READ       0x00010000
#define VR_PROT_WRITE      0x00020000
#define VR_PROT_EXEC       0x00040000

struct mcmem_print_wrap {
	ulong vdso_addr;
	ulong vvar_addr;
	ulong brk_start;
	ulong brk_end_allocated;
	ulong match_addr;
};

struct tree_data_cb {
	ulong flags;
	ulong start;
	long node_member_offset;
	char **structname;
	int structname_args;
	int count;
	int (*cb)(ulong addr, void *arg);
	void *cb_arg;
};

static int
mcmem_print_one_range(ulong range, void *cb_arg)
{
	ulong start, end;
	ulong flag;
	ulong memobj;
	ulong path;
	char path_str[MAXPATHLEN];
	struct mcmem_print_wrap *wrap = cb_arg;

	if (!readmem(range + MCK_MEMBER_OFFSET(vm_range_start), KVADDR,
		     &start, sizeof(start), "vm_range start", RETURN_ON_ERROR))
		return 1;
	if (!readmem(range + MCK_MEMBER_OFFSET(vm_range_end), KVADDR,
		     &end, sizeof(end), "vm_range end", RETURN_ON_ERROR))
		return 1;

	if (wrap->match_addr != -1UL && start > wrap->match_addr)
		return 1;
	if (wrap->match_addr != -1UL && end <= wrap->match_addr)
		return 0;

	if (!readmem(range + MCK_MEMBER_OFFSET(vm_range_flag), KVADDR,
		     &flag, sizeof(flag), "vm_range flag", RETURN_ON_ERROR))
		return 1;
	if (!readmem(range + MCK_MEMBER_OFFSET(vm_range_memobj), KVADDR,
		     &memobj, sizeof(memobj), "vm_range memobj",
		     RETURN_ON_ERROR))
		return 1;

	path_str[0] = 0;
	if (memobj && readmem(memobj + MCK_MEMBER_OFFSET(memobj_path), KVADDR,
			      &path, sizeof(path), "memobj path",
			      RETURN_ON_ERROR) && path) {
		read_string(path, path_str, MAXPATHLEN);
		path_str[MAXPATHLEN-1] = 0;
	}
	if (path_str[0] == 0) {
		if (start == wrap->vdso_addr)
			strcpy(path_str, "[vdso]");
		else if (start == wrap->vvar_addr)
			strcpy(path_str, "[vsyscall]");
		else if (flag & VR_STACK)
			strcpy(path_str, "[stack]");
		else if (start >= wrap->brk_start &&
				end <= wrap->brk_end_allocated)
			strcpy(path_str, "[heap]");
	}

	fprintf(fp, "%016lx-%016lx %s%s%s%s %08lx %016lx   %s\n",
		start, end,
		flag & VR_PROT_READ  ? "r" : "-",
		flag & VR_PROT_WRITE ? "w" : "-",
		flag & VR_PROT_EXEC  ? "x" : "-",
		flag & VR_PRIVATE    ? "p" : "-",
		end - start,
		memobj,
		path_str);

	return 0;
}

/* unfortunately rbtree_iteration / do_rbtree do not allow a callback like
 * the list helpers, so redefine them here.
 * Keep it as close as possible to update easily / switch over when/if the
 * main one accepts a callback.
 */
static void
mck_rbtree_iteration(ulong node_p, struct tree_data_cb *td, char *pos)
{
	ulong struct_p, new_p, test_p;
	char new_pos[BUFSIZE];

	if (!node_p)
		return;

	if (hq_enter(node_p))
		td->count++;
	else
		error(FATAL, "\nduplicate tree entry: %lx\n", node_p);

	if ((td->flags & TREE_LINEAR_ORDER) &&
	    readmem(node_p+OFFSET(rb_node_rb_left), KVADDR, &new_p,
	    sizeof(void *), "rb_node rb_left", RETURN_ON_ERROR) && new_p) {
		if (readmem(new_p+OFFSET(rb_node_rb_left), KVADDR, &test_p,
			sizeof(void *), "rb_node rb_left", RETURN_ON_ERROR|QUIET)) {
			sprintf(new_pos, "%s/l", pos);
			mck_rbtree_iteration(new_p, td, new_pos);
		} else
			error(INFO, "rb_node: %lx: corrupted rb_left pointer: %lx\n",
					node_p, new_p);
	}

	struct_p = node_p - td->node_member_offset;

	if (td->flags & VERBOSE)
		fprintf(fp, "%lx\n", struct_p);

	if (td->flags & TREE_POSITION_DISPLAY)
		fprintf(fp, "  position: %s\n", pos);

	if (td->cb(struct_p, td->cb_arg))
		return; // mck

	if (!(td->flags & TREE_LINEAR_ORDER) &&
	    readmem(node_p+OFFSET(rb_node_rb_left), KVADDR, &new_p,
	    sizeof(void *), "rb_node rb_left", RETURN_ON_ERROR) && new_p) {
		if (readmem(new_p+OFFSET(rb_node_rb_left), KVADDR, &test_p,
			sizeof(void *), "rb_node rb_left", RETURN_ON_ERROR|QUIET)) {
			sprintf(new_pos, "%s/l", pos);
			mck_rbtree_iteration(new_p, td, new_pos);
		} else
			error(INFO, "rb_node: %lx: corrupted rb_left pointer: %lx\n",
					node_p, new_p);
	}

	if (readmem(node_p+OFFSET(rb_node_rb_right), KVADDR, &new_p,
	    sizeof(void *), "rb_node rb_right", RETURN_ON_ERROR) && new_p) {
		if (readmem(new_p+OFFSET(rb_node_rb_left), KVADDR, &test_p,
			sizeof(void *), "rb_node rb_left", RETURN_ON_ERROR|QUIET)) {
			sprintf(new_pos, "%s/r", pos);
			mck_rbtree_iteration(new_p, td, new_pos);
		} else
			error(INFO, "rb_node: %lx: corrupted rb_right pointer: %lx\n",
					node_p, new_p);
	}
}

static int
mck_do_rbtree(struct tree_data_cb *td)
{
	ulong start;
	char pos[BUFSIZE];

	if (!VALID_MEMBER(rb_root_rb_node) || !VALID_MEMBER(rb_node_rb_left) ||
	    !VALID_MEMBER(rb_node_rb_right))
		error(FATAL, "red-black trees do not exist or have changed "
			"their format\n");

	sprintf(pos, "root");

	if (td->flags & TREE_NODE_POINTER)
		start = td->start;
	else
		readmem(td->start + OFFSET(rb_root_rb_node), KVADDR,
			&start, sizeof(void *), "rb_root rb_node", FAULT_ON_ERROR);

	hq_open(); //mck
	mck_rbtree_iteration(start, td, pos);
	hq_close(); //mck

	return td->count;
}

static void
cmd_mcmem(void)
{
	int c;
	ulong thread, process_vm, pid;
	struct tree_data_cb td = {
		.flags = TREE_LINEAR_ORDER | TREE_ROOT_OFFSET_ENTERED,
		.node_member_offset = MCK_MEMBER_OFFSET(vm_range_vm_rb_node),
		.cb = mcmem_print_one_range,
	};

	if (!mck_loaded)
		error(FATAL, "You must run mcsymbols first");
	mckernel_refresh_symbols(1);

	while ((c = getopt(argcnt, args, "")) != EOF) {
		switch (c) {
		default:
			argerrs++;
			break;
		}
	}

next:
	switch (mck_str_to_context(args[optind++], &pid, &thread)) {
	case STR_PID:
	case STR_TASK:
		break;
	default:
		error(FATAL, "No thread found from pid or thread address");
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (!readmem(thread + MCK_MEMBER_OFFSET(thread_vm), KVADDR,
		     &process_vm, sizeof(process_vm), "thread vm",
		     RETURN_ON_ERROR|QUIET)) {
		error(FATAL, "Could not read process_vm for thread");
	}
	struct mcmem_print_wrap wrap = {
		.match_addr = -1UL,
	};
	readmem(process_vm + MCK_MEMBER_OFFSET(process_vm_vdso_addr),
		KVADDR, &wrap.vdso_addr, sizeof(wrap.vdso_addr),
		"process_vm vdso_addr", RETURN_ON_ERROR|QUIET);
	readmem(process_vm + MCK_MEMBER_OFFSET(process_vm_vvar_addr),
		KVADDR, &wrap.vvar_addr, sizeof(wrap.vvar_addr),
		"process_vm vvar_addr", RETURN_ON_ERROR|QUIET);
	readmem(process_vm + MCK_MEMBER_OFFSET(process_vm_region)
			   + MCK_MEMBER_OFFSET(vm_regions_brk_start),
		KVADDR, &wrap.brk_start, sizeof(wrap.brk_start),
		"process_vm region.brk_start", RETURN_ON_ERROR|QUIET);
	readmem(process_vm + MCK_MEMBER_OFFSET(process_vm_region)
			   + MCK_MEMBER_OFFSET(vm_regions_brk_end_allocated),
		KVADDR, &wrap.brk_end_allocated, sizeof(wrap.brk_end_allocated),
		"process_vm region.brk_end_allocated", RETURN_ON_ERROR|QUIET);
	td.start = process_vm + MCK_MEMBER_OFFSET(process_vm_vm_range_tree);
	td.cb_arg = &wrap;
	fprintf(fp, "Memory mapping for process %ld / %lx\n", pid, thread);
	fprintf(fp, "%-16s %-16s %4s %-8s %-16s  %s\n",
		"START", "END", "PERM", "SIZE", "MEMOBJ", "BACKING FILE");
	mck_do_rbtree(&td);

	if (args[optind])
		goto next;
}

static char *help_mcmem[] = {
	"mcmem",
	"mckernel memory helper",
	"<pid>|<proc address>",

	"  This command looks at user process memory regions; get proc from mcps",
	"\nEXAMPLE\n",
	"    crash> mcmem 11037",
	"    Memory mapping for process 4589 / ffff880002f23000",
	"    START            END              PERM SIZE     MEMOBJ            BACKING FILE",
	"    0000000000400000-0000000000406000 r-x- 00006000 0000000000000000   ",
	"    0000000000606000-0000000000607000 r--- 00001000 0000000000000000   ",
	"    0000000000607000-0000000000608000 rw-- 00001000 0000000000000000   ",
	"    0000000000800000-0000000000821000 rw-- 00021000 0000000000000000   [heap]",
	"    00002aaaaa9f8000-00002aaaaaa00000 rw-- 00008000 0000000000000000   ",
	"    00002aaaaaa00000-00002aaaaaa22000 r-x- 00022000 0000000000000000   ",
	"    00002aaaaac21000-00002aaaaac22000 r--- 00001000 0000000000000000   ",
	"    00002aaaaac22000-00002aaaaac24000 rw-- 00002000 0000000000000000   ",
	"    00002aaaaac24000-00002aaaaac26000 r-x- 00002000 0000000000000000   [vdso]",
	"    00002aaaaac26000-00002aaaaac27000 rw-p 00001000 0000000000000000   ",
	"    00002aaaaac30000-00002aaaaadf3000 r-xp 001c3000 ffff880002fbe020   /usr/lib64/libc-2.17.so",
	"    00002aaaaadf3000-00002aaaaaff2000 ---p 001ff000 ffff880002fbe020   /usr/lib64/libc-2.17.so",
	"    00002aaaaaff2000-00002aaaaaff6000 r--p 00004000 ffff880002fbe020   /usr/lib64/libc-2.17.so",
	"    00002aaaaaff6000-00002aaaaaff8000 rw-p 00002000 ffff880002fbe020   /usr/lib64/libc-2.17.so",
	"    00002aaaaaff8000-00002aaaaaffd000 rw-p 00005000 0000000000000000   ",
	"    00002aaaaaffd000-00002aaaaaffe000 rw-p 00001000 0000000000000000   ",
	"    00002aaaaaffe000-00002aaaab000000 rw-p 00002000 0000000000000000   ",
	"    00002aaaab000000-00002aaab1529000 r--p 06529000 ffff880003232020   /usr/lib/locale/locale-archive",
	"    0000547fff800000-0000548000000000 rw-- 00800000 0000000000000000   [stack]",
	NULL
};


/* mcvtop */

/* arch specific pte functions */
#if X86_64
#define PAGE_SHIFT         12
#define PAGE_SIZE          (1UL << PAGE_SHIFT)
#define PAGE_MASK          (~((unsigned long)PAGE_SIZE - 1))

#define PTL4_SHIFT         39
#define PTL4_SIZE          (1UL << PTL4_SHIFT)
#define PTL3_SHIFT         30
#define PTL3_SIZE          (1UL << PTL3_SHIFT)
#define PTL2_SHIFT         21
#define PTL2_SIZE          (1UL << PTL2_SHIFT)
#define PTL1_SHIFT         12
#define PTL1_SIZE          (1UL << PTL1_SHIFT)

#define PT_ENTRIES         512

#define PT_PHYSMASK (((1UL << 52) - 1) & PAGE_MASK)

#define GET_VIRT_INDICES(virt, l4i, l3i, l2i, l1i) \
	l4i = ((virt) >> PTL4_SHIFT) & (PT_ENTRIES - 1); \
	l3i = ((virt) >> PTL3_SHIFT) & (PT_ENTRIES - 1); \
	l2i = ((virt) >> PTL2_SHIFT) & (PT_ENTRIES - 1); \
	l1i = ((virt) >> PTL1_SHIFT) & (PT_ENTRIES - 1)

static ulong
pte_get_phys(ulong pte)
{
	return pte & PT_PHYSMASK;
}

#define PTATTRMASK (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_PWT |    \
		    _PAGE_PCD | _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE | \
		    _PAGE_PROTNONE | _PAGE_GLOBAL | _PAGE_NX)

/* XXX check if _PAGE* macros are arch-independent in crash */
static void
pte_print_(ulong pte, ulong virt, int pgshift)
{
	int others = 0;
	ulong phys = pte_get_phys(pte) + (virt & ((1 << pgshift) - 1));

	/* sign extension */
	if (virt >= 0x0000800000000000UL && virt < 0xffff800000000000UL)
		virt += 0xffff000000000000UL;

	fprintf(fp, "%016lx %016lx %4s (",
	       phys, virt, pgshift == PTL1_SHIFT ? "4K" :
		   (pgshift == PTL2_SHIFT ? "2M" : "1G"));
	if (pte & _PAGE_RW)
		fprintf(fp, "%sRW", others++ ? "|" : "");
	if (pte & _PAGE_USER)
		fprintf(fp, "%sUSER", others++ ? "|" : "");
	if (pte & _PAGE_PWT)
		fprintf(fp, "%sPWT", others++ ? "|" : "");
	if (pte & _PAGE_PCD)
		fprintf(fp, "%sPCD", others++ ? "|" : "");
	if (pte & _PAGE_ACCESSED)
		fprintf(fp, "%sACCESSED", others++ ? "|" : "");
	if (pte & _PAGE_DIRTY)
		fprintf(fp, "%sDIRTY", others++ ? "|" : "");
	if (pte & _PAGE_GLOBAL)
		fprintf(fp, "%sGLOBAL", others++ ? "|" : "");
	if (pte & _PAGE_NX)
		fprintf(fp, "%sNX", others++ ? "|" : "");
	fprintf(fp, ")\n");
}

static void
pte_print(ulong pte, ulong virt, int pgshift)
{
	static ulong prev_pte, prev_virt;
	static int prev_pgshift, skipped_pte;

	if ((pte & PTATTRMASK) == (prev_pte & PTATTRMASK) &&
	    pgshift == prev_pgshift &&
	    virt == prev_virt + (1L << pgshift)) {
		if (skipped_pte < 2)
			skipped_pte++;
		prev_pte = pte;
		prev_virt = virt;
		return;
	}

	if (prev_pte) {
		if (skipped_pte > 1)
			fprintf(fp, "...\n");
		if (skipped_pte)
			pte_print_(prev_pte, prev_virt, prev_pgshift);
		prev_pte = skipped_pte = 0;
	}

	if (!pte)
		return;

	pte_print_(pte, virt, pgshift);
	prev_pte = pte;
	prev_virt = virt;
	prev_pgshift = pgshift;
}

static int
ptl_shift(int level)
{
	switch (level) {
	case 1: return PTL1_SHIFT;
	case 2: return PTL2_SHIFT;
	case 3: return PTL3_SHIFT;
	case 4: return PTL4_SHIFT;
	default: error(FATAL, "ptl_shift called with invalid level %d\n", level);
	}
	return 0; // never happens
}

static void
pte_do_walk(ulong pt, ulong virt, int level)
{
	ulong i;
	ulong pte;

	for (i = 0; i < PT_ENTRIES; i++) {
		if (!readmem(pt + i * sizeof(pte), KVADDR, &pte, sizeof(pte),
			     "page table entry", RETURN_ON_ERROR|QUIET))
			error(FATAL, "Could not read page table entry");
		if (!(pte & _PAGE_PRESENT))
			continue;
		if (level == 1 || ((level == 2 || level == 3) &&
				   (pte & _PAGE_PSE))) {
			pte_print(pte, virt | (i << ptl_shift(level)),
				  ptl_shift(level));
		} else if (level > 1) {
			pte_do_walk(phys_to_virt(pte_get_phys(pte)),
				    virt | (i << ptl_shift(level)),
				    level - 1);
		}
	}
}

static void
pte_walk(ulong pt)
{
	fprintf(fp, "%-16s %-16s %s %s\n", "PHYS", "VIRT", "SIZE", "FLAGS");
	pte_do_walk(pt, 0, 4);
	pte_print(0, 0, 0); // flush last one if any
}

static void
pte_lookup(ulong pt, ulong virt)
{
	int l4idx, l3idx, l2idx, l1idx;
	int pgshift;
	ulong pte;

	GET_VIRT_INDICES(virt, l4idx, l3idx, l2idx, l1idx);
	// XXX use_1gb_page ?

	if (pc->debug)
		fprintf(fp, "pt %#lx, virt %lx, l4idx %d, l3idx %d, l2idx %d, l1idx %d\n",
			pt, virt, l4idx, l3idx, l2idx, l1idx);

	if (!readmem(pt + l4idx * sizeof(pte), KVADDR, &pte, sizeof(pte),
		     "l4 page table entry", RETURN_ON_ERROR|QUIET))
		error(FATAL, "Could not read l4 page table entry");
	if (!pte) {
		fprintf(fp, "l4 page table entry empty\n");
		return;
	}

	pt = phys_to_virt(pte_get_phys(pte));
	if (pc->debug)
		fprintf(fp, "l4 pte %lx, l3 base pt: %#lx\n", pte, pt);
	if (!readmem(pt + l3idx * sizeof(pte), KVADDR, &pte, sizeof(pte),
		     "l3 page table entry", RETURN_ON_ERROR|QUIET))
		error(FATAL, "Could not read l3 page table entry");
	if (!pte) {
		fprintf(fp, "l3 page table entry empty\n");
		return;
	}
	if (pte & _PAGE_PSE) {
		pgshift = PTL3_SHIFT;
		goto found;
	}

	pt = phys_to_virt(pte_get_phys(pte));
	if (pc->debug)
		fprintf(fp, "l3 pte %lx, l2 base pt: %#lx\n", pte, pt);
	if (!readmem(pt + l2idx * sizeof(pte), KVADDR, &pte, sizeof(pte),
		     "l2 page table entry", RETURN_ON_ERROR|QUIET))
		error(FATAL, "Could not read l2 page table entry");
	if (!pte) {
		fprintf(fp, "l2 page table entry empty\n");
		return;
	}
	if (pte & _PAGE_PSE) {
		pgshift = PTL2_SHIFT;
		goto found;
	}

	pt = phys_to_virt(pte_get_phys(pte));
	if (pc->debug)
		fprintf(fp, "l2 pte %lx, l1 base pt: %#lx\n", pte, pt);
	if (!readmem(pt + l1idx * sizeof(pte), KVADDR, &pte, sizeof(pte),
		     "l1 page table entry", RETURN_ON_ERROR|QUIET))
		error(FATAL, "Could not read l1 page table entry");
	if (!pte) {
		fprintf(fp, "l1 page table entry empty\n");
		return;
	}
	pgshift = PTL1_SHIFT;

found:
	if (pc->debug)
		fprintf(fp, "pte found %lx, pgshift %d\n", pte, pgshift);

	fprintf(fp, "%-16s %-16s %s %s\n", "PHYS", "VIRT", "SIZE", "FLAGS");
	pte_print(pte, virt, pgshift);
}
#elif ARM64
// XXX
#endif // arch specific pte lookup

static void
cmd_mcvtop(void)
{
	int c, print_all = 0;
	char *s;
	ulong thread = 0, process_vm, address_space;
	ulong page_table, addr = BADADDR;
	struct tree_data_cb td = {
		.flags = TREE_LINEAR_ORDER | TREE_ROOT_OFFSET_ENTERED,
		.node_member_offset = MCK_MEMBER_OFFSET(vm_range_vm_rb_node),
		.cb = mcmem_print_one_range,
	};

	if (!mck_loaded)
		error(FATAL, "You must run mcsymbols first");
	mckernel_refresh_symbols(1);

	while ((c = getopt(argcnt, args, "c:a")) != EOF) {
		switch (c) {
		case 'c':
			switch (mck_str_to_context(optarg, NULL, &thread)) {
			case STR_PID:
			case STR_TASK:
				break;
			default:
				error(FATAL,
				      "No thread found from pid or thread address");
			}
			break;
		case 'a':
			print_all = 1;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (thread) {
		if (!readmem(thread + MCK_MEMBER_OFFSET(thread_vm), KVADDR,
			     &process_vm, sizeof(process_vm), "thread vm",
			     RETURN_ON_ERROR|QUIET)) {
			error(FATAL, "Could not read process_vm for thread");
		}
		if (!readmem(process_vm + MCK_MEMBER_OFFSET(process_vm_address_space),
			     KVADDR, &address_space, sizeof(address_space),
			     "address_space", RETURN_ON_ERROR|QUIET)) {
			error(FATAL, "Could not read address_space for thread");
		}
		if (!readmem(address_space + MCK_MEMBER_OFFSET(address_space_page_table),
			     KVADDR, &page_table, sizeof(page_table),
			     "page_table", RETURN_ON_ERROR|QUIET)) {
			error(FATAL, "Could not read page_table for thread");
		}
	} else {
		page_table = MCK_SYMBOL(init_pt);
	}

	if (print_all) {
		pte_walk(page_table);
		return;
	}

next:
	s = args[optind++];
	if (!s)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (hexadecimal(s, 0)) {
		addr = htol(s, RETURN_ON_ERROR, NULL);
	}
	if (addr == BADADDR)
		error(FATAL, "address needs to be a hex value");

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	pte_lookup(page_table, addr);

	if (!thread)
		goto skip_mem_range;

	struct mcmem_print_wrap wrap = {
		.match_addr = addr,
	};
	readmem(process_vm + MCK_MEMBER_OFFSET(process_vm_vdso_addr),
		KVADDR, &wrap.vdso_addr, sizeof(wrap.vdso_addr),
		"process_vm vdso_addr", RETURN_ON_ERROR|QUIET);
	readmem(process_vm + MCK_MEMBER_OFFSET(process_vm_vvar_addr),
		KVADDR, &wrap.vvar_addr, sizeof(wrap.vvar_addr),
		"process_vm vvar_addr", RETURN_ON_ERROR|QUIET);
	readmem(process_vm + MCK_MEMBER_OFFSET(process_vm_region)
			   + MCK_MEMBER_OFFSET(vm_regions_brk_start),
		KVADDR, &wrap.brk_start, sizeof(wrap.brk_start),
		"process_vm region.brk_start", RETURN_ON_ERROR|QUIET);
	readmem(process_vm + MCK_MEMBER_OFFSET(process_vm_region)
			   + MCK_MEMBER_OFFSET(vm_regions_brk_end_allocated),
		KVADDR, &wrap.brk_end_allocated, sizeof(wrap.brk_end_allocated),
		"process_vm region.brk_end_allocated", RETURN_ON_ERROR|QUIET);
	td.start = process_vm + MCK_MEMBER_OFFSET(process_vm_vm_range_tree);
	td.cb_arg = &wrap;
	fprintf(fp, "\nMemory range:\n");
	mck_do_rbtree(&td);

skip_mem_range:
	if (args[optind])
		goto next;
}

static char *help_mcvtop[] = {
	"mcvtop",
	"mckernel vtop",
	"[-c [pid | taskp]] [-a | address ...]",

	"  This command looks at kernel's or a user process's page table",
	"\nEXAMPLE\n",
	"  Lookup a given address in process PID 100124",
	"    crash> mcvtop -c 100124 547fffff3210 ",
	"    PHYS             VIRT             SIZE FLAGS",
	"    00000001817f3210 0000547fffff3210   2M (RW|USER|ACCESSED|DIRTY|NX)",
	"",
	"    Memory range:",
	"    0000547fff800000-0000548000000000 rw-- 00800000 0000000000000000   [stack]",
	"",
	"  Dump the whole table page for process with thread ffff880180b45c28 (truncated)",
	"    crash> mcvtop -c ffff880180b45c28 -a",
	"    PHYS             VIRT             SIZE FLAGS",
	"    000000018132b000 0000000000400000   4K (USER|ACCESSED)",
	"    ...",
	"    000000018132d000 0000000000402000   4K (USER|ACCESSED)",
	"    000000018132e000 0000000000403000   4K (USER)",
	"    000000018132f000 0000000000404000   4K (USER|ACCESSED)",
	"    ...",
	"    0000000181334000 0000000000409000   4K (USER|ACCESSED)",
	"    0000000181335000 000000000040a000   4K (USER)",
	"    0000000181339000 000000000060b000   4K (USER|ACCESSED|DIRTY|NX)",
	"    000000018133a000 000000000060c000   4K (RW|USER|ACCESSED|DIRTY|NX)",
	"    00000001813ce000 0000000000800000   4K (RW|USER|ACCESSED|DIRTY|NX)",
	"    00000001813cf000 0000000000801000   4K (RW|USER|ACCESSED|DIRTY|NX)",
	"    00000001813d0000 0000000000802000   4K (RW|USER|NX)",
	"    ...",
	"    00000001813e1000 0000000000811000   4K (RW|USER|NX)",

	NULL
};


/* mckmsg */

static void
cmd_mckmsg(void)
{
	int kmsg_buf_head, kmsg_buf_tail, kmsg_buf_len;
	ulong kmsg_buf_str;
	size_t part;
	char *msg;

	if (!mck_loaded)
		error(FATAL, "You must run mcsymbols first");
	mckernel_refresh_symbols(1);

	kmsg_buf_str = MCK_SYMBOL(kmsg_buf) + MCK_MEMBER_OFFSET(kmsg_buf_str);
	if (!readmem(MCK_SYMBOL(kmsg_buf) + MCK_MEMBER_OFFSET(kmsg_buf_head),
		     KVADDR, &kmsg_buf_head, sizeof(kmsg_buf_head),
		     "kmsg_buf head", RETURN_ON_ERROR))
		return;
	if (!readmem(MCK_SYMBOL(kmsg_buf) + MCK_MEMBER_OFFSET(kmsg_buf_tail),
		     KVADDR, &kmsg_buf_tail, sizeof(kmsg_buf_tail),
		     "kmsg_buf tail", RETURN_ON_ERROR))
		return;
	if (!readmem(MCK_SYMBOL(kmsg_buf) + MCK_MEMBER_OFFSET(kmsg_buf_len),
		     KVADDR, &kmsg_buf_len, sizeof(kmsg_buf_len),
		     "kmsg_buf len", RETURN_ON_ERROR))
		return;

	msg = GETBUF(kmsg_buf_len);
	part = kmsg_buf_tail < kmsg_buf_head ? kmsg_buf_len - kmsg_buf_head :
					       kmsg_buf_tail - kmsg_buf_head;
	if (!read_string(kmsg_buf_str + kmsg_buf_head, msg, part) ||
	    (kmsg_buf_tail < kmsg_buf_head &&
	     !read_string(kmsg_buf_str, msg + part, kmsg_buf_tail))) {
		FREEBUF(msg);
		error(FATAL, "could not read kmsg buf\n");
	}

	fprintf(fp, "%s", msg);
	FREEBUF(msg);
}

static char *help_mckmsg[] = {
	"mckmsg",
	"mckernel kmsg",
	"",

	"  This prints the kmsg buffer",
	"\nEXAMPLE\n",
	"    crash> mckmsg",
	"    IHK/McKernel started.",
	"    [ -1]: no_execute_available: 1",
	"    [ -1]: setup_x86 done.",
	"    [ -1]: ns_per_tsc: 385",
	"    [ -1]: Physical memory: 0x88ad4000 - 0xa8000000, 525516800 bytes, 128300 pages available @ NUMA: 0",
	"    [ -1]: NUMA: 0, Linux NUMA: 0, type: 1, available bytes: 525516800, pages: 128300",
	"    [ -1]: NUMA 0 distances: 0 (10), ",
	"    [ -1]: map_fixed: phys: 0x5e000 => 0xffff86000000f000 (2 pages)",
	"    [ -1]: Trampoline area: 0x5e000 ",
	"    [ -1]: map_fixed: phys: 0x0 => 0xffff860000011000 (1 pages)",
	"    [ -1]: # of cpus : 3",
	"    [ -1]: locals = ffff880088af7000",
	"    [  0]: BSP: 0 (HW ID: 1 @ NUMA 0)",
	"    [  0]: BSP: booted 2 AP CPUs",
	"    [  0]: Master channel init acked.",
	"    [  0]: vdso is enabled",
	"    IHK/McKernel booted.",
	NULL
};


/* boilerplate */

static struct command_table_entry command_table[] = {
	{ "mcsymbols", cmd_mcsymbols, help_mcsymbols, 0},
	{ "mcps", cmd_mcps, help_mcps, 0},
	{ "mcmem", cmd_mcmem, help_mcmem, 0},
	{ "mckmsg", cmd_mckmsg, help_mckmsg, 0},
	{ "mcvtop", cmd_mcvtop, help_mcvtop, 0},
	{ NULL },
};


void __attribute__((constructor))
mckernel_init(void)
{
	register_extension(command_table);
}

void __attribute__((destructor))
mckernel_fini(void)
{
}

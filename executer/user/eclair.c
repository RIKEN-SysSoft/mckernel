/* eclair.c COPYRIGHT FUJITSU LIMITED 2016 */
/**
 * \file eclair.c
 *  License details are found in the file LICENSE.
 * \brief
 *  IHK os memory dump analyzer for McKernel
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */

#include "config.h"
#include <bfd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <ihk/ihk_host_user.h>
#include <eclair.h>
#include <arch-eclair.h>
#include <signal.h>
#include <errno.h>

#define CPU_TID_BASE 1000000

#define PHYSMEM_NAME_SIZE 32

struct options {
	uint8_t	cpu;
	uint8_t	help;
	char *kernel_path;
	char *dump_path;
	char *log_path;
	int interactive;
	int os_id;
	int mcos_fd;
	int print_idle;
}; /* struct options */

struct thread_info {
	struct thread_info *next;
	int status;
#define PS_RUNNING		0x01
#define PS_INTERRUPTIBLE	0x02
#define PS_UNINTERRUPTIBLE	0x04
#define PS_STOPPED		0x20
#define PS_TRACED		0x40
#define CS_IDLE			0x010000
#define CS_RUNNING		0x020000
#define CS_RESERVED		0x030000
	int pid;
	int tid;
	int cpu;
	int lcpu;
	int idle;
	uintptr_t process;
	uintptr_t clv;
	uintptr_t arch_clv;
}; /* struct thread_info */

/* Physical memory start addr (non-zero on ARM64) */
unsigned long PHYS_OFFSET;
/* Virtual address where McKernel is mapped to */
unsigned long MAP_KERNEL_START;

static struct options opt;
static volatile int f_done = 0;
static bfd *symbfd = NULL;
static bfd *dumpbfd = NULL;
static asection *dumpscn = NULL;
static dump_mem_chunks_t *mem_chunks;
static int num_processors = -1;
static asymbol **symtab = NULL;
static ssize_t nsyms;
uintptr_t kernel_base;
static struct thread_info *tihead = NULL;
static struct thread_info **titailp = &tihead;
static struct thread_info *curr_thread = NULL;
static int remote_running;

uintptr_t lookup_symbol(char *name)
{
	int i;

	for (i = 0; i < nsyms; ++i) {
		if (!strcmp(symtab[i]->name, name)) {
			return (symtab[i]->section->vma + symtab[i]->value);
		}
	}
	return NOSYMBOL;
} /* lookup_symbol() */

static int read_physmem(uintptr_t pa, void *buf, size_t size)
{
	off_t off;
	bfd_boolean ok;
	int i;

	char physmem_name[PHYSMEM_NAME_SIZE];

	off = 0;
	/* Check if pa is valid in any chunks and figure
	 * out the global offset in dump section */
	for (i = 0; i < mem_chunks->nr_chunks; ++i) {

		if (mem_chunks->chunks[i].addr <= pa &&
				((pa + size) <= (mem_chunks->chunks[i].addr +
					mem_chunks->chunks[i].size))) {

			off += (pa - mem_chunks->chunks[i].addr);
			break;
		}
	}

	if (i == mem_chunks->nr_chunks) {
		printf("read_physmem: invalid addr 0x%lx\n", pa);
		return 1;
	}

	memset(physmem_name,0,sizeof(physmem_name));
	sprintf(physmem_name, "physmem%d",i);

	dumpscn = bfd_get_section_by_name(dumpbfd, physmem_name);
	if (!dumpscn) {
		bfd_perror("read_physmem:bfd_get_section_by_name(physmem)");
		return 1;
	}

	ok = bfd_get_section_contents(dumpbfd, dumpscn, buf, off, size);
	if (!ok) {
		bfd_perror("read_physmem:bfd_get_section_contents");
		return 1;
	}

	return 0;
} /* read_physmem() */

int read_mem(uintptr_t va, void *buf, size_t size)
{
	uintptr_t pa;
	int error;

	pa = virt_to_phys(va);
	if (pa == NOPHYS) {
		if (0) {
			/* NOPHYS is usual for 'bt' command */
			perror("read_mem:virt_to_phys");
		}
		return 1;
	}

	if (opt.interactive) {
		dumpargs_t args;

		args.cmd = DUMP_READ;
		args.start = pa;
		args.size = size;
		args.buf = buf;

		error = ioctl(opt.mcos_fd, IHK_OS_DUMP, &args);
	}
	else {
		error = read_physmem(pa, buf, size);
	}

	if (error) {
		perror("read_mem:read_physmem");
		return 1;
	}

	return 0;
} /* read_mem() */

int read_64(uintptr_t va, void *buf)
{
	return read_mem(va, buf, sizeof(uint64_t));
} /* read_64() */

int read_32(uintptr_t va, void *buf)
{
	return read_mem(va, buf, sizeof(uint32_t));
} /* read_32() */

int read_symbol_64(char *name, void *buf)
{
	uintptr_t va;
	int error;

	va = lookup_symbol(name);
	if (va == NOSYMBOL) {
		printf("read_symbol_64(%s):lookup_symbol failed\n", name);
		return 1;
	}

	error = read_64(va, buf);
	if (error) {
		printf("read_symbol_64(%s):read_64(%#lx) failed", name, va);
		return 1;
	}

	return 0;
} /* read_symbol_64() */

enum {
	/* cpu_local_var */
	CPU_LOCAL_VAR_SIZE = 0,
	CURRENT_OFFSET,
	RUNQ_OFFSET,
	CPU_STATUS_OFFSET,
	IDLE_THREAD_OFFSET,

	/* process */
	CTX_OFFSET,
	SCHED_LIST_OFFSET,
	PROC_OFFSET,

	/* fork_tree_node */
	STATUS_OFFSET,
	PID_OFFSET,
	TID_OFFSET,

	END_MARK,
}; /* enum */
static uintptr_t debug_constants[END_MARK+1];
#define K(name) (debug_constants[name])

static int setup_constants(void) {
	int error;
	uintptr_t va;

	error = arch_setup_constants(opt.mcos_fd);
	if (error) {
		fprintf(stderr, "error: setting up arch constants\n");
		return 1;
	}

	va = lookup_symbol("debug_constants");
	if (va == NOSYMBOL) {
		perror("debug_constants");
		return 1;
	}

	error = read_mem(va, debug_constants, sizeof(debug_constants));
	if (error) {
		perror("debug_constants");
		return 1;
	}

	if (0) {
		printf("CPU_LOCAL_VAR_SIZE: %ld\n", K(CPU_LOCAL_VAR_SIZE));
		printf("CURRENT_OFFSET: %ld\n", K(CURRENT_OFFSET));
		printf("RUNQ_OFFSET: %ld\n", K(RUNQ_OFFSET));
		printf("CPU_STATUS_OFFSET: %ld\n", K(CPU_STATUS_OFFSET));
		printf("IDLE_THREAD_OFFSET: %ld\n", K(IDLE_THREAD_OFFSET));
		printf("CTX_OFFSET: %ld\n", K(CTX_OFFSET));
		printf("SCHED_LIST_OFFSET: %ld\n", K(SCHED_LIST_OFFSET));
		printf("PROC_OFFSET: %ld\n", K(PROC_OFFSET));
		printf("STATUS_OFFSET: %ld\n", K(STATUS_OFFSET));
		printf("PID_OFFSET: %ld\n", K(PID_OFFSET));
		printf("TID_OFFSET: %ld\n", K(TID_OFFSET));
		printf("END_MARK: %ld\n", K(END_MARK));
	}

	return 0;
} /* setup_constants() */

static int setup_threads(void) {
	int error;
	uintptr_t clv;
	int cpu;
	uintptr_t current;
	uintptr_t locals;
	size_t locals_span;
	struct thread_info *ti;
	struct thread_info *tin;

	error = read_symbol_64("num_processors", &num_processors);
	if (error) {
		perror("num_processors");
		return 1;
	}
	dprintf("%s: num_processors: %d\n", __func__, num_processors);

	error = read_symbol_64("locals", &locals);
	if (error) {
		perror("locals");
		return 1;
	}

	error = read_symbol_64(ARCH_CLV_SPAN, &locals_span);
	if (error) {
		locals_span = sysconf(_SC_PAGESIZE);
	}
	if (0) printf("locals 0x%lx span 0x%lx\n", locals, locals_span);

	error = read_symbol_64("clv", &clv);
	if (error) {
		perror("clv");
		return 1;
	}

	/* Drop previous threads */
	for (ti = tihead; ti; ) {
		tin = ti->next;
		free(ti);
		ti = tin;
	}
	tihead = NULL;
	titailp = &tihead;

	for (cpu = 0; cpu < num_processors; ++cpu) {
		uintptr_t v;
		uintptr_t head;
		uintptr_t entry;

		v = clv + (cpu * K(CPU_LOCAL_VAR_SIZE));

		error = read_64(v+K(CURRENT_OFFSET), &current);
		if (error) {
			perror("current");
			return 1;
		}

		head = v + K(RUNQ_OFFSET);
		error = read_64(head, &entry);
		if (error) {
			perror("runq head");
			return 1;
		}

		while (entry != head) {
			uintptr_t thread;
			uintptr_t proc;
			int pid;
			int tid;
			struct thread_info *ti;
			int status;

			ti = malloc(sizeof(*ti));
			if (!ti) {
				perror("malloc");
				return 1;
			}

			thread = entry - K(SCHED_LIST_OFFSET);

			error = read_64(thread+K(PROC_OFFSET), &proc);
			if (error) {
				perror("proc");
				return 1;
			}

			error = read_32(thread+K(STATUS_OFFSET), &status);
			if (error) {
				perror("status");
				return 1;
			}

			error = read_32(proc+K(PID_OFFSET), &pid);
			if (error) {
				perror("pid");
				return 1;
			}

			error = read_32(thread+K(TID_OFFSET), &tid);
			if (error) {
				perror("tid");
				return 1;
			}

			ti->next = NULL;
			ti->status = status;
			ti->pid = pid;
			ti->tid = tid;
			ti->cpu = (thread == current) ? cpu : -1;
			ti->lcpu = cpu;
			ti->process = thread;
			ti->idle = 0;
			ti->clv = v;
			ti->arch_clv = locals + locals_span*cpu;

			*titailp = ti;
			titailp = &ti->next;

			if (!curr_thread)
				curr_thread = ti;

			error = read_64(entry, &entry);
			if (error) {
				perror("process2");
				return 1;
			}
		}
	}

	/* Set up idle threads */
	if (opt.print_idle) {
		for (cpu = 0; cpu < num_processors; ++cpu) {
			uintptr_t v;
			uintptr_t thread;
			uintptr_t proc;
			int pid;
			int tid;
			struct thread_info *ti;
			int status;

			v = clv + (cpu * K(CPU_LOCAL_VAR_SIZE));

			error = read_64(v+K(CURRENT_OFFSET), &current);
			if (error) {
				perror("current");
				return 1;
			}

			ti = malloc(sizeof(*ti));
			if (!ti) {
				perror("malloc");
				return 1;
			}

			thread = v+K(IDLE_THREAD_OFFSET);

			error = read_64(thread+K(PROC_OFFSET), &proc);
			if (error) {
				perror("proc");
				return 1;
			}

			error = read_32(thread+K(STATUS_OFFSET), &status);
			if (error) {
				perror("status");
				return 1;
			}

			error = read_32(proc+K(PID_OFFSET), &pid);
			if (error) {
				perror("pid");
				return 1;
			}

			error = read_32(thread+K(TID_OFFSET), &tid);
			if (error) {
				perror("tid");
				return 1;
			}

			ti->next = NULL;
			ti->status = status;
			ti->pid = 1;
			ti->tid = 2000000000 + tid;
			ti->cpu = (thread == current) ? cpu : -1;
			ti->lcpu = cpu;
			ti->process = thread;
			ti->idle = 1;
			ti->clv = v;
			ti->arch_clv = locals + locals_span * cpu;

			*titailp = ti;
			titailp = &ti->next;

			if (!curr_thread)
				curr_thread = ti;
		}
	}

	if (!tihead) {
		printf("No threads found, forcing CPU mode.\n");
		opt.cpu = 1;
	}

	if (opt.cpu) {
		for (cpu = 0; cpu < num_processors; ++cpu) {
			uintptr_t v;
			struct thread_info *ti;
			int status;
			uintptr_t current;

			v = clv + K(CPU_LOCAL_VAR_SIZE)*cpu;

			error = read_32(v+K(CPU_STATUS_OFFSET), &status);
			if (error) {
				perror("cpu.status");
				return 1;
			}

			if (!status) {
				continue;
			}

			error = read_64(v+K(CURRENT_OFFSET), &current);
			if (error) {
				perror("current");
				return 1;
			}

			ti = malloc(sizeof(*ti));
			if (!ti) {
				perror("malloc");
				return 1;
			}

			ti->next = NULL;
			ti->status = status << 16;
			ti->pid = CPU_TID_BASE + cpu;
			ti->tid = CPU_TID_BASE + cpu;
			ti->cpu = cpu;
			ti->process = current;
			ti->idle = 1;
			ti->clv = v;
			ti->arch_clv = locals + locals_span * cpu;

			*titailp = ti;
			titailp = &ti->next;
		}
	}

	if (!tihead) {
		printf("thread not found\n");
		return 1;
	}

	if (!curr_thread)
		curr_thread = tihead;

	return 0;
} /* setup_threads() */

static int setup_symbols(char *fname) {
	ssize_t needs;
	bfd_boolean ok;

	symbfd = bfd_openr(fname, NULL);

	if (!symbfd) {
		bfd_perror("bfd_openr");
		return 1;
	}

	ok = bfd_check_format(symbfd, bfd_object);
	if (!ok) {
		bfd_perror("bfd_check_format");
		return 1;
	}

	needs = bfd_get_symtab_upper_bound(symbfd);
	if (needs < 0) {
		bfd_perror("bfd_get_symtab_upper_bound");
		return 1;
	}

	if (!needs) {
		printf("no symbols\n");
		return 1;
	}

	symtab = malloc(needs);
	if (!symtab) {
		perror("malloc");
		return 1;
	}

	nsyms = bfd_canonicalize_symtab(symbfd, symtab);
	if (nsyms < 0) {
		bfd_perror("bfd_canonicalize_symtab");
		return 1;
	}

	return 0;
} /* setup_symbols() */

static int setup_dump_interactive(void)
{
	int error;
	long mem_size;
	int dump_level = DUMP_LEVEL_ALL;
	dumpargs_t args;

	args.cmd = DUMP_SET_LEVEL;
	args.level = dump_level;
	error = ioctl(opt.mcos_fd, IHK_OS_DUMP, &args);
	if (error) {
		perror("DUMP_SET_LEVEL");
		return 1;
	}

	args.cmd = DUMP_NMI;
	error = ioctl(opt.mcos_fd, IHK_OS_DUMP, &args);
	if (error) {
		perror("DUMP_NMI");
		return 1;
	}

	remote_running = 0;

	args.cmd = DUMP_QUERY_NUM_MEM_AREAS;
	args.size = 0;
	error = ioctl(opt.mcos_fd, IHK_OS_DUMP, &args);
	if (error) {
		perror("DUMP_QUERY_NUM_MEM_AREAS");
		return 1;
	}

	mem_size = args.size;
	mem_chunks = malloc(mem_size);
	if (!mem_chunks) {
		perror("allocating mem_chunks");
		return 1;
	}

	memset(mem_chunks, 0, mem_size);

	args.cmd = DUMP_QUERY_MEM_AREAS;
	args.buf = (void *)mem_chunks;
	error = ioctl(opt.mcos_fd, IHK_OS_DUMP, &args);
	if (error) {
		perror("DUMP_QUERY_MEM_AREAS");
		return 1;
	}

	kernel_base = mem_chunks->kernel_base;
	PHYS_OFFSET = mem_chunks->phys_start;

	return 0;
}


static int setup_dump(char *fname) {
	bfd_boolean ok;
	long mem_size;
	static dump_mem_chunks_t mem_info;

	char physmem_name[PHYSMEM_NAME_SIZE];
	int i;

	dumpbfd = bfd_fopen(opt.dump_path, NULL, "r", -1);
	if (!dumpbfd) {
		bfd_perror("bfd_fopen");
		return 1;
	}

	ok = bfd_check_format(dumpbfd, bfd_object);
	if (!ok) {
		bfd_perror("bfd_check_format");
		return 1;
	}

	dumpscn = bfd_get_section_by_name(dumpbfd, "physchunks");
	if (!dumpscn) {
		bfd_perror("bfd_get_section_by_name");
		return 1;
	}

	ok = bfd_get_section_contents(dumpbfd, dumpscn, &mem_info,
			0, sizeof(mem_info));
	if (!ok) {
		bfd_perror("read_physmem:bfd_get_section_contents(mem_size)");
		return 1;
	}

	mem_size = (sizeof(dump_mem_chunks_t) + (sizeof(struct dump_mem_chunk) * mem_info.nr_chunks));

	mem_chunks = malloc(mem_size);
	if (!mem_chunks) {
		perror("allocating mem chunks descriptor: ");
		return 1;
	}

	ok = bfd_get_section_contents(dumpbfd, dumpscn, mem_chunks,
			0, mem_size);
	if (!ok) {
		bfd_perror("read_physmem:bfd_get_section_contents(mem_chunks)");
		return 1;
	}

	kernel_base = mem_chunks->kernel_base;
	PHYS_OFFSET = mem_chunks->phys_start;

	for (i = 0; i < mem_info.nr_chunks; ++i) {
		memset(physmem_name,0,sizeof(physmem_name));
		sprintf(physmem_name, "physmem%d",i);

		dumpscn = bfd_get_section_by_name(dumpbfd, physmem_name);
		if (!dumpscn) {
			bfd_perror("read_physmem:bfd_get_section_by_name(physmem)");
			return 1;
		}
	}

	return 0;
} /* setup_dump() */

static ssize_t print_hex(char *buf, size_t buf_size, char *str) {

	char *p;
	char *q;

	q = buf;
	for (p = str; *p != '\0'; ++p) {
		int ret;

		ret = snprintf(q, buf_size, "%02x", *p);
		if (ret < 0) {
			return ret;
		}
		q += ret;
		buf_size -= ret;
	}
	*q = '\0';

	return (q - buf);
} /* print_hex() */

ssize_t print_bin(char *buf, size_t buf_size, void *data, size_t size) {
	uint8_t *p;
	char *q;
	int i;

	p = data;
	q = buf;
	for (i = 0; i < size; ++i) {
		int ret;

		ret = snprintf(q, buf_size, "%02x", *p);
		if (ret < 0) {
			return ret;
		}
		q += ret;
		buf_size -= ret;
		++p;
	}
	*q = '\0';

	return (q - buf);
} /* print_bin() */

static void command(const char *cmd, char *res, size_t res_size) {
	const char *p;
	char *rbp;
	int error;

	p = cmd;
	rbp = res;

	do {
		dprintf("query: %s\n", p);
		if (!strncmp(p, "qSupported", 10)) {
			rbp += sprintf(rbp, "PacketSize=1024");
			rbp += sprintf(rbp, ";qXfer:features:read+");
		}
		else if (!strncmp(p, "Hg", 2)) {
			int n;
			int tid;
			struct thread_info *ti;

			p += 2;
			n = sscanf(p, "%x", &tid);
			if (n != 1) {
				printf("cannot parse 'Hg' cmd: \"%s\"\n", p);
				break;
			}
			if (tid) {
				for (ti = tihead; ti; ti = ti->next) {
					if (ti->tid == tid) {
						break;
					}
				}
				if (!ti) {
					printf("invalid tid %#x\n", tid);
					break;
				}
				curr_thread = ti;
			}
			rbp += sprintf(rbp, "OK");
		}
		else if (!strncmp(p, "Hc", 2)) {
			if (opt.interactive) {
				rbp += sprintf(rbp, "OK");
			}
			else {
				rbp += sprintf(rbp, "S02");
			}
		}
		else if (opt.interactive &&
				!strcmp(p, "vCtrlC")) {
			if (remote_running) {
				dumpargs_t args;
				args.cmd = DUMP_NMI;

				error = ioctl(opt.mcos_fd, IHK_OS_DUMP, &args);
				if (error) {
					perror("DUMP_NMI");
					break;
				}

				remote_running = 0;
			}
			rbp += sprintf(rbp, "OK");
		}
		else if (opt.interactive &&
				!strcmp(p, "Ctrl-C")) {
			if (remote_running) {
				dumpargs_t args;
				args.cmd = DUMP_NMI;

				error = ioctl(opt.mcos_fd, IHK_OS_DUMP, &args);
				if (error) {
					perror("DUMP_NMI");
					break;
				}

				remote_running = 0;
			}
			rbp += sprintf(rbp, "S02");
		}
		else if (!strcmp(p, "vCont?")) {
			if (opt.interactive) {
				rbp += sprintf(rbp, "vCont;c");
			}
		}
		else if (!strcmp(p, "c")) {
			if (opt.interactive) {
				if (!remote_running) {
					dumpargs_t args;
					args.cmd = DUMP_NMI_CONT;

					error = ioctl(opt.mcos_fd, IHK_OS_DUMP, &args);
					if (error) {
						perror("DUMP_NMI_CONT for continue");
						break;
					}

					remote_running = 1;
				}
				rbp += sprintf(rbp, "OK");
			}
			else {
				rbp += sprintf(rbp, "S02");
			}
		}
		else if (opt.interactive &&
				!strcmp(p, "?")) {
			if (remote_running) {
				rbp += sprintf(rbp, "S12");
			}
			else {
				rbp += sprintf(rbp, "S02");
			}
		}
		else if (!strcmp(p, "?")) {
			rbp += sprintf(rbp, "S02");
		}
		else if (!strcmp(p, "qC")) {
			rbp += sprintf(rbp, "QC%x", curr_thread->tid);
		}
		else if (!strcmp(p, "qAttached")) {
			rbp += sprintf(rbp, "1");
		}
		else if (!strncmp(p, "qXfer:features:read:target.xml:", 31)) {
			char *str =
				"<target version=\"1.0\">"
				"<architecture>"ARCH"</architecture>"
				"</target>";
			rbp += sprintf(rbp, "l");
			if (0)
			rbp += print_hex(rbp, res_size, str);
			rbp += sprintf(rbp, "%s", str);
		}
		else if (!strcmp(p, "D")) {
			if (opt.interactive && !remote_running) {
				dumpargs_t args;
				args.cmd = DUMP_NMI_CONT;

				error = ioctl(opt.mcos_fd, IHK_OS_DUMP, &args);
				if (error) {
					perror("DUMP_NMI_CONT for continue");
					break;
				}

				remote_running = 1;
			}
			rbp += sprintf(rbp, "OK");
			f_done = 1;
		}
		else if (!strcmp(p, "g")) {
			if (curr_thread->cpu < 0) {
				int error;
				struct arch_kregs kregs;

				error = arch_read_kregs(curr_thread->process+K(CTX_OFFSET),
						&kregs);
				if (error) {
					perror("arch_read_kregs");
					break;
				}

				rbp += print_kregs(rbp, res_size, &kregs);
			}
			else {
				int error;
				uintptr_t regs[ARCH_REGS];
				uint8_t *pu8;
				int i;

				error = read_mem(curr_thread->arch_clv+PANIC_REGS_OFFSET,
						&regs, sizeof(regs));
				if (error) {
					perror("read_mem");
					break;
				}

				//if (regs[17] > MAP_KERNEL) {}
				pu8 = (void *)&regs;
				for (i = 0; i < sizeof(regs)-4; ++i) {
					rbp += sprintf(rbp, "%02x", pu8[i]);
				}
			}
		}
		/*
		else if (!strcmp(p, "mffffffff80018a82,1")) {
			rbp += sprintf(rbp, "b8");
		}
		else if (!strcmp(p, "mffffffff80018a82,9")) {
			rbp += sprintf(rbp, "b8f2ffffff41564155");
		}
		*/
		else if (!strncmp(p, "m", 1)) {
			int n;
			uintptr_t start;
			size_t size;
			uintptr_t addr;
			int error;
			uint8_t u8;

			++p;
			n = sscanf(p, "%lx,%lx", &start, &size);
			if (n != 2) {
				break;
			}

			for (addr = start; addr < (start + size); ++addr) {
				error = read_mem(addr, &u8, sizeof(u8));
				if (error) {
					//u8 = 0xE5;
					u8 = 0x00;
				}
				rbp += sprintf(rbp, "%02x", u8);
			}
		}
		else if (!strcmp(p, "qTStatus")) {
			rbp += sprintf(rbp, "T0;tnotrun:0");
		}
		else if (!strncmp(p, "qXfer:memory-map:read::", 23)) {
			char str[1024];
			sprintf(str, "<memory-map>"
					"<memory type=\"rom\" start=\"0x%lx\" length=\"0x27000\"/>"
					"</memory-map>", MAP_KERNEL_START);

			rbp += sprintf(rbp, "l");
			if (0)
			rbp += print_hex(rbp, res_size, str);
			rbp += sprintf(rbp, "%s", str);
		}
		else if (!strncmp(p, "T", 1)) {
			int n;
			int tid;
			struct thread_info *ti;

			p += 1;
			n = sscanf(p, "%x", &tid);
			if (n != 1) {
				printf("cannot parse 'T' cmd: \"%s\"\n", p);
				break;
			}
			for (ti = tihead; ti; ti = ti->next) {
				if (ti->tid == tid) {
					break;
				}
			}
			if (!ti) {
				printf("invalid tid %#x\n", tid);
				break;
			}
			rbp += sprintf(rbp, "OK");
		}
		else if (!strcmp(p, "qfThreadInfo")) {
			struct thread_info *ti;

			if (opt.interactive) {
				error = setup_threads();
				if (error) {
					perror("setup_threads");
					exit(1);
				}
			}

			for (ti = tihead; ti; ti = ti->next) {
				if (ti == tihead) {
					rbp += sprintf(rbp, "m%x", ti->tid);
				}
				else {
					rbp += sprintf(rbp, ",%x", ti->tid);
				}
			}
		}
		else if (!strcmp(p, "qsThreadInfo")) {
			rbp += sprintf(rbp, "l");
		}
		else if (!strncmp(p, "qThreadExtraInfo,", 17)) {
			int n;
			int tid;
			struct thread_info *ti;
			char buf[64];
			char *q;

			p += 17;
			n = sscanf(p, "%x", &tid);
			if (n != 1) {
				printf("cannot parse 'qThreadExtraInfo' cmd: \"%s\"\n", p);
				break;
			}
			for (ti = tihead; ti; ti = ti->next) {
				if (ti->tid == tid) {
					break;
				}
			}
			if (!ti) {
				printf("invalid tid %#x\n", tid);
				break;
			}
			q = buf;
			q += sprintf(q, "PID %d, ", ti->pid);
			if (ti->status & PS_RUNNING) {
				q += sprintf(q, "%srunning on CPU %d",
					ti->idle ? "idle " : "", ti->lcpu);
			}
			else if (ti->status & (PS_INTERRUPTIBLE | PS_UNINTERRUPTIBLE)) {
				q += sprintf(q, "%swaiting on CPU %d",
					ti->idle ? "idle " : "", ti->lcpu);
			}
			else if (ti->status & PS_STOPPED) {
				q += sprintf(q, "%sstopped on CPU %d",
					ti->idle ? "idle " : "", ti->lcpu);
			}
			else if (ti->status & PS_TRACED) {
				q += sprintf(q, "%straced on CPU %d",
					ti->idle ? "idle " : "", ti->lcpu);
			}
			else if (ti->status == CS_IDLE) {
				q += sprintf(q, "CPU %d idle", ti->cpu);
			}
			else if (ti->status == CS_RUNNING) {
				q += sprintf(q, "CPU %d running", ti->cpu);
			}
			else if (ti->status == CS_RESERVED) {
				q += sprintf(q, "CPU %d reserved", ti->cpu);
			}
			else {
				q += sprintf(q, "status=%#x", ti->status);
			}
			rbp += print_hex(rbp, res_size, buf);
		}
	} while (0);

	*rbp = '\0';
	dprintf("res: %s\n", res);
	return;
} /* command() */

static void options(int argc, char *argv[]) {
	memset(&opt, 0, sizeof(opt));
	opt.kernel_path = "./mckernel.img";
	opt.dump_path = "./mcdump";
	opt.mcos_fd = -1;

	for (;;) {
		int c;

		c = getopt(argc, argv, "ilcd:hk:o:");
		if (c < 0) {
			break;
		}
		switch (c) {
		case 'h':
		case '?':
			opt.help = 1;
			break;
		case 'c':
			opt.cpu = 1;
			break;
		case 'k':
			opt.kernel_path = optarg;
			break;
		case 'd':
			opt.dump_path = optarg;
			break;
		case 'i':
			opt.interactive = 1;
			break;
		case 'o':
			opt.os_id = atoi(optarg);
			break;
		case 'l':
			opt.print_idle = 1;
			break;
		}
	}
	if (optind < argc) {
		opt.help = 1;
	}

	if (opt.interactive) {
		char fn[128];
		sprintf(fn, "/dev/mcos%d", opt.os_id);

		opt.mcos_fd = open(fn, O_RDONLY);
		if (opt.mcos_fd < 0) {
			fprintf(stderr, "%s:%d error: "
				"opening /dev/mcos%d, errno: %d\n",
				__FILE__, __LINE__, opt.os_id, errno);
			exit(1);
		}
	}

	return;
} /* options() */

static int sock = -1;
static FILE *ifp = NULL;
static FILE *ofp = NULL;
pid_t gdbpid;

void intr_handler(int dummy)
{
	kill(gdbpid, SIGINT);
}


static int start_gdb(void) {
	struct sockaddr_in sin;
	socklen_t slen;
	int error;
	int ss;

	if (opt.interactive) {
		signal(SIGINT, intr_handler);
	}

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	error = listen(sock, SOMAXCONN);
	if (error) {
		perror("listen");
		return 1;
	}

	slen = sizeof(sin);
	error = getsockname(sock, (struct sockaddr *)&sin, &slen);
	if (error) {
		perror("getsockname");
		return 1;
	}

	gdbpid = fork();
	if (gdbpid == (pid_t)-1) {
		perror("fork");
		return 1;
	}

	if (!gdbpid) {
		char buf[32];

		sprintf(buf, "target remote :%d", ntohs(sin.sin_port));
		execlp("gdb", "eclair", "-q", "-ex", "set prompt (eclair) ",
				"-ex", buf, opt.kernel_path, "-ex", "set pagination off", NULL);
		perror("execlp");
		return 3;
	}

	ss = accept(sock, NULL, NULL);
	if (ss < 0) {
		perror("accept");
		return 1;
	}

	ifp = fdopen(ss, "r");
	if (!ifp) {
		perror("fdopen(r)");
		return 1;
	}

	ofp = fdopen(ss, "r+");
	if (!ofp) {
		perror("fdopen(r+)");
		return 1;
	}

	return 0;
} /* start_gdb() */

static void print_usage(void) {
	fprintf(stderr, "usage: eclair [-ch] [-d <mcdump>] [-k <kernel.img>]\n");
	return;
} /* print_usage() */

int main(int argc, char *argv[]) {
	int c;
	int error;
	int mode;
	uint8_t sum;
	uint8_t check;
	static char lbuf[1024];
	static char rbuf[8192];
	static char cbuf[3];
	char *lbp;
	char *p;

	options(argc, argv);
	printf("eclair 0.20160314 %s%s\n",
		opt.interactive ? "live debug mode" : "using dump file: ",
		opt.interactive ? "" : opt.dump_path);
	if (opt.help) {
		print_usage();
		return 2;
	}

	error = setup_symbols(opt.kernel_path);
	if (error) {
		perror("setup_symbols");
		print_usage();
		return 1;
	}

	if (opt.interactive) {
		error = setup_dump_interactive();
	}
	else {
		error = setup_dump(opt.dump_path);
	}

	if (error) {
		perror("setup_dump");
		print_usage();
		return 1;
	}

	error = setup_constants();
	if (error) {
		perror("setup_constants");
		return 1;
	}

	error = setup_threads();
	if (error) {
		perror("setup_threads");
		return 1;
	}

	error = start_gdb();
	if (error) {
		perror("start_gdb");
		return 1;
	}

	mode = 0;
	sum = 0;
	lbp = NULL;
	while (!f_done) {
		c = fgetc(ifp);
		if (c < 0) {
			break;
		}

		if (mode == 0) {
			if (c == '$') {
				mode = 1;
				sum = 0;
				lbp = lbuf;
				continue;
			}
			// Interrupt remote
			else if (opt.interactive &&
					c == 0x03) {
				mode = 0;
				fputc('+', ofp);
				sprintf(lbuf, "%s", "Ctrl-C");
				command(lbuf, rbuf, sizeof(rbuf));
				sum = 0;
				for (p = rbuf; *p != '\0'; ++p) {
					sum += *p;
				}
				fprintf(ofp, "$%s#%02x", rbuf, sum);
				fflush(ofp);
				continue;
			}
		}
		if (mode == 1) {
			if (c == '#') {
				mode = 2;
				*lbp = '\0';
				continue;
			}
			sum += c;
			*lbp++ = c;
		}
		if (mode == 2) {
			cbuf[0] = c;
			mode = 3;
			continue;
		}
		if (mode == 3) {
			cbuf[1] = c;
			cbuf[2] = '\0';
			check = strtol(cbuf, NULL, 16);
			if (check != sum) {
				mode = 0;
				fputc('-', ofp);
				continue;
			}
			mode = 0;
			fputc('+', ofp);
			command(lbuf, rbuf, sizeof(rbuf));
			sum = 0;
			for (p = rbuf; *p != '\0'; ++p) {
				sum += *p;
			}
			fprintf(ofp, "$%s#%02x", rbuf, sum);
			fflush(ofp);
			continue;
		}
	}

	return 0;
} /* main() */

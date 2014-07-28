/**
 * \file executer/user/mcexec.c
 *  License details are found in the file LICENSE.
 * \brief
 *  ....
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 *      Copyright (C) 2012  RIKEN AICS
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 *      Copyright (C) 2012 - 2013 Hitachi, Ltd.
 * \author Tomoki Shirasawa  <tomoki.shirasawa.kk@hitachi-solutions.com> \par
 *      Copyright (C) 2012 - 2013 Hitachi, Ltd.
 * \author Balazs Gerofi  <bgerofi@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2013  The University of Tokyo
 */
/*
 * HISTORY:
 *  2013/11/07 hamada added <sys/resource.h> which is required by getrlimit(2)
 *  2013/10/21 nakamura exclude interpreter's segment from data region
 *  2013/10/11 nakamura mcexec: add a upper limit of the stack size
 *  2013/10/11 nakamura mcexec: add a path prefix for interpreter search
 *  2013/10/11 nakamura mcexec: add a interpreter invocation
 *  2013/10/08 nakamura add a AT_ENTRY entry to the auxiliary vector
 *  2013/09/02 shirasawa add terminate thread
 *  2013/08/19 shirasawa mcexec forward signal to MIC process
 *  2013/08/07 nakamura add page fault forwarding
 *  2013/07/26 shirasawa mcexec print signum or exit status
 *  2013/07/17 nakamura create more mcexec thread so that all cpu to be serviced
 *  2013/04/17 nakamura add generic system call forwarding
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <asm/unistd.h>
#include "../include/uprotocol.h"
#include <sched.h>

#include <termios.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <signal.h>

//#define DEBUG

#ifndef DEBUG
#define __dprint(msg, ...)
#define __dprintf(arg, ...)
#define __eprint(msg, ...)
#define __eprintf(format, ...)
#else
#define __dprint(msg, ...)  {printf("%s: " msg, __FUNCTION__);fflush(stdout);}
#define __dprintf(format, ...)  {printf("%s: " format, __FUNCTION__, \
                                       __VA_ARGS__);fflush(stdout);}
#define __eprint(msg, ...)  {fprintf(stderr, "%s: " msg, __FUNCTION__);fflush(stderr);}
#define __eprintf(format, ...)  {fprintf(stderr, "%s: " format, __FUNCTION__, \
                                        __VA_ARGS__);fflush(stderr);}
#endif

#ifdef USE_SYSCALL_MOD_CALL
extern int mc_cmd_server_init();
extern void mc_cmd_server_exit();
extern void mc_cmd_handle(int fd, int cpu, unsigned long args[6]);

#ifdef CMD_DCFA
extern void ibmic_cmd_server_exit();
extern int ibmic_cmd_server_init();
#endif

#ifdef CMD_DCFAMPI
extern void dcfampi_cmd_server_exit();
extern int dcfampi_cmd_server_init();
#endif

int __glob_argc = -1;
char **__glob_argv = 0;
#endif

typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;

#ifdef NCCS
#undef NCCS
#endif

#define NCCS 19
struct kernel_termios {
	tcflag_t c_iflag;               /* input mode flags */
        tcflag_t c_oflag;               /* output mode flags */
	tcflag_t c_cflag;               /* control mode flags */
	tcflag_t c_lflag;               /* local mode flags */
	cc_t c_line;                    /* line discipline */
	cc_t c_cc[NCCS];                /* control characters */
};

int main_loop(int fd, int cpu, pthread_mutex_t *lock);

static int fd;
static char *altroot;
static const char rlimit_stack_envname[] = "MCKERNEL_RLIMIT_STACK";

pid_t gettid(void)
{
	return syscall(SYS_gettid);
}

struct program_load_desc *load_elf(FILE *fp, char **interp_pathp)
{
	Elf64_Ehdr hdr;
	Elf64_Phdr phdr;
	int i, j, nhdrs = 0;
	struct program_load_desc *desc;
	unsigned long load_addr = 0;
	int load_addr_set = 0;
	static char interp_path[PATH_MAX];
	ssize_t ss;

	*interp_pathp = NULL;

	if (fread(&hdr, sizeof(hdr), 1, fp) < 1) {
		__eprint("Cannot read Ehdr.\n");
		return NULL;
	}
	if (memcmp(hdr.e_ident, ELFMAG, SELFMAG)) {
		__eprint("ELFMAG mismatched.\n");
		return NULL;
	}
	fseek(fp, hdr.e_phoff, SEEK_SET);
	for (i = 0; i < hdr.e_phnum; i++) {
		if (fread(&phdr, sizeof(phdr), 1, fp) < 1) {
			__eprintf("Loading phdr failed (%d)\n", i);
			return NULL;
		}
		if (phdr.p_type == PT_LOAD) {
			nhdrs++;
		}
	}
	
	desc = malloc(sizeof(struct program_load_desc)
	              + sizeof(struct program_image_section) * nhdrs);
	fseek(fp, hdr.e_phoff, SEEK_SET);
	j = 0;
	desc->num_sections = nhdrs;
	desc->stack_prot = PROT_READ | PROT_WRITE | PROT_EXEC;	/* default */
	for (i = 0; i < hdr.e_phnum; i++) {
		if (fread(&phdr, sizeof(phdr), 1, fp) < 1) {
			__eprintf("Loading phdr failed (%d)\n", i);
			return NULL;
		}
		if (phdr.p_type == PT_INTERP) {
			if (phdr.p_filesz > sizeof(interp_path)) {
				__eprint("too large PT_INTERP segment\n");
				return NULL;
			}
			ss = pread(fileno(fp), interp_path, phdr.p_filesz,
					phdr.p_offset);
			if (ss <= 0) {
				__eprint("cannot read PT_INTERP segment\n");
				return NULL;
			}
			interp_path[ss] = '\0';
			*interp_pathp = interp_path;
		}
		if (phdr.p_type == PT_LOAD) {
			desc->sections[j].vaddr = phdr.p_vaddr;
			desc->sections[j].filesz = phdr.p_filesz;
			desc->sections[j].offset = phdr.p_offset;
			desc->sections[j].len = phdr.p_memsz;
			desc->sections[j].interp = 0;
			desc->sections[j].fp = fp;

			desc->sections[j].prot = PROT_NONE;
			desc->sections[j].prot |= (phdr.p_flags & PF_R)? PROT_READ: 0;
			desc->sections[j].prot |= (phdr.p_flags & PF_W)? PROT_WRITE: 0;
			desc->sections[j].prot |= (phdr.p_flags & PF_X)? PROT_EXEC: 0;

			__dprintf("%d: (%s) %lx, %lx, %lx, %lx, %x\n",
				  j, (phdr.p_type == PT_LOAD ? "PT_LOAD" : "PT_TLS"), 
				  desc->sections[j].vaddr,
			          desc->sections[j].filesz,
			          desc->sections[j].offset,
			          desc->sections[j].len,
				  desc->sections[j].prot);
			j++;

			if (!load_addr_set) {
				load_addr_set = 1;
				load_addr = phdr.p_vaddr - phdr.p_offset;
			}
		}
		if (phdr.p_type == PT_GNU_STACK) {
			desc->stack_prot = PROT_NONE;
			desc->stack_prot |= (phdr.p_flags & PF_R)? PROT_READ: 0;
			desc->stack_prot |= (phdr.p_flags & PF_W)? PROT_WRITE: 0;
			desc->stack_prot |= (phdr.p_flags & PF_X)? PROT_EXEC: 0;
		}
	}
	desc->pid = getpid();
	desc->entry = hdr.e_entry;

	desc->at_phdr = load_addr + hdr.e_phoff;
	desc->at_phent = sizeof(phdr);
	desc->at_phnum = hdr.e_phnum;
	desc->at_entry = hdr.e_entry;

	return desc;
}

char *search_file(char *orgpath, int mode)
{
	int error;
	static char modpath[PATH_MAX];
	int n;

	error = access(orgpath, mode);
	if (!error) {
		return orgpath;
	}

	n = snprintf(modpath, sizeof(modpath), "%s/%s", altroot, orgpath);
	if (n >= sizeof(modpath)) {
		__eprintf("modified path too long: %s/%s\n", altroot, orgpath);
		return NULL;
	}

	error = access(modpath, mode);
	if (!error) {
		return modpath;
	}

	return NULL;
}

struct program_load_desc *load_interp(struct program_load_desc *desc0, FILE *fp)
{
	Elf64_Ehdr hdr;
	Elf64_Phdr phdr;
	int i, j, nhdrs = 0;
	struct program_load_desc *desc = desc0;
	size_t newsize;
	unsigned long align;

	if (fread(&hdr, sizeof(hdr), 1, fp) < 1) {
		__eprint("Cannot read Ehdr.\n");
		return NULL;
	}
	if (memcmp(hdr.e_ident, ELFMAG, SELFMAG)) {
		__eprint("ELFMAG mismatched.\n");
		return NULL;
	}
	fseek(fp, hdr.e_phoff, SEEK_SET);
	for (i = 0; i < hdr.e_phnum; i++) {
		if (fread(&phdr, sizeof(phdr), 1, fp) < 1) {
			__eprintf("Loading phdr failed (%d)\n", i);
			return NULL;
		}
		if (phdr.p_type == PT_LOAD) {
			nhdrs++;
		}
	}

	nhdrs += desc->num_sections;
	newsize = sizeof(struct program_load_desc)
		+ (nhdrs * sizeof(struct program_image_section));
	desc = realloc(desc, newsize);
	if (!desc) {
		__eprintf("realloc(%#lx) failed\n", (long)newsize);
		return NULL;
	}

	fseek(fp, hdr.e_phoff, SEEK_SET);
	align = 1;
	j = desc->num_sections;
	for (i = 0; i < hdr.e_phnum; i++) {
		if (fread(&phdr, sizeof(phdr), 1, fp) < 1) {
			__eprintf("Loading phdr failed (%d)\n", i);
			return NULL;
		}
		if (phdr.p_type == PT_INTERP) {
			__eprint("PT_INTERP on interp\n");
			return NULL;
		}
		if (phdr.p_type == PT_LOAD) {
			desc->sections[j].vaddr = phdr.p_vaddr;
			desc->sections[j].filesz = phdr.p_filesz;
			desc->sections[j].offset = phdr.p_offset;
			desc->sections[j].len = phdr.p_memsz;
			desc->sections[j].interp = 1;
			desc->sections[j].fp = fp;

			desc->sections[j].prot = PROT_NONE;
			desc->sections[j].prot |= (phdr.p_flags & PF_R)? PROT_READ: 0;
			desc->sections[j].prot |= (phdr.p_flags & PF_W)? PROT_WRITE: 0;
			desc->sections[j].prot |= (phdr.p_flags & PF_X)? PROT_EXEC: 0;

			if (phdr.p_align > align) {
				align = phdr.p_align;
			}

			__dprintf("%d: (%s) %lx, %lx, %lx, %lx, %x\n",
				  j, (phdr.p_type == PT_LOAD ? "PT_LOAD" : "PT_TLS"),
				  desc->sections[j].vaddr,
			          desc->sections[j].filesz,
			          desc->sections[j].offset,
			          desc->sections[j].len,
				  desc->sections[j].prot);
			j++;
		}
	}
	desc->num_sections = j;

	desc->entry = hdr.e_entry;
	desc->interp_align = align;

	return desc;
}

unsigned char *dma_buf;

int load_elf_desc(char *filename, struct program_load_desc **desc_p)
{
	FILE *fp;
	FILE *interp = NULL;
	char *interp_path;
	struct program_load_desc *desc;

	fp = fopen(filename, "rb");
	if (!fp) {
		fprintf(stderr, "Error: Failed to open %s\n", filename);
		return 1;
	}

	desc = load_elf(fp, &interp_path);
	if (!desc) {
		fclose(fp);
		fprintf(stderr, "Error: Failed to parse ELF!\n");
		return 1;
	}

	if (interp_path) {
		char *path;

		path = search_file(interp_path, X_OK);
		if (!path) {
			fprintf(stderr, "Error: interp not found: %s\n", interp_path);
			return 1;
		}

		interp = fopen(path, "rb");
		if (!interp) {
			fprintf(stderr, "Error: Failed to open %s\n", path);
			return 1;
		}

		desc = load_interp(desc, interp);
		if (!desc) {
			fprintf(stderr, "Error: Failed to parse interp!\n");
			return 1;
		}
	}

	__dprintf("# of sections: %d\n", desc->num_sections);
	
	*desc_p = desc;
	return 0;
}

#define PAGE_SIZE 4096
#define PAGE_MASK ~((unsigned long)PAGE_SIZE - 1)

void transfer_image(int fd, struct program_load_desc *desc)
{
	struct remote_transfer pt;
	unsigned long s, e, flen, rpa;
	int i, l, lr;
	FILE *fp;

	for (i = 0; i < desc->num_sections; i++) {
		fp = desc->sections[i].fp;
		s = (desc->sections[i].vaddr) & PAGE_MASK;
		e = (desc->sections[i].vaddr + desc->sections[i].len
		     + PAGE_SIZE - 1) & PAGE_MASK;
		rpa = desc->sections[i].remote_pa;

		fseek(fp, desc->sections[i].offset, SEEK_SET);
		flen = desc->sections[i].filesz;

		__dprintf("seeked to %lx | size %ld\n",
		          desc->sections[i].offset, flen);

		while (s < e) {
			pt.rphys = rpa;
			pt.userp = dma_buf;
			pt.size = PAGE_SIZE;
			pt.direction = MCEXEC_UP_TRANSFER_TO_REMOTE;
			lr = 0;
			
			memset(dma_buf, 0, PAGE_SIZE);
			if (s < desc->sections[i].vaddr) {
				l = desc->sections[i].vaddr 
					& (PAGE_SIZE - 1);
				lr = PAGE_SIZE - l;
				if (lr > flen) {
					lr = flen;
				}
				fread(dma_buf + l, 1, lr, fp); 
				flen -= lr;
			} 
			else if (flen > 0) {
				if (flen > PAGE_SIZE) {
					lr = PAGE_SIZE;
				} else {
					lr = flen;
				}
				fread(dma_buf, 1, lr, fp);
				flen -= lr;
			} 
			s += PAGE_SIZE;
			rpa += PAGE_SIZE;
			
			/* No more left to upload.. */
			if (lr == 0 && flen == 0) break;

			if (ioctl(fd, MCEXEC_UP_TRANSFER,
						(unsigned long)&pt)) {
				perror("dma");
				break;
			}
		}
	}
}

void print_desc(struct program_load_desc *desc)
{
	int i;

	__dprintf("Desc (%p)\n", desc);
	__dprintf("Status = %d, CPU = %d, pid = %d, entry = %lx, rp = %lx\n",
	          desc->status, desc->cpu, desc->pid, desc->entry,
	          desc->rprocess);
	for (i = 0; i < desc->num_sections; i++) {
		__dprintf("vaddr: %lx, mem_len: %lx, remote_pa: %lx, files: %lx\n", 
		          desc->sections[i].vaddr, desc->sections[i].len, 
				  desc->sections[i].remote_pa, desc->sections[i].filesz);
	}
}

#define PIN_SHIFT  12
#define PIN_SIZE  (1 << PIN_SHIFT)
#define PIN_MASK  ~(unsigned long)(PIN_SIZE - 1)

#if 0
unsigned long dma_buf_pa;
#endif


void print_flat(char *flat) 
{
	char **string;
		
	__dprintf("counter: %d\n", *((int *)flat));

	string = (char **)(flat + sizeof(int));
	while (*string) {
		
		__dprintf("%s\n", (flat + (unsigned long)(*string)));

		++string;
	}
}

/* 
 * Flatten out a (char **) string array into the following format:
 * [nr_strings][char *offset of string_0]...[char *offset of string_n-1][NULL][string0]...[stringn_1]
 * if nr_strings == -1, we assume the last item is NULL 
 *
 * NOTE: copy this string somewhere, add the address of the string to each offset
 * and we get back a valid argv or envp array.
 *
 * returns the total length of the flat string and updates flat to
 * point to the beginning.
 */
int flatten_strings(int nr_strings, char **strings, char **flat)
{
	int full_len, string_i;
	unsigned long flat_offset;
	char *_flat;

	/* How many strings do we have? */
	if (nr_strings == -1) {
		for (nr_strings = 0; strings[nr_strings]; ++nr_strings); 
	}

	/* Count full length */
	full_len = sizeof(int) + sizeof(char *); // Counter and terminating NULL
	for (string_i = 0; string_i < nr_strings; ++string_i) {
		// Pointer + actual value
		full_len += sizeof(char *) + strlen(strings[string_i]) + 1; 
	}

	_flat = (char *)malloc(full_len);
	if (!_flat) {
		return 0;
	}

	memset(_flat, 0, full_len);

	/* Number of strings */
	*((int*)_flat) = nr_strings;
	
	// Actual offset
	flat_offset = sizeof(int) + sizeof(char *) * (nr_strings + 1); 

	for (string_i = 0; string_i < nr_strings; ++string_i) {
		
		/* Fabricate the string */
		*((char **)(_flat + sizeof(int) + string_i * sizeof(char *))) = (void *)flat_offset;
		memcpy(_flat + flat_offset, strings[string_i], strlen(strings[string_i]) + 1);
		flat_offset += strlen(strings[string_i]) + 1;

	}

	*flat = _flat;
	return full_len;
}

//#define NUM_HANDLER_THREADS	248

struct thread_data_s {
	pthread_t thread_id;
	int fd;
	int cpu;
	int ret;
	pid_t	tid;
	int terminate;
	pthread_mutex_t *lock;
	pthread_barrier_t *init_ready;
} *thread_data;
int ncpu;
pid_t master_tid;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_barrier_t init_ready;

static void *main_loop_thread_func(void *arg)
{
	struct thread_data_s *td = (struct thread_data_s *)arg;

	td->tid = gettid();
	pthread_barrier_wait(&init_ready);
	td->ret = main_loop(td->fd, td->cpu, td->lock);

	return NULL;
}

void
sendsig(int sig, siginfo_t *siginfo, void *context)
{
	pid_t	pid = getpid();
	pid_t	tid = gettid();
	int	i;
	int	cpu;
	struct signal_desc sigdesc;


	if(siginfo->si_pid == pid &&
	   siginfo->si_signo == SIGINT)
		return;
	if(tid == thread_data[0].tid){
		cpu = thread_data[0].cpu;
		tid = master_tid;
	}
	else if(tid != master_tid){
		for(i = 1; i < ncpu; i++)
			if(thread_data[i].tid == tid){
				if(thread_data[i].terminate)
					return;
				break;
			}
		if(i != ncpu)
			cpu = thread_data[i].cpu;
		else{
			cpu = 0;
			tid = -1;
		}
	}
	else{
		cpu = 0;
		tid = -1;
	}

	sigdesc.cpu = cpu;
	sigdesc.pid = (int)pid;
	sigdesc.tid = (int)tid;
	sigdesc.sig = sig;
	if (ioctl(fd, MCEXEC_UP_SEND_SIGNAL, &sigdesc) != 0) {
		perror("send_signal");
		close(fd);
		exit(1);
	}
}

static int reduce_stack(struct rlimit *orig_rlim, char *argv[])
{
	int n;
	char newval[40];
	int error;
	struct rlimit new_rlim;

	/* save original value to environment variable */
	n = snprintf(newval, sizeof(newval), "%#lx,%#lx",
			(unsigned long)orig_rlim->rlim_cur,
			(unsigned long)orig_rlim->rlim_max);
	if (n >= sizeof(newval)) {
		__eprintf("snprintf(%s):buffer overflow\n",
				rlimit_stack_envname);
		return 1;
	}

#define	DO_NOT_OVERWRITE	0
	error = setenv(rlimit_stack_envname, newval, DO_NOT_OVERWRITE);
	if (error) {
		__eprintf("failed to setenv(%s)\n", rlimit_stack_envname);
		return 1;
	}

	/* exec() myself with small stack */
#define	MCEXEC_STACK_SIZE	(10 * 1024 * 1024)	/* 10 MiB */
	new_rlim.rlim_cur = MCEXEC_STACK_SIZE;
	new_rlim.rlim_max = orig_rlim->rlim_max;

	error = setrlimit(RLIMIT_STACK, &new_rlim);
	if (error) {
		__eprint("failed to setrlimit(RLIMIT_STACK)\n");
		return 1;
	}

	execv("/proc/self/exe", argv);

	__eprint("failed to execv(myself)\n");
	return 1;
}

void print_usage(char **argv)
{
	fprintf(stderr, "Usage: %s [-c target_core] [<mcos-id>] (program) [args...]\n", argv[0]);
}

void init_sigaction(void)
{
	int i;

	master_tid = gettid();
	for (i = 1; i <= 64; i++) {
		if (i != SIGCHLD && i != SIGCONT && i != SIGSTOP &&
		    i != SIGTSTP && i != SIGTTIN && i != SIGTTOU) {
			struct sigaction act;

			sigaction(i, NULL, &act);
			act.sa_sigaction = sendsig;
			act.sa_flags &= ~(SA_RESTART);
			act.sa_flags |= SA_SIGINFO;
			sigaction(i, &act, NULL);
		}
	}
}		

void init_worker_threads(int fd) 
{
	int i;

	pthread_mutex_init(&lock, NULL);
	pthread_barrier_init(&init_ready, NULL, ncpu + 2);

	for (i = 0; i <= ncpu; ++i) {
		int ret;

		thread_data[i].fd = fd;
		thread_data[i].cpu = i;
		thread_data[i].lock = &lock;
		thread_data[i].init_ready = &init_ready;
		thread_data[i].terminate = 0;
		ret = pthread_create(&thread_data[i].thread_id, NULL, 
		                     &main_loop_thread_func, &thread_data[i]);

		if (ret < 0) {
			printf("ERROR: creating syscall threads\n");
			exit(1);
		}
	}

	pthread_barrier_wait(&init_ready);
}	

char dev[64];

int main(int argc, char **argv)
{
//	int fd;
#if 0	
	int fdm;
	long r;
#endif
	struct program_load_desc *desc;
	int envs_len;
	char *envs;
	char *args;
	char *p;
	int i;
	int error;
	struct rlimit rlim_stack;
	unsigned long lcur;
	unsigned long lmax;
	int target_core = 0;
	int mcosid = 0;
	int opt;

#ifdef USE_SYSCALL_MOD_CALL
	__glob_argc = argc;
	__glob_argv = argv;
#endif

	altroot = getenv("MCEXEC_ALT_ROOT");
	if (!altroot) {
		altroot = "/usr/linux-k1om-4.7/linux-k1om";
	}
	
	/* Collect environment variables */
	envs_len = flatten_strings(-1, environ, &envs);
	envs = envs;

	error = getrlimit(RLIMIT_STACK, &rlim_stack);
	if (error) {
		fprintf(stderr, "Error: Failed to get stack limit.\n");
		return 1;
	}
#define	MCEXEC_MAX_STACK_SIZE	(1024 * 1024 * 1024)	/* 1 GiB */
	if (rlim_stack.rlim_cur > MCEXEC_MAX_STACK_SIZE) {
		/* need to call reduce_stack() before modifying the argv[] */
		(void)reduce_stack(&rlim_stack, argv);	/* no return, unless failure */
		fprintf(stderr, "Error: Failed to reduce stack.\n");
		return 1;
	}
           
	/* Parse options ("+" denotes stop at the first non-option) */
	while ((opt = getopt(argc, argv, "+c:")) != -1) {
		switch (opt) {
			case 'c':
				target_core = atoi(optarg);
				break;
			
			default: /* '?' */
				print_usage(argv);
				exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		print_usage(argv);
		exit(EXIT_FAILURE);
	}

	/* Determine OS device */
	if (isdigit(*argv[optind])) {
		mcosid = atoi(argv[optind]);
		++optind;
	}

	sprintf(dev, "/dev/mcos%d", mcosid);

	/* No more arguments? */
	if (optind >= argc) {
		print_usage(argv);
		exit(EXIT_FAILURE);
	}

	__dprintf("target_core: %d, device: %s, command: ", target_core, dev);
	for (i = optind; i < argc; ++i) {
		__dprintf("%s ", argv[i]);
	}
	__dprintf("\n");

	if (load_elf_desc(argv[optind], &desc) != 0) {
		fprintf(stderr, "error: loading file: %s\n", argv[optind]);
		return 1;
	}
	
	desc->envs_len = envs_len;
	desc->envs = envs;
	//print_flat(envs);

	desc->args_len = flatten_strings(-1, argv + optind, &args);
	desc->args = args;
	//print_flat(args);

	desc->cpu = target_core;
	p = getenv(rlimit_stack_envname);
	if (p) {
		errno = 0;
		lcur = strtoul(p, &p, 0);
		if (errno || (*p != ',')) {
			fprintf(stderr, "Error: Failed to parse %s\n",
					rlimit_stack_envname);
			return 1;
		}
		errno = 0;
		lmax = strtoul(p+1, &p, 0);
		if (errno || (*p != '\0')) {
			fprintf(stderr, "Error: Failed to parse %s\n",
					rlimit_stack_envname);
			return 1;
		}
		if (lmax > rlim_stack.rlim_max) {
			lmax = rlim_stack.rlim_max;
		}
		if (lcur > lmax) {
			lcur = lmax;
		}
		rlim_stack.rlim_cur = lcur;
		rlim_stack.rlim_max = lmax;
	}
	desc->rlimit_stack_cur = rlim_stack.rlim_cur;
	desc->rlimit_stack_max = rlim_stack.rlim_max;

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Error: Failed to open %s.\n", dev);
		return 1;
	}

	ncpu = ioctl(fd, MCEXEC_UP_GET_CPU, 0);
	if(ncpu == -1){
		fprintf(stderr, "No CPU found.\n");
		return 1;
	}

	thread_data = (struct thread_data_s *)malloc(sizeof(struct thread_data_s) * (ncpu + 1));
	memset(thread_data, '\0', sizeof(struct thread_data_s) * (ncpu + 1));

#if 0	
	fdm = open("/dev/fmem", O_RDWR);
	if (fdm < 0) {
		fprintf(stderr, "Error: Failed to open /dev/fmem.\n");
		return 1;
	}

	if ((r = ioctl(fd, MCEXEC_UP_PREPARE_DMA, 
	               (unsigned long)&dma_buf_pa)) < 0) {
		perror("prepare_dma");
		close(fd);
		return 1;
	}

	dma_buf = mmap(NULL, PIN_SIZE, PROT_READ | PROT_WRITE,
	               MAP_SHARED, fdm, dma_buf_pa);
	__dprintf("DMA Buffer: %lx, %p\n", dma_buf_pa, dma_buf);
#endif

	dma_buf = mmap(0, PIN_SIZE, PROT_READ | PROT_WRITE, 
	               (MAP_ANONYMOUS | MAP_PRIVATE), -1, 0);
	if (dma_buf == (void *)-1) {
		__dprint("error: allocating DMA area\n");
		exit(1);
	}
	
	/* PIN buffer */
	if (mlock(dma_buf, (size_t)PIN_SIZE)) {
		__dprint("ERROR: locking dma_buf\n");
		exit(1);
	}

	if (ioctl(fd, MCEXEC_UP_PREPARE_IMAGE, (unsigned long)desc) != 0) {
		perror("prepare");
		close(fd);
		return 1;
	}

	print_desc(desc);
	transfer_image(fd, desc);
	fflush(stdout);
	fflush(stderr);
	
#ifdef USE_SYSCALL_MOD_CALL
	/**
	 * TODO: need mutex for static structures
	 */
	if(mc_cmd_server_init()){
		fprintf(stderr, "Error: cmd server init failed\n");
		return 1;
	}

#ifdef CMD_DCFA
	if(ibmic_cmd_server_init()){
		fprintf(stderr, "Error: Failed to initialize ibmic_cmd_server.\n");
		return -1;
	}
#endif

#ifdef CMD_DCFAMPI
	if(dcfampi_cmd_server_init()){
		fprintf(stderr, "Error: Failed to initialize dcfampi_cmd_server.\n");
		return -1;
	}
#endif
	__dprint("mccmd server initialized\n");
#endif

	init_sigaction();

	init_worker_threads(fd);

	if (ioctl(fd, MCEXEC_UP_START_IMAGE, (unsigned long)desc) != 0) {
		perror("exec");
		close(fd);
		return 1;
	}

	for (i = 0; i <= ncpu; ++i) {
		pthread_join(thread_data[i].thread_id, NULL);
	}

	return 0;
}


void do_syscall_return(int fd, int cpu,
                       long ret, int n, unsigned long src, unsigned long dest,
                       unsigned long sz)
{
	struct syscall_ret_desc desc;

	desc.cpu = cpu;
	desc.ret = ret;
	desc.src = src;
	desc.dest = dest;
	desc.size = sz;
	
	if (ioctl(fd, MCEXEC_UP_RET_SYSCALL, (unsigned long)&desc) != 0) {
		perror("ret");
	}
}

void do_syscall_load(int fd, int cpu, unsigned long dest, unsigned long src,
                     unsigned long sz)
{
	struct syscall_load_desc desc;

	desc.cpu = cpu;
	desc.src = src;
	desc.dest = dest;
	desc.size = sz;

	if (ioctl(fd, MCEXEC_UP_LOAD_SYSCALL, (unsigned long)&desc) != 0){
		perror("load");
	}
}

static long
do_generic_syscall(
		struct syscall_wait_desc *w)
{
	long	ret;

	__dprintf("do_generic_syscall(%ld)\n", w->sr.number);

	errno = 0;
	ret = syscall(w->sr.number, w->sr.args[0], w->sr.args[1], w->sr.args[2],
		 w->sr.args[3], w->sr.args[4], w->sr.args[5]);
	if (errno != 0) {
		ret = -errno;
	}

	__dprintf("do_generic_syscall(%ld):%ld (%#lx)\n", w->sr.number, ret, ret);
	return ret;
}

static void
kill_thread(unsigned long cpu)
{
	if(cpu >= 0 && cpu < ncpu){
		pthread_kill(thread_data[cpu].thread_id, SIGINT);
	}
	else{
		int	i;

		for (i = 0; i < ncpu; ++i) {
			pthread_kill(thread_data[i].thread_id, SIGINT);
		}
	}
}

static long do_strncpy_from_user(int fd, void *dest, void *src, unsigned long n)
{
	struct strncpy_from_user_desc desc;
	int ret;

	desc.dest = dest;
	desc.src = src;
	desc.n = n;

	ret = ioctl(fd, MCEXEC_UP_STRNCPY_FROM_USER, (unsigned long)&desc);
	if (ret) {
		ret = -errno;
		perror("strncpy_from_user:ioctl");
		return ret;
	}

	return desc.result;
}

#define SET_ERR(ret) if (ret == -1) ret = -errno

int main_loop(int fd, int cpu, pthread_mutex_t *lock)
{
	struct syscall_wait_desc w;
	long ret;
	char *fn;
	int sig;
	int term;
	struct timeval tv;
	char pathbuf[PATH_MAX];

	w.cpu = cpu;
	w.pid = getpid();

	while (((ret = ioctl(fd, MCEXEC_UP_WAIT_SYSCALL, (unsigned long)&w)) == 0) || (ret == -1 && errno == EINTR)) {

		if (ret) {
			continue;
		}

		/* Don't print when got a msg to stdout */
		if (!(w.sr.number == __NR_write && w.sr.args[0] == 1))
			__dprintf("[%d] got syscall: %ld\n", cpu, w.sr.number);
		
		//pthread_mutex_lock(lock);

		switch (w.sr.number) {
		case __NR_open:
			ret = do_strncpy_from_user(fd, pathbuf, (void *)w.sr.args[0], PATH_MAX);
			if (ret >= PATH_MAX) {
				ret = -ENAMETOOLONG;
			}
			if (ret < 0) {
				do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
				break;
			}
			__dprintf("open: %s\n", pathbuf);

			fn = pathbuf;
			if(!strcmp(fn, "/proc/meminfo")){
				fn = "/admin/fs/attached/files/proc/meminfo";
			}
			else if(!strcmp(fn, "/proc/cpuinfo")){
				fn = "/admin/fs/attached/files/proc/cpuinfo";
			}
			else if(!strcmp(fn, "/sys/devices/system/cpu/online")){
				fn = "/admin/fs/attached/files/sys/devices/system/cpu/online";
			}
			ret = open(fn, w.sr.args[1], w.sr.args[2]);
			SET_ERR(ret);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_futex:
			ret = gettimeofday(&tv, NULL);
			SET_ERR(ret);
			__dprintf("gettimeofday=%016ld,%09ld\n",
					tv.tv_sec,
					tv.tv_usec);
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)&tv,
			                  w.sr.args[0], sizeof(struct timeval));
			break;

		case __NR_kill: // interrupt syscall
			kill_thread(w.sr.args[0]);
			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);
			break;
		case __NR_exit:
		case __NR_exit_group:
			sig = 0;
			term = 0;
			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);

			__dprintf("__NR_exit/__NR_exit_group: %ld (cpu_id: %d)\n",
					w.sr.args[0], cpu);
			if(w.sr.number == __NR_exit_group){
				sig = w.sr.args[0] & 0x7f;
				term = (w.sr.args[0] & 0xff00) >> 8;
				if(isatty(2)){
					if(sig)
						fprintf(stderr, "Terminate by signal %d\n", sig);
					else if(term)
						__dprintf("Exit status: %d\n", term);
				}
			}

#ifdef USE_SYSCALL_MOD_CALL
#ifdef CMD_DCFA
			ibmic_cmd_server_exit();
#endif

#ifdef CMD_DCFAMPI
			dcfampi_cmd_server_exit();
#endif
			mc_cmd_server_exit();
			__dprint("mccmd server exited\n");
#endif
			if(sig){
				signal(sig, SIG_DFL);
				kill(getpid(), sig);
				pause();
			}
			exit(term);

			//pthread_mutex_unlock(lock);
			return w.sr.args[0];

		case __NR_mmap:
		case __NR_munmap:
		case __NR_mprotect:
			/* reserved for internal use */
			do_syscall_return(fd, cpu, -ENOSYS, 0, 0, 0, 0);
			break;

#ifdef USE_SYSCALL_MOD_CALL
		case 303:{
			__dprintf("mcexec.c,mod_cal,mod=%ld,cmd=%ld\n", w.sr.args[0], w.sr.args[1]);
			mc_cmd_handle(fd, cpu, w.sr.args);
			break;
		}
#endif
		case __NR_fork: {
			int child;

			child = fork();

			switch (child) {
				/* Error */
				case -1:
					do_syscall_return(fd, cpu, -1, 0, 0, 0, 0);
					break;

				/* Child process */
				case 0: {
					int i;

					/* Reopen device fd */
					close(fd);
					fd = open(dev, O_RDWR);
					if (fd < 0) {
						/* TODO: tell parent something went wrong? */
						fprintf(stderr, "ERROR: opening %s\n", dev);
						return 1;
					}
					
					/* Reinit signals and syscall threads */
					init_sigaction();
					init_worker_threads(fd);

					__dprintf("pid(%d): signals and syscall threads OK\n", 
							getpid());
				
					/* TODO: does the forked thread run in a pthread context? */
					for (i = 0; i <= ncpu; ++i) {
						pthread_join(thread_data[i].thread_id, NULL);
					}

					return 0;
				}
				
				/* Parent */
				default:
					
					do_syscall_return(fd, cpu, child, 0, 0, 0, 0);
					break;
			}

			break;
		}

		case __NR_wait4: {
			int status;
			int ret;
			pid_t pid = w.sr.args[0];

			if ((ret = waitpid(pid, &status, 0)) != pid) {
				fprintf(stderr, "ERROR: waiting for %lu\n", w.sr.args[0]);
			}

			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;
		}

		case __NR_execve: {

			/* Execve phase */
			switch (w.sr.args[0]) {
				int ret = -1;
				struct program_load_desc *desc;
				struct remote_transfer trans;
				FILE *fp;
				int status;
				char path[2048];
				char *filename;

				/* Load descriptor phase */
				case 1:

					filename = (char *)w.sr.args[1];

					/* Is filename without path? */
					if (0 && strncmp(filename, "/", 1) 
						//&& strncmp(filename, ".", 1)
						) {

						char *PATH = getenv("PATH");
						fprintf(stderr, "PATH: %s\n", PATH);

						/* Open command for reading. */
						sprintf(path, "/usr/bin/which %s", filename);
						fp = popen(path, "r");
						if (fp == NULL) {
							fprintf(stderr, "execve(): failed to run which\n" );
							goto return_execve1;
						}

						/* Read the output a line at a time - output it. */
						if (fgets(path, sizeof(path)-1, fp) == NULL) {
							fprintf(stderr, "execve(): failed to read which\n" );
							pclose(fp);
							goto return_execve1;
						}

						/* close */
						pclose(fp);
					}
					else {
						sprintf(path, "%s", filename);
					}

					__dprintf("execve: filename: %s\n", filename);
					__dprintf("execve: LD_LIBRARY_PATH: %s\n", getenv("LD_LIBRARY_PATH") ? getenv("LD_LIBRARY_PATH") : "(empty)");

					if (load_elf_desc(path, &desc) != 0) {
						fprintf(stderr, 
							"execve(): error loading ELF for file %s\n", path);
						goto return_execve1;
					}

					__dprintf("execve(): load_elf_desc() for %s OK, num sections: %d\n",
						path, desc->num_sections);

					/* Copy descriptor to co-kernel side */
					trans.userp = (void*)desc;
					trans.rphys = w.sr.args[2];
					trans.size = sizeof(struct program_load_desc) + 
						sizeof(struct program_image_section) * 
						desc->num_sections;
					trans.direction = MCEXEC_UP_TRANSFER_TO_REMOTE;
					
					if (ioctl(fd, MCEXEC_UP_TRANSFER, &trans) != 0) {
						fprintf(stderr, 
							"execve(): error transfering ELF for file %s\n", 
							(char *)w.sr.args[1]);
						goto return_execve1;
					}
					
					__dprintf("execve(): load_elf_desc() for %s OK\n",
						path);

					/* We can't be sure next phase will succeed */
					/* TODO: what shall we do with fp in desc?? */
					free(desc);
					
					ret = 0;
return_execve1:
					do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
					break;

				/* Copy program image phase */
				case 2:
					
					/* Alloc descriptor */
					desc = malloc(w.sr.args[2]);
					if (!desc) {
						fprintf(stderr, "execve(): error allocating desc\n");
						goto return_execve2;
					}

					/* Copy descriptor from co-kernel side */
					trans.userp = (void*)desc;
					trans.rphys = w.sr.args[1];
					trans.size = w.sr.args[2];
					trans.direction = MCEXEC_UP_TRANSFER_FROM_REMOTE;
					
					if (ioctl(fd, MCEXEC_UP_TRANSFER, &trans) != 0) {
						fprintf(stderr, 
							"execve(): error obtaining ELF descriptor\n");
						goto return_execve1;
					}
					
					__dprintf("execve(): transfer ELF desc OK\n");

					transfer_image(fd, desc);	
					__dprintf("execve(): image transferred\n");

					ret = 0;
return_execve2:					
					do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
					break;

				default:
					fprintf(stderr, "execve(): ERROR: invalid execve phase\n");
					break;
			}

			break;
		}

		default:
			 ret = do_generic_syscall(&w);
			 do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		}
		
		//pthread_mutex_unlock(lock);
	}
	__dprint("timed out.\n");
	return 1;
}

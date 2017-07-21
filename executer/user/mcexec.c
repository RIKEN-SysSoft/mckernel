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
#include <sched.h>
#include <dirent.h>

#include <termios.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/fsuid.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/mount.h>
#include <include/generated/uapi/linux/version.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include "../include/uprotocol.h"
#include <getopt.h>
#include "archdep.h"
#include "arch_args.h"
#include "../../config.h"
#include <numa.h>
#include <numaif.h>
#include <sys/personality.h>

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
	
#define CHKANDJUMPF(cond, err, format, ...)								\
	do {																\
		if(cond) {														\
			__eprintf(format, __VA_ARGS__);								\
			ret = err;													\
			goto fn_fail;												\
		}																\
	} while(0)

#define CHKANDJUMP(cond, err, msg)										\
	do {																\
		if(cond) {														\
			__eprint(msg);												\
			ret = err;													\
			goto fn_fail;												\
		}																\
	} while(0)


#undef DEBUG_UTI

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

#ifdef ENABLE_MCOVERLAYFS
#undef ENABLE_MCOVERLAYFS
#ifndef RHEL_RELEASE_CODE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0) && LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
#define ENABLE_MCOVERLAYFS 1
#endif // LINUX_VERSION_CODE == 4.0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0) && LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
#define ENABLE_MCOVERLAYFS 1
#endif // LINUX_VERSION_CODE == 4.6
#else
#if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,3) 
#define ENABLE_MCOVERLAYFS 1
#endif // RHEL_RELEASE_CODE <= 7.3
#endif // RHEL_RELEASE_CODE
#endif // ENABLE_MCOVERLAYFS

typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;

struct sigfd {
	struct sigfd *next;
	int sigpipe[2];
};

struct sigfd *sigfdtop;


struct syscall_struct {
	int number;
	unsigned long args[6];
	unsigned long ret;
};

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

#define UTI_FLAG_NUMA_SET (1ULL<<1) /* Indicates NUMA_SET is specified */

#define UTI_FLAG_SAME_NUMA_DOMAIN (1ULL<<2)
#define UTI_FLAG_DIFFERENT_NUMA_DOMAIN (1ULL<<3)

#define UTI_FLAG_SAME_L1 (1ULL<<4)
#define UTI_FLAG_SAME_L2 (1ULL<<5)
#define UTI_FLAG_SAME_L3 (1ULL<<6)

#define UTI_FLAG_DIFFERENT_L1 (1ULL<<7)
#define UTI_FLAG_DIFFERENT_L2 (1ULL<<8)
#define UTI_FLAG_DIFFERENT_L3 (1ULL<<9)

#define UTI_FLAG_EXCLUSIVE_CPU (1ULL<<10)
#define UTI_FLAG_CPU_INTENSIVE (1ULL<<11)
#define UTI_FLAG_HIGH_PRIORITY (1ULL<<12)
#define UTI_FLAG_NON_COOPERATIVE (1ULL<<13)

/* Linux default value is used */
#define UTI_MAX_NUMA_DOMAINS (1024)

typedef struct uti_attr {
	/* UTI_CPU_SET environmental variable is used to denote the preferred
	   location of utility thread */
	uint64_t numa_set[(UTI_MAX_NUMA_DOMAINS + sizeof(uint64_t) * 8 - 1) /
	                  (sizeof(uint64_t) * 8)];
	uint64_t flags; /* Representing location and behavior hints by bitmap */
} uti_attr_t;

struct kuti_attr {
	long parent_cpuid;
	struct uti_attr attr;
};

struct thread_data_s;
int main_loop(struct thread_data_s *);

static int mcosid;
static int fd;
static char *exec_path = NULL;
static char *altroot;
static const char rlimit_stack_envname[] = "MCKERNEL_RLIMIT_STACK";
static const char ld_preload_envname[] = "MCKERNEL_LD_PRELOAD";
static int ischild;
static int enable_vdso = 1;
static int mpol_no_heap = 0;
static int mpol_no_stack = 0;
static int mpol_no_bss = 0;
static int mpol_shm_premap = 0;
static int no_bind_ikc_map = 0;
static unsigned long mpol_threshold = 0;
static unsigned long heap_extension = (4*1024);
static int profile = 0;
static int disable_sched_yield = 0;

/* Partitioned execution (e.g., for MPI) */
static int nr_processes = 0;
static int nr_threads = -1;

struct fork_sync {
	pid_t pid;
	int status;
	sem_t sem;
};

struct fork_sync_container {
	struct fork_sync_container *next;
	struct fork_sync *fs;
};

struct fork_sync_container *fork_sync_top;
pthread_mutex_t fork_sync_mutex = PTHREAD_MUTEX_INITIALIZER;

pid_t gettid(void)
{
	return syscall(SYS_gettid);
}

int tgkill(int tgid, int tid, int sig)
{
	return syscall(SYS_tgkill, tgid, tid, sig);
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
	memset(desc, '\0', sizeof(struct program_load_desc)
	                   + sizeof(struct program_image_section) * nhdrs);
	desc->shell_path[0] = '\0';
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
	desc->pgid = getpgid(0);
	if(*interp_pathp)
		desc->reloc = hdr.e_type == ET_DYN;
	desc->entry = hdr.e_entry;
	ioctl(fd, MCEXEC_UP_GET_CREDV, desc->cred);
	desc->at_phdr = load_addr + hdr.e_phoff;
	desc->at_phent = sizeof(phdr);
	desc->at_phnum = hdr.e_phnum;
	desc->at_entry = hdr.e_entry;
	desc->at_clktck = sysconf(_SC_CLK_TCK);

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

int lookup_exec_path(char *filename, char *path, int max_len, int execvp) 
{
	int found;
	int error;
	struct stat sb;
	char *link_path = NULL;

retry:
	found = 0;

	/* Is file not absolute path? */
	if (strncmp(filename, "/", 1)) {
		
		/* Is filename a single component without path? */
		while (strncmp(filename, ".", 1) && !strchr(filename, '/')) {

			char *token, *string, *tofree;
			char *PATH = getenv("COKERNEL_PATH");

			if (!execvp) {
				if (strlen(filename) + 1 > max_len) {
					return ENAMETOOLONG;
				}
				strcpy(path, filename);
				error = access(path, X_OK);
				if (error) {
					return errno;
				}
				found = 1;
				break;
			}

			if (!(PATH = getenv("COKERNEL_PATH"))) {
				PATH = getenv("PATH");
			}

			if (strlen(filename) >= 255) {
				return ENAMETOOLONG;
			}

			__dprintf("PATH: %s\n", PATH);

			/* strsep() modifies string! */
			tofree = string = strdup(PATH);
			if (string == NULL) {
				printf("lookup_exec_path(): copying PATH, not enough memory?\n");
				return ENOMEM;
			}

			while ((token = strsep(&string, ":")) != NULL) {

				error = snprintf(path, max_len, 
						"%s/%s", token, filename);
				if (error < 0 || error >= max_len) {
					fprintf(stderr, "lookup_exec_path(): array too small?\n");
					continue;
				}

				error = access(path, X_OK);
				if (error == 0) {
					found = 1;
					break;
				}
			}

			free(tofree);
			if(!found){
				return ENOENT;
			}
			break;
		}

		/* Not in path, file to be open from the working directory */
		if (!found) {
			error = snprintf(path, max_len, "%s", filename);

			if (error < 0 || error >= max_len) {
				fprintf(stderr, "lookup_exec_path(): array too small?\n");
				return ENOMEM;
			}

			found = 1;
		}
	}
	/* Absolute path */
	else if (!strncmp(filename, "/", 1)) {
		char *root = getenv("COKERNEL_EXEC_ROOT");

		if (root) {
			error = snprintf(path, max_len, "%s/%s", root, filename);
		}
		else {
			error = snprintf(path, max_len, "%s", filename);
		}

		if (error < 0 || error >= max_len) {
			fprintf(stderr, "lookup_exec_path(): array too small?\n");
			return ENOMEM;
		}

		found = 1;
	}

	if (link_path) {
		free(link_path);
		link_path = NULL;
	}

	/* Check whether the resolved path is a symlink */
	if (lstat(path, &sb) == -1) {
		__eprint("lookup_exec_path(): error stat\n");
		return errno;
	}

	if ((sb.st_mode & S_IFMT) == S_IFLNK) {
		link_path = malloc(max_len);
		if (!link_path) {
			fprintf(stderr, "lookup_exec_path(): error allocating\n");
			return ENOMEM;
		}
		
		error = readlink(path, link_path, max_len);
		if (error == -1 || error == max_len) {
			fprintf(stderr, "lookup_exec_path(): error readlink\n");
			return EINVAL;
		}
		link_path[error] = '\0';

		__dprintf("lookup_exec_path(): %s is link -> %s\n", path, link_path);

		if(link_path[0] != '/'){
			char *t = strrchr(path, '/');
			if(t){
				t++;
				strcpy(t, link_path);
				strcpy(link_path, path);
			}
		}
		filename = link_path;
		goto retry; 
	}
	
	if (!found) {
		fprintf(stderr, 
				"lookup_exec_path(): error finding file %s\n", filename);
		return ENOENT;
	}

	__dprintf("lookup_exec_path(): %s\n", path);

	return 0;
}

int load_elf_desc(char *filename, struct program_load_desc **desc_p, 
		char **shell_p)
{
	FILE *fp;
	FILE *interp = NULL;
	char *interp_path;
	char *shell = NULL;
	size_t shell_len = 0;
	struct program_load_desc *desc;
	int ret = 0;
	struct stat sb;
	char header[1024];

	if ((ret = access(filename, X_OK)) != 0) {
		fprintf(stderr, "Error: %s is not an executable?, errno: %d\n", 
			filename, errno);
		return errno;
	}
	
	if ((ret = stat(filename, &sb)) == -1) {
		fprintf(stderr, "Error: failed to stat %s\n", filename);
		return errno;
	}
	
	if (sb.st_size == 0) {
		fprintf(stderr, "Error: file %s is zero length\n", filename);
		return ENOEXEC;
	}

	fp = fopen(filename, "rb");
	if (!fp) {
		fprintf(stderr, "Error: Failed to open %s\n", filename);
		return errno;
	}

	if (fread(&header, 1, 2, fp) != 2) {
		fprintf(stderr, "Error: Failed to read header from %s\n", filename);
		return errno;
	}

	if (!strncmp(header, "#!", 2)) {
		
		if (getline(&shell, &shell_len, fp) == -1) {
			fprintf(stderr, "Error: reading shell path %s\n", filename);
		}

		fclose(fp);

		/* Delete new line character */
		shell[strlen(shell) - 1] = 0;
		*shell_p = shell;
		return 0;
	}

	rewind(fp);
	
	if ((ret = ioctl(fd, MCEXEC_UP_OPEN_EXEC, filename)) != 0) {
		fprintf(stderr, "Error: open_exec() fails for %s: %d (fd: %d)\n", 
			filename, ret, fd);
		return ret;
	}

	/* Drop old name if exists */
	if (exec_path) {
		free(exec_path);
		exec_path = NULL;
	}

	if (!strncmp("/", filename, 1)) {
		exec_path = strdup(filename);
		
		if (!exec_path) {
			fprintf(stderr, "WARNING: strdup(filename) failed\n");
			return ENOMEM;
		}
	}
	else {
		char *cwd = getcwd(NULL, 0);
		if (!cwd) {
			fprintf(stderr, "Error: getting current working dir pathname\n");
			return ENOMEM;
		}

		exec_path = malloc(strlen(cwd) + strlen(filename) + 2);
		if (!exec_path) {
			fprintf(stderr, "Error: allocating exec_path\n");
			return ENOMEM;
		}

		sprintf(exec_path, "%s/%s", cwd, filename);
		free(cwd);
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

int transfer_image(int fd, struct program_load_desc *desc)
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

		if (fseek(fp, desc->sections[i].offset, SEEK_SET) != 0) {
			fprintf(stderr, "transfer_image(): error: seeking file position\n");
			return -1;
		}
		flen = desc->sections[i].filesz;

		__dprintf("seeked to %lx | size %ld\n",
		          desc->sections[i].offset, flen);

		while (s < e) {
			memset(&pt, '\0', sizeof pt);
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
				if (fread(dma_buf + l, 1, lr, fp) != lr) {
					if (ferror(fp) > 0) {
						fprintf(stderr, "transfer_image(): error: accessing file\n");
						return -EINVAL;
					}
					else if (feof(fp) > 0) {
						fprintf(stderr, "transfer_image(): file too short?\n");
						return -EINVAL;
					}
					else {
						/* TODO: handle smaller reads.. */
						return -EINVAL;
					}
				}
				flen -= lr;
			} 
			else if (flen > 0) {
				if (flen > PAGE_SIZE) {
					lr = PAGE_SIZE;
				} else {
					lr = flen;
				}
				if (fread(dma_buf, 1, lr, fp) != lr) {
					if (ferror(fp) > 0) {
						fprintf(stderr, "transfer_image(): error: accessing file\n");
						return -EINVAL;
					}
					else if (feof(fp) > 0) {
						fprintf(stderr, "transfer_image(): file too short?\n");
						return -EINVAL;
					}
					else {
						/* TODO: handle smaller reads.. */
						return -EINVAL;
					}
				}
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

	return 0;
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
int flatten_strings(int nr_strings, char *first, char **strings, char **flat)
{
	int full_len, string_i;
	unsigned long flat_offset;
	char *_flat;

	/* How many strings do we have? */
	if (nr_strings == -1) {
		for (nr_strings = 0; strings[nr_strings]; ++nr_strings); 
	}

	/* Count full length */
	full_len = sizeof(long) + sizeof(char *); // Counter and terminating NULL
	if (first) {
		full_len += sizeof(char *) + strlen(first) + 1; 
	}

	for (string_i = 0; string_i < nr_strings; ++string_i) {
		// Pointer + actual value
		full_len += sizeof(char *) + strlen(strings[string_i]) + 1; 
	}

	full_len = (full_len + sizeof(long) - 1) & ~(sizeof(long) - 1);

	_flat = (char *)malloc(full_len);
	if (!_flat) {
		return 0;
	}

	memset(_flat, 0, full_len);

	/* Number of strings */
	*((long *)_flat) = nr_strings + (first ? 1 : 0);
	
	// Actual offset
	flat_offset = sizeof(long) + sizeof(char *) * (nr_strings + 1 + 
			(first ? 1 : 0)); 

	if (first) {
		*((char **)(_flat + sizeof(long))) = (void *)flat_offset;
		memcpy(_flat + flat_offset, first, strlen(first) + 1);
		flat_offset += strlen(first) + 1;
	}

	for (string_i = 0; string_i < nr_strings; ++string_i) {
		
		/* Fabricate the string */
		*((char **)(_flat + sizeof(long) + (string_i + (first ? 1 : 0)) 
					* sizeof(char *))) = (void *)flat_offset;
		memcpy(_flat + flat_offset, strings[string_i], strlen(strings[string_i]) + 1);
		flat_offset += strlen(strings[string_i]) + 1;
	}

	*flat = _flat;
	return full_len;
}

//#define NUM_HANDLER_THREADS	248

struct thread_data_s {
	struct thread_data_s *next;
	pthread_t thread_id;
	int cpu;
	int ret;
	pid_t	tid;
	int terminate;
	int remote_tid;
	int remote_cpu;
	int joined;
	pthread_mutex_t *lock;
	pthread_barrier_t *init_ready;
} *thread_data;

int ncpu;
int n_threads;

pid_t master_tid;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_barrier_t init_ready;

static void *main_loop_thread_func(void *arg)
{
	struct thread_data_s *td = (struct thread_data_s *)arg;

	td->tid = gettid();
	td->remote_tid = -1;
	if (td->init_ready)
		pthread_barrier_wait(td->init_ready);
	td->ret = main_loop(td);

	return NULL;
}

#define LOCALSIG SIGURG

void
sendsig(int sig, siginfo_t *siginfo, void *context)
{
	pid_t	pid;
	pid_t	tid;
	int	remote_tid;
	int	cpu;
	struct signal_desc sigdesc;
	struct thread_data_s *tp;
	int localthread;

	localthread = ioctl(fd, MCEXEC_UP_SIG_THREAD, 1);
	pid = getpid();
	tid = gettid();
	if (siginfo->si_pid == pid &&
	    siginfo->si_signo == LOCALSIG)
		goto out;

	if (siginfo->si_signo == SIGCHLD)
		goto out;

	for (tp = thread_data; tp; tp = tp->next) {
		if (siginfo->si_pid == pid &&
		    tp->tid == tid) {
			if (tp->terminate)
				goto out;
			break;
		}
		if (siginfo->si_pid != pid &&
		    tp->remote_tid == tid) {
			if (tp->terminate)
				goto out;
			break;
		}
	}
	if (tp) {
		remote_tid = tp->remote_tid;
		cpu = tp->remote_cpu;
	}
	else {
		cpu = 0;
		remote_tid = -1;
	}

	if (localthread) {
		memset(&sigdesc, '\0', sizeof sigdesc);
		sigdesc.cpu = cpu;
		sigdesc.pid = (int)pid;
		sigdesc.tid = remote_tid;
		sigdesc.sig = sig;
		memcpy(&sigdesc.info, siginfo, 128);
		if (ioctl(fd, MCEXEC_UP_SEND_SIGNAL, &sigdesc) != 0) {
			close(fd);
			exit(1);
		}
	}
	else {
		struct syscall_struct param;
		int rc;

		param.number = SYS_rt_sigaction;
		param.args[0] = sig;
		rc = ioctl(fd, MCEXEC_UP_SYSCALL_THREAD, &param);
		if (rc == -1);
		else if (param.ret == (unsigned long)SIG_IGN);
		else if (param.ret == (unsigned long)SIG_DFL) {
			if (sig != SIGCHLD && sig != SIGURG && sig != SIGCONT) {
				signal(sig, SIG_DFL);
				kill(getpid(), sig);
				for(;;)
					sleep(1);
			}
		}
		else {
			ioctl(fd, MCEXEC_UP_SIG_THREAD, 0);
			((void (*)(int, siginfo_t *, void *))param.ret)(sig,
			                                      siginfo, context);
			ioctl(fd, MCEXEC_UP_SIG_THREAD, 1);
		}
	}
out:
	if (!localthread)
		ioctl(fd, MCEXEC_UP_SIG_THREAD, 0);
}

long
act_signalfd4(struct syscall_wait_desc *w)
{
	struct sigfd *sfd;
	struct sigfd *sb;
	int mode = w->sr.args[0];
	int flags;
	int tmp;
	int rc = 0;
	struct signalfd_siginfo *info;

	switch(mode){
	    case 0: /* new signalfd */
		sfd = malloc(sizeof(struct sigfd));
		memset(sfd, '\0', sizeof(struct sigfd));
		tmp = w->sr.args[1];
		flags = 0;
		if(tmp & SFD_NONBLOCK)
			flags |= O_NONBLOCK;
		if(tmp & SFD_CLOEXEC)
			flags |= O_CLOEXEC;
		if (pipe2(sfd->sigpipe, flags) < 0) {
			perror("pipe2 failed:");
			return -1;
		}
		sfd->next = sigfdtop;
		sigfdtop = sfd;
		rc = sfd->sigpipe[0];
		break;
	    case 1: /* close signalfd */
		tmp = w->sr.args[1];
		for(sfd = sigfdtop, sb = NULL; sfd; sb = sfd, sfd = sfd->next)
			if(sfd->sigpipe[0] == tmp)
				break;
		if(!sfd)
			rc = -EBADF;
		else{
			if(sb)
				sb->next = sfd->next;
			else
				sigfdtop = sfd->next;
			close(sfd->sigpipe[0]);
			close(sfd->sigpipe[1]);
			free(sfd);
		}
		break;
	    case 2: /* push signal */
		tmp = w->sr.args[1];
		for(sfd = sigfdtop; sfd; sfd = sfd->next)
			if(sfd->sigpipe[0] == tmp)
				break;
		if(!sfd)
			rc = -EBADF;
		else{
			info = (struct signalfd_siginfo *)w->sr.args[2];
			if (write(sfd->sigpipe[1], info, sizeof(struct signalfd_siginfo))
					!= sizeof(struct signalfd_siginfo)) {
				fprintf(stderr, "error: writing sigpipe\n");
				rc = -EBADF;
			}
		}
		break;
	}
	return rc;
}

void
act_sigaction(struct syscall_wait_desc *w)
{
	struct sigaction act;
	int sig;

	sig = w->sr.args[0];
	if (sig == SIGCHLD || sig == LOCALSIG)
		return;
	memset(&act, '\0', sizeof act);
	if (w->sr.args[1] == (unsigned long)SIG_IGN)
		act.sa_handler = SIG_IGN;
	else{
		act.sa_sigaction = sendsig;
		act.sa_flags = SA_SIGINFO;
	}
	sigaction(sig, &act, NULL);
}

void
act_sigprocmask(struct syscall_wait_desc *w)
{
	sigset_t set;

	sigemptyset(&set);
	memcpy(&set, &w->sr.args[0], sizeof(unsigned long));
	sigdelset(&set, LOCALSIG);
	sigprocmask(SIG_SETMASK, &set, NULL);
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
	fprintf(stderr, "usage: %s [-c target_core] [-n nr_partitions] [--mpol-threshold=N] [--enable-straight-map] [--extend-heap-by=N] [--mpol-no-heap] [--mpol-no-bss] [--mpol-no-stack] [<mcos-id>] (program) [args...]\n", argv[0]);
}

void init_sigaction(void)
{
	int i;

	master_tid = gettid();
	for (i = 1; i <= 64; i++) {
		if (i != SIGKILL && i != SIGSTOP && i != SIGCHLD) {
			struct sigaction act;

			sigaction(i, NULL, &act);
			act.sa_sigaction = sendsig;
			act.sa_flags &= ~(SA_RESTART);
			act.sa_flags |= SA_SIGINFO;
			sigaction(i, &act, NULL);
		}
	}
}

static int max_cpuid;

static int
create_worker_thread(pthread_barrier_t *init_ready)
{
	struct thread_data_s *tp;

	tp = malloc(sizeof(struct thread_data_s));
	if (!tp) {
		fprintf(stderr, "%s: error: allocating thread structure\n",
			__FUNCTION__);
		return ENOMEM;
	}
	memset(tp, '\0', sizeof(struct thread_data_s));
	tp->cpu = max_cpuid++;
	tp->lock = &lock;
	tp->init_ready = init_ready;
	tp->terminate = 0;
	tp->next = thread_data;
	thread_data = tp;

	return pthread_create(&tp->thread_id, NULL, 
	                      &main_loop_thread_func, tp);
}

int init_worker_threads(int fd)
{
	int i;

	pthread_mutex_init(&lock, NULL);
	pthread_barrier_init(&init_ready, NULL, n_threads + 2);

	max_cpuid = 0;
	for (i = 0; i <= n_threads; ++i) {
		int ret = create_worker_thread(&init_ready);

		if (ret) {
			printf("ERROR: creating syscall threads (%d), check ulimit?\n", ret);
			return ret;
		}
	}

	pthread_barrier_wait(&init_ready);
	return 0;
}

#ifdef ENABLE_MCOVERLAYFS
#define READ_BUFSIZE 1024
static int find_mount_prefix(char *prefix)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char proc_path[PATH_MAX];
	int ret = 0;

	snprintf(proc_path, sizeof(proc_path), "/proc/%d/mounts", getpid());

	fp = fopen(proc_path, "r");
	if (fp == NULL) {
		return -1;
	}

	while ((read = getline(&line, &len, fp)) != -1) {
		if (strlen(line) < strlen(prefix))
			continue;

		if (!strncmp(line, prefix, strlen(prefix))) {
			ret = 1;
			break;
		}
	}

	if (line)
		free(line);

	return ret;
}

static int isunshare(void)
{
	return find_mount_prefix("mcoverlay /proc ");
}
#endif // ENABLE_MCOVERLAYFS

#define MCK_RLIMIT_AS	0
#define MCK_RLIMIT_CORE	1
#define MCK_RLIMIT_CPU	2
#define MCK_RLIMIT_DATA	3
#define MCK_RLIMIT_FSIZE	4
#define MCK_RLIMIT_LOCKS	5
#define MCK_RLIMIT_MEMLOCK	6
#define MCK_RLIMIT_MSGQUEUE	7
#define MCK_RLIMIT_NICE	8
#define MCK_RLIMIT_NOFILE	9
#define MCK_RLIMIT_NPROC	10
#define MCK_RLIMIT_RSS	11
#define MCK_RLIMIT_RTPRIO	12
#define MCK_RLIMIT_RTTIME	13
#define MCK_RLIMIT_SIGPENDING	14
#define MCK_RLIMIT_STACK	15

static int rlimits[] = {
#ifdef RLIMIT_AS
	RLIMIT_AS,	MCK_RLIMIT_AS,
#endif
#ifdef RLIMIT_CORE
	RLIMIT_CORE,	MCK_RLIMIT_CORE,
#endif
#ifdef RLIMIT_CPU
	RLIMIT_CPU,	MCK_RLIMIT_CPU,
#endif
#ifdef RLIMIT_DATA
	RLIMIT_DATA,	MCK_RLIMIT_DATA,
#endif
#ifdef RLIMIT_FSIZE
	RLIMIT_FSIZE,	MCK_RLIMIT_FSIZE,
#endif
#ifdef RLIMIT_LOCKS
	RLIMIT_LOCKS,	MCK_RLIMIT_LOCKS,
#endif
#ifdef RLIMIT_MEMLOCK
	RLIMIT_MEMLOCK,	MCK_RLIMIT_MEMLOCK,
#endif
#ifdef RLIMIT_MSGQUEUE
	RLIMIT_MSGQUEUE,MCK_RLIMIT_MSGQUEUE,
#endif
#ifdef RLIMIT_NICE
	RLIMIT_NICE,	MCK_RLIMIT_NICE,
#endif
#ifdef RLIMIT_NOFILE
	RLIMIT_NOFILE,	MCK_RLIMIT_NOFILE,
#endif
#ifdef RLIMIT_NPROC
	RLIMIT_NPROC,	MCK_RLIMIT_NPROC,
#endif
#ifdef RLIMIT_RSS
	RLIMIT_RSS,	MCK_RLIMIT_RSS,
#endif
#ifdef RLIMIT_RTPRIO
	RLIMIT_RTPRIO,	MCK_RLIMIT_RTPRIO,
#endif
#ifdef RLIMIT_RTTIME
	RLIMIT_RTTIME,	MCK_RLIMIT_RTTIME,
#endif
#ifdef RLIMIT_SIGPENDING
	RLIMIT_SIGPENDING,MCK_RLIMIT_SIGPENDING,
#endif
#ifdef RLIMIT_STACK
	RLIMIT_STACK,	MCK_RLIMIT_STACK,
#endif
};

char dev[64];

unsigned long atobytes(char *string)
{
	unsigned long mult = 1;
	char *postfix;
	errno = ERANGE;

	if (!strlen(string)) {
		return 0;
	}

	postfix = &string[strlen(string) - 1];

	if (*postfix == 'k' || *postfix == 'K') {
		mult = 1024;
		*postfix = 0;
	}
	else if (*postfix == 'm' || *postfix == 'M') {
		mult = 1024 * 1024;
		*postfix = 0;
	}
	else if (*postfix == 'g' || *postfix == 'G') {
		mult = 1024 * 1024 * 1024;
		*postfix = 0;
	}

	errno = 0;
	return atol(string) * mult;
}

static struct option mcexec_options[] = {
	{
		.name =		"disable-vdso",
		.has_arg =	no_argument,
		.flag =		&enable_vdso,
		.val =		0,
	},
	{
		.name =		"enable-vdso",
		.has_arg =	no_argument,
		.flag =		&enable_vdso,
		.val =		1,
	},
	{
		.name =		"profile",
		.has_arg =	no_argument,
		.flag =		&profile,
		.val =		1,
	},
	{
		.name =		"mpol-no-heap",
		.has_arg =	no_argument,
		.flag =		&mpol_no_heap,
		.val =		1,
	},
	{
		.name =		"mpol-no-stack",
		.has_arg =	no_argument,
		.flag =		&mpol_no_stack,
		.val =		1,
	},
	{
		.name =		"mpol-no-bss",
		.has_arg =	no_argument,
		.flag =		&mpol_no_bss,
		.val =		1,
	},
	{
		.name =		"mpol-shm-premap",
		.has_arg =	no_argument,
		.flag =		&mpol_shm_premap,
		.val =		1,
	},
	{
		.name =		"no-bind-ikc-map",
		.has_arg =	no_argument,
		.flag =		&no_bind_ikc_map,
		.val =		1,
	},
	{
		.name =		"mpol-threshold",
		.has_arg =	required_argument,
		.flag =		NULL,
		.val =		'm',
	},
	{
		.name =		"disable-sched-yield",
		.has_arg =	no_argument,
		.flag =		&disable_sched_yield,
		.val =		1,
	},
	{
		.name =		"extend-heap-by",
		.has_arg =	required_argument,
		.flag =		NULL,
		.val =		'h',
	},
	/* end */
	{ NULL, 0, NULL, 0, },
};

#define	MCEXEC_DEF_CUR_STACK_SIZE	(2 * 1024 * 1024)	/* 2 MiB */
#define	MCEXEC_DEF_MAX_STACK_SIZE	(64 * 1024 * 1024)	/* 64 MiB */

#ifdef ENABLE_MCOVERLAYFS
void bind_mount_recursive(const char *root, char *prefix)
{
	DIR *dir;
	struct dirent *entry;
	char path[PATH_MAX];
	int len;

	len = snprintf(path, sizeof(path) - 1, "%s/%s", root, prefix);
	path[len] = 0;

	if (!(dir = opendir(path))) {
		return;
	}

	if (!(entry = readdir(dir))) {
		return;
	}

	do {
		len = snprintf(path, sizeof(path) - 1,
				"%s/%s", prefix, entry->d_name);
		path[len] = 0;

		if (entry->d_type == DT_DIR) {
			if (strcmp(entry->d_name, ".") == 0 ||
					strcmp(entry->d_name, "..") == 0)
				continue;

			bind_mount_recursive(root, path);
		}
		else if (entry->d_type == DT_REG) {
			int ret;
			struct sys_mount_desc mount_desc;
			memset(&mount_desc, '\0', sizeof mount_desc);
			char bind_path[PATH_MAX];

			len = snprintf(bind_path, sizeof(bind_path) - 1,
					"%s/%s/%s", root, prefix, entry->d_name);
			bind_path[len] = 0;

			mount_desc.dev_name = bind_path;
			mount_desc.dir_name = path;
			mount_desc.type = NULL;
			mount_desc.flags = MS_BIND | MS_PRIVATE;
			mount_desc.data = NULL;
			if ((ret = ioctl(fd, MCEXEC_UP_SYS_MOUNT,
						(unsigned long)&mount_desc)) != 0) {
				fprintf(stderr, "WARNING: failed to bind mount %s over %s: %d\n",
						bind_path, path, ret);
			}
		}
	}
	while ((entry = readdir(dir)) != NULL);

	closedir(dir);
}
#endif

static void
join_all_threads()
{
	struct thread_data_s *tp;
	int live_thread;

	do {
		live_thread = 0;
		for (tp = thread_data; tp; tp = tp->next) {
			if (tp->joined)
				continue;
			live_thread = 1;
			pthread_join(tp->thread_id, NULL);
			tp->joined = 1;
		}
	} while (live_thread);
}

static int
opendev()
{
	int f;

	sprintf(dev, "/dev/mcos%d", mcosid);

	/* Open OS chardev for ioctl() */
	f = open(dev, O_RDWR);
	if (f < 0) {
		fprintf(stderr, "Error: Failed to open %s.\n", dev);
		return -1;
	}
	fd = f;

	return fd;
}

int main(int argc, char **argv)
{
	int ret = 0;
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
	int opt;
	char path[1024];
	char *shell = NULL;
	char shell_path[1024];
	int num = 0;
	int persona;

#ifdef USE_SYSCALL_MOD_CALL
	__glob_argc = argc;
	__glob_argv = argv;
#endif

	altroot = getenv("MCEXEC_ALT_ROOT");
	if (!altroot) {
		altroot = "/usr/linux-k1om-4.7/linux-k1om";
	}

	/* Disable address space layout randomization */
	persona = personality(0xffffffff);
	__dprintf("persona=%08x\n", persona);
	if ((persona & (PER_LINUX | ADDR_NO_RANDOMIZE)) == 0) {
		CHKANDJUMP(getenv("MCEXEC_ADDR_NO_RANDOMIZE"), 1, "personality() and then execv() failed\n");

		persona = personality(persona | PER_LINUX | ADDR_NO_RANDOMIZE);
		CHKANDJUMPF(persona == -1, 1, "personality failed, persona=%08x, strerror=%s\n", persona, strerror(errno));

		error = setenv("MCEXEC_ADDR_NO_RANDOMIZE", "1", 1);
		CHKANDJUMP(error == -1, 1, "setenv failed\n");

		error = execv("/proc/self/exe", argv);
		CHKANDJUMPF(error == -1, 1, "execv failed, error=%d,strerror=%s\n", error, strerror(errno));
	}
	if (getenv("MCEXEC_ADDR_NO_RANDOMIZE")) {
		error = unsetenv("MCEXEC_ADDR_NO_RANDOMIZE");
		CHKANDJUMP(error == -1, 1, "unsetenv failed");
	}

	rlim_stack.rlim_cur = MCEXEC_DEF_CUR_STACK_SIZE;
	rlim_stack.rlim_max = MCEXEC_DEF_MAX_STACK_SIZE;

#define	MCEXEC_MAX_STACK_SIZE	(1024 * 1024 * 1024)	/* 1 GiB */
	if (rlim_stack.rlim_cur > MCEXEC_MAX_STACK_SIZE) {
		/* need to call reduce_stack() before modifying the argv[] */
		(void)reduce_stack(&rlim_stack, argv);	/* no return, unless failure */
		fprintf(stderr, "Error: Failed to reduce stack.\n");
		return 1;
	}

	/* Parse options ("+" denotes stop at the first non-option) */
	while ((opt = getopt_long(argc, argv, "+c:n:t:m:h:", mcexec_options, NULL)) != -1) {
		switch (opt) {
			case 'c':
				target_core = atoi(optarg);
				break;

			case 'n':
				nr_processes = atoi(optarg);
				break;

			case 't':
				nr_threads = atoi(optarg);
				break;

			case 'm':
				mpol_threshold = atobytes(optarg);
				break;

			case 'h':
				heap_extension = atobytes(optarg);
				break;

			case 0:	/* long opt */
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
		num = atoi(argv[optind]);
		++optind;
	}

	/* No more arguments? */
	if (optind >= argc) {
		print_usage(argv);
		exit(EXIT_FAILURE);
	}

	mcosid = num;
	if (opendev() == -1)
		exit(EXIT_FAILURE);

	if (disable_sched_yield) {
		char sched_yield_lib_path[PATH_MAX];
		sprintf(sched_yield_lib_path, "%s/libsched_yield.so.1.0.0",
			MCKERNEL_LIBDIR);
		__dprintf("%s: %s\n", __FUNCTION__, sched_yield_lib_path);
		if (setenv("LD_PRELOAD", sched_yield_lib_path, 1) < 0) {
			printf("%s: warning: failed to set LD_PRELOAD for sched_yield\n",
					__FUNCTION__);
		}
	}
	/* Set LD_PRELOAD to McKernel specific value */
	else if (getenv(ld_preload_envname)) {
		if (setenv("LD_PRELOAD", getenv(ld_preload_envname), 1) < 0) {
			printf("%s: warning: failed to set LD_PRELOAD environment variable\n",
					__FUNCTION__);
		}
		unsetenv(ld_preload_envname);
	}

	/* Collect environment variables */
	envs_len = flatten_strings(-1, NULL, environ, &envs);

#ifdef ENABLE_MCOVERLAYFS
	__dprint("mcoverlay enable\n");
	char mcos_procdir[PATH_MAX];
	char mcos_sysdir[PATH_MAX];

	error = isunshare();
	if (error == 0) {
		struct sys_unshare_desc unshare_desc;
		struct sys_mount_desc mount_desc;
		struct sys_umount_desc umount_desc;

		/* Unshare mount namespace */
		memset(&unshare_desc, '\0', sizeof unshare_desc);
		memset(&mount_desc, '\0', sizeof mount_desc);
		unshare_desc.unshare_flags = CLONE_NEWNS;
		if (ioctl(fd, MCEXEC_UP_SYS_UNSHARE,
			(unsigned long)&unshare_desc) != 0) {
			fprintf(stderr, "Error: Failed to unshare. (%s)\n",
				strerror(errno));
			return 1;
		}

		/* Privatize mount namespace */
		mount_desc.dev_name = NULL;
		mount_desc.dir_name = "/";
		mount_desc.type = NULL;
		mount_desc.flags = MS_PRIVATE | MS_REC;
		mount_desc.data = NULL;
		if (ioctl(fd, MCEXEC_UP_SYS_MOUNT,
			(unsigned long)&mount_desc) != 0) {
			fprintf(stderr, "Error: Failed to privatize mounts. (%s)\n",
				strerror(errno));
			return 1;
		}

		/*
		 * Umount cgroup filesystems that may expose invalid NUMA
		 * information
		 */
		if (find_mount_prefix("cgroup /sys/fs/cgroup/cpu,cpuacct")) {
			umount_desc.dir_name = "/sys/fs/cgroup/cpu,cpuacct";

			if (ioctl(fd, MCEXEC_UP_SYS_UMOUNT,
						(unsigned long)&umount_desc) != 0) {
				fprintf(stderr,
						"WARNING: Failed to umount cgroup/cpu,cpuacct. (%s)\n",
						strerror(errno));
			}
		}
		else if (find_mount_prefix("cgroup /sys/fs/cgroup/cpu")) {
			umount_desc.dir_name = "/sys/fs/cgroup/cpu";

			if (ioctl(fd, MCEXEC_UP_SYS_UMOUNT,
						(unsigned long)&umount_desc) != 0) {
				fprintf(stderr,
						"WARNING: Failed to umount cgroup/cpu. (%s)\n",
						strerror(errno));
			}
		}

		if (find_mount_prefix("cgroup /sys/fs/cgroup/cpuset")) {
			umount_desc.dir_name = "/sys/fs/cgroup/cpuset";

			if (ioctl(fd, MCEXEC_UP_SYS_UMOUNT,
						(unsigned long)&umount_desc) != 0) {
				fprintf(stderr,
						"WARNING: Failed to umount cgroup/cpuset. (%s)\n",
						strerror(errno));
			}
		}

		if (find_mount_prefix("cgroup /sys/fs/cgroup/memory")) {
			umount_desc.dir_name = "/sys/fs/cgroup/memory/";

			if (ioctl(fd, MCEXEC_UP_SYS_UMOUNT,
						(unsigned long)&umount_desc) != 0) {
				fprintf(stderr,
						"WARNING: Failed to umount cgroup/memory. (%s)\n",
						strerror(errno));
			}
		}

		sprintf(mcos_procdir, "/tmp/mcos/mcos%d_proc", mcosid);
		mount_desc.dev_name = mcos_procdir;
		mount_desc.dir_name = "/proc";
		mount_desc.type = NULL;
		mount_desc.flags = MS_BIND;
		mount_desc.data = NULL;
		if (ioctl(fd, MCEXEC_UP_SYS_MOUNT, 
			(unsigned long)&mount_desc) != 0) {
			fprintf(stderr, "Error: Failed to mount /proc. (%s)\n", 
				strerror(errno));
			return 1;
		}

		sprintf(mcos_sysdir, "/tmp/mcos/mcos%d_sys", mcosid);
		mount_desc.dev_name = mcos_sysdir;
		mount_desc.dir_name = "/sys";
		mount_desc.type = NULL;
		mount_desc.flags = MS_BIND;
		mount_desc.data = NULL;
		if (ioctl(fd, MCEXEC_UP_SYS_MOUNT, 
			(unsigned long)&mount_desc) != 0) {
			fprintf(stderr, "Error: Failed to mount /sys. (%s)\n", 
				strerror(errno));
			return 1;
		}

		bind_mount_recursive(ROOTFSDIR, "");

	} else if (error == -1) {
		return 1;
	}
#else
	__dprintf("mcoverlay disable\n");
#endif // ENABLE_MCOVERLAYFS

	if (lookup_exec_path(argv[optind], path, sizeof(path), 1) != 0) {
		fprintf(stderr, "error: finding file: %s\n", argv[optind]);
		return 1;
	}

	if (load_elf_desc(path, &desc, &shell) != 0) {
		fprintf(stderr, "error: loading file: %s\n", argv[optind]);
		return 1;
	}

	/* Check whether shell script */
	if (shell) {
		if (lookup_exec_path(shell, shell_path, sizeof(shell_path), 0) != 0) {
			fprintf(stderr, "error: finding file: %s\n", shell);
			return 1;
		}

		if (load_elf_desc(shell_path, &desc, &shell) != 0) {
			fprintf(stderr, "error: loading file: %s\n", shell);
			return 1;
		}
	}

	if (shell) {
		argv[optind] = path;
	}

	for(i = 0; i < sizeof(rlimits) / sizeof(int); i += 2)
		getrlimit(rlimits[i], &desc->rlimit[rlimits[i + 1]]);
	desc->envs_len = envs_len;
	desc->envs = envs;
	//print_flat(envs);

	desc->args_len = flatten_strings(-1, shell, argv + optind, &args);
	desc->args = args;
	//print_flat(args);

	desc->cpu = target_core;
	desc->enable_vdso = enable_vdso;

	p = getenv(rlimit_stack_envname);
	if (p) {
		char *saveptr;
		char *token;
		errno = 0;

		token = strtok_r(p, ",", &saveptr);
		if (!token) {
			fprintf(stderr, "Error: Failed to parse %s 1\n",
					rlimit_stack_envname);
			return 1;
		}

		lcur = atobytes(token);
		if (lcur == 0 || errno) {
			fprintf(stderr, "Error: Failed to parse %s 2\n",
					rlimit_stack_envname);
			return 1;
		}

		token = strtok_r(NULL, ",", &saveptr);
		if (!token) {
			fprintf(stderr, "Error: Failed to parse %s 4\n",
					rlimit_stack_envname);
			return 1;
		}

		lmax = atobytes(token);
		if (lmax == 0 || errno) {
			fprintf(stderr, "Error: Failed to parse %s 5\n",
					rlimit_stack_envname);
			return 1;
		}

		if (lcur > lmax) {
			lcur = lmax;
		}
		if (lmax > rlim_stack.rlim_max) {
			rlim_stack.rlim_max = lmax;
		}
		if (lcur > rlim_stack.rlim_cur) {
			rlim_stack.rlim_cur = lcur;
		}
	}
	desc->rlimit[MCK_RLIMIT_STACK].rlim_cur = rlim_stack.rlim_cur;
	desc->rlimit[MCK_RLIMIT_STACK].rlim_max = rlim_stack.rlim_max;

	ncpu = ioctl(fd, MCEXEC_UP_GET_CPU, 0);
	if(ncpu == -1){
		fprintf(stderr, "No CPU found.\n");
		return 1;
	}

	if (nr_threads > 0) {
		n_threads = nr_threads;
	}
	else if (getenv("OMP_NUM_THREADS")) {
		/* Leave some headroom for helper threads.. */
		n_threads = atoi(getenv("OMP_NUM_THREADS")) + 4;
	}
	else {
		n_threads = ncpu;
	}

	/* 
	 * XXX: keep thread_data ncpu sized despite that there are only
	 * n_threads worker threads in the pool so that signaling code
	 * keeps working.
	 *
	 * TODO: fix signaling code to be independent of TIDs.
	 * TODO: implement dynaic thread pool resizing.
	 */
#if 0
	thread_data = (struct thread_data_s *)malloc(sizeof(struct thread_data_s) * (ncpu + 1));
	if (!thread_data) {
		fprintf(stderr, "error: allocating thread pool data\n");
		return 1;
	}
	memset(thread_data, '\0', sizeof(struct thread_data_s) * (ncpu + 1));
#endif

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

	/* Register per-process structure in mcctrl */
	if (ioctl(fd, MCEXEC_UP_CREATE_PPD) != 0) {
		perror("creating mcctrl per-process structure");
		close(fd);
		exit(1);
	}

	/* Partitioned execution, obtain CPU set */
	if (nr_processes > 0) {
		struct get_cpu_set_arg cpu_set_arg;
		int mcexec_linux_numa = 0;
		int ikc_mapped = 0;
		cpu_set_t mcexec_cpu_set;

		CPU_ZERO(&mcexec_cpu_set);

		cpu_set_arg.cpu_set = (void *)&desc->cpu_set;
		cpu_set_arg.cpu_set_size = sizeof(desc->cpu_set);
		cpu_set_arg.nr_processes = nr_processes;
		cpu_set_arg.target_core = &target_core;
		cpu_set_arg.mcexec_linux_numa = &mcexec_linux_numa;
		cpu_set_arg.mcexec_cpu_set = &mcexec_cpu_set;
		cpu_set_arg.mcexec_cpu_set_size = sizeof(mcexec_cpu_set);
		cpu_set_arg.ikc_mapped = &ikc_mapped;

		if (ioctl(fd, MCEXEC_UP_GET_CPUSET, (void *)&cpu_set_arg) != 0) {
			perror("getting CPU set for partitioned execution");
			close(fd);
			return 1;
		}

		desc->cpu = target_core;

		/* Bind to CPU cores where the LWK process' IKC target maps to */
		if (ikc_mapped && !no_bind_ikc_map) {
			/* This call may not succeed, but that is fine */
			if (sched_setaffinity(0, sizeof(mcexec_cpu_set),
						&mcexec_cpu_set) < 0) {
				__dprint("WARNING: couldn't bind to mcexec_cpu_set\n");
			}
#ifdef DEBUG
			else {
				int i;
				for (i = 0; i < numa_num_possible_cpus(); ++i) {
					if (CPU_ISSET(i, &mcexec_cpu_set)) {
						__dprintf("PID %d bound to CPU %d\n",
							getpid(), i);
					}
				}
			}
#endif // DEBUG
		}
		else {
			/* This call may not succeed, but that is fine */
			if (numa_run_on_node(mcexec_linux_numa) < 0) {
				__dprintf("WARNING: couldn't bind to NUMA %d\n",
						mcexec_linux_numa);
			}
#ifdef DEBUG
			else {
				cpu_set_t cpuset;
				char affinity[BUFSIZ];

				CPU_ZERO(&cpuset);
				if ((sched_getaffinity(0, sizeof(cpu_set_t), &cpuset)) != 0) {
					perror("Error sched_getaffinity");
					exit(1);
				}

				affinity[0] = '\0';
				for (i = 0; i < 512; i++) {
					if (CPU_ISSET(i, &cpuset) == 1) {
						sprintf(affinity, "%s %d", affinity, i);
					}
				}
				__dprintf("PID: %d affinity: %s\n",
						getpid(), affinity);
			}
#endif // DEBUG			
		}
	}

	desc->profile = profile;
	desc->nr_processes = nr_processes;
	desc->mpol_flags = 0;
	if (mpol_no_heap) {
		desc->mpol_flags |= MPOL_NO_HEAP;
	}

	if (mpol_no_stack) {
		desc->mpol_flags |= MPOL_NO_STACK;
	}

	if (mpol_no_bss) {
		desc->mpol_flags |= MPOL_NO_BSS;
	}

	if (mpol_shm_premap) {
		desc->mpol_flags |= MPOL_SHM_PREMAP;
	}

	desc->mpol_threshold = mpol_threshold;
	desc->heap_extension = heap_extension;

	if (ioctl(fd, MCEXEC_UP_PREPARE_IMAGE, (unsigned long)desc) != 0) {
		perror("prepare");
		close(fd);
		return 1;
	}

	print_desc(desc);
	if (transfer_image(fd, desc) < 0) {
		fprintf(stderr, "error: transferring image\n");
		return -1;
	}
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

	if (init_worker_threads(fd) < 0) {
		perror("worker threads: ");
		close(fd);
		return 1;
	}

	if (ioctl(fd, MCEXEC_UP_START_IMAGE, (unsigned long)desc) != 0) {
		perror("exec");
		close(fd);
		return 1;
	}

	join_all_threads();

 fn_fail:
	return ret;
}


void do_syscall_return(int fd, int cpu,
                       long ret, int n, unsigned long src, unsigned long dest,
                       unsigned long sz)
{
	struct syscall_ret_desc desc;

	memset(&desc, '\0', sizeof desc);
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

	memset(&desc, '\0', sizeof desc);
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

	/* Overlayfs /sys/X directory lseek() problem work around */
	if (w->sr.number == __NR_lseek && ret == -EINVAL) {
		char proc_path[PATH_MAX];
		char path[PATH_MAX];
		struct stat sb;

		sprintf(proc_path, "/proc/self/fd/%d", (int)w->sr.args[0]);

		/* Get filename */
		if (readlink(proc_path, path, sizeof(path)) < 0) {
			fprintf(stderr, "%s: error: readlink() failed for %s\n",
				__FUNCTION__, proc_path);
			perror(": ");
			goto out;
		}

		/* Not in /sys? */
		if (strncmp(path, "/sys/", 5))
			goto out;

		/* Stat */
		if (stat(path, &sb) < 0) {
			fprintf(stderr, "%s: error stat() failed for %s\n",
				__FUNCTION__, path);
			goto out;
		}

		/* Not dir? */
		if ((sb.st_mode & S_IFMT) != S_IFDIR)
			goto out;

		ret = 0;
	}
	/* Fake that nodeX in /sys/devices/system/node do not exist,
	 * where X >= number of LWK NUMA nodes */
	else if (w->sr.number == __NR_getdents && ret > 0) {
		struct linux_dirent {
			long           d_ino;
			off_t          d_off;
			unsigned short d_reclen;
			char           d_name[];
		};
		struct linux_dirent *d;
		char *buf = (char *)w->sr.args[1];
		int bpos = 0;
		int nodes,len;
		char proc_path[PATH_MAX];
		char path[PATH_MAX];

		sprintf(proc_path, "/proc/self/fd/%d", (int)w->sr.args[0]);

		/* Get filename */
		if ((len = readlink(proc_path, path, sizeof(path))) < 0) {
			fprintf(stderr, "%s: error: readlink() failed for %s\n",
				__FUNCTION__, proc_path);
			goto out;
		}
		path[len] = 0;

		/* Not /sys/devices/system/node ? */
		if (strcmp(path, "/sys/devices/system/node"))
			goto out;

		nodes = ioctl(fd, MCEXEC_UP_GET_NODES, 0);
		if (nodes == -1) {
			goto out;
		}

		d = (struct linux_dirent *) (buf + bpos);
		for (bpos = 0; bpos < ret; ) {
			int nodeid, tmp_reclen;
			d = (struct linux_dirent *) (buf + bpos);

			if (sscanf(d->d_name, "node%d", &nodeid) != 1) {
				bpos += d->d_reclen;
				continue;
			}

			if (nodeid >= nodes) {
				tmp_reclen = d->d_reclen;
				memmove(buf + bpos,
						buf + bpos + tmp_reclen,
						ret - bpos - tmp_reclen);
				ret -= tmp_reclen;
				continue;
			}

			bpos += d->d_reclen;
		}
	}

out:
	__dprintf("do_generic_syscall(%ld):%ld (%#lx)\n", w->sr.number, ret, ret);
	return ret;
}

static void
kill_thread(unsigned long tid, int sig)
{
	struct thread_data_s *tp;

	if (sig == 0)
		sig = LOCALSIG;

	for (tp = thread_data; tp; tp = tp->next) {
		if (tp->remote_tid == tid) {
			pthread_kill(tp->thread_id, sig);
			break;
		}
	}
}

static int
samepage(void *a, void *b)
{
	unsigned long aa = (unsigned long)a;
	unsigned long bb = (unsigned long)b;

	return (aa & PAGE_MASK) == (bb & PAGE_MASK);
}

#ifdef DEBUG_UTI
long syscalls[512];

static void
debug_sig(int s)
{
	int i;
	for (i = 0; i < 512; i++)
		if (syscalls[i])
			fprintf(stderr, "syscall %d called %ld\n", i,
			                                           syscalls[i]);
}
#endif

static int
create_tracer(void *wp, int mck_tid, unsigned long key)
{
	int pid = getpid();
	int tid = gettid();
	int pfd[2];
	int tpid;
	int rc;
	int st;
	int sig = 0;
	int i;
	struct syscall_struct *param_top = NULL;
	struct syscall_struct *param;
	unsigned long code = 0;
	int exited = 0;
	int mode = 0;

	if (pipe(pfd) == -1)
		return -1;
	tpid = fork();
	if (tpid) {
		struct timeval tv;
		fd_set rfd;

		if (tpid == -1)
			return -1;
		close(pfd[1]);
		while ((rc = waitpid(tpid, &st, 0)) == -1 && errno == EINTR);
		if (rc == -1 || !WIFEXITED(st) || WEXITSTATUS(st)) {
			fprintf(stderr, "waitpid rc=%d st=%08x\n", rc, st);
			return -ENOMEM;
		}
		FD_ZERO(&rfd);
		FD_SET(pfd[0], &rfd);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		while ((rc = select(pfd[0] + 1, &rfd, NULL, NULL, &tv)) == -1 &&
		       errno == EINTR);
		if (rc == 0) {
			close(pfd[0]);
			return -ETIMEDOUT;
		}
		if (rc == -1) {
			close(pfd[0]);
			return -errno;
		}
		rc = read(pfd[0], &st, 1);
		close(pfd[0]);
		if (rc != 1) {
			return -EAGAIN;
		}
		return 0;
	}
	close(pfd[0]);
	tpid = fork();
	if (tpid) {
		if (tpid == -1) {
			fprintf(stderr, "fork errno=%d\n", errno);
			exit(1);
		}
		exit(0);
	}
	if (ptrace(PTRACE_ATTACH, tid, 0, 0) == -1) {
		fprintf(stderr, "PTRACE_ATTACH errno=%d\n", errno);
		exit(1);
	}
	waitpid(-1, &st, __WALL);
	if (ptrace(PTRACE_SETOPTIONS, tid, 0, PTRACE_O_TRACESYSGOOD) == -1) {
		fprintf(stderr, "PTRACE_SETOPTIONS errno=%d\n", errno);
		exit(1);
	}
	write(pfd[1], " ", 1);
	close(pfd[1]);

	for (i = 0; i < 4096; i++)
		if (i != fd
#ifdef DEBUG_UTI
		   && i != 2
#endif
		   )
			close(i);
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);
#ifndef DEBUG_UTI
	open("/dev/null", O_WRONLY);
#endif

	for (i = 1; i <= 10; i++) {
		param = (struct syscall_struct *)wp + i;
		*(void **)param = param_top;
		param_top = param;
	}
	memset(wp, '\0', sizeof(long));

#ifdef DEBUG_UTI
	fprintf(stderr, "tracer PID=%d\n", getpid());
	signal(SIGINT, debug_sig);
#endif
	for (;;) {
		ptrace(PTRACE_SYSCALL, tid, 0, sig);
		sig = 0;
		waitpid(-1, &st, __WALL);
		if (WIFEXITED(st) || WIFSIGNALED(st)) {
			unsigned long term_param[4];

			term_param[0] = pid;
			term_param[1] = tid;
			term_param[3] = key;
			code = st;
			if (exited == 2 || // exit_group
			    WIFSIGNALED(st)) {
				code |= 0x0000000100000000;
			}
			term_param[2] = code;
			ioctl(fd, MCEXEC_UP_TERMINATE_THREAD, term_param);
			break;
		}
		if (!WIFSTOPPED(st)) {
			continue;
		}
		if (WSTOPSIG(st) & 0x80) { // syscall
			syscall_args args;

			get_syscall_args(tid, &args);

#ifdef DEBUG_UTI
			if (get_syscall_return(&args) == -ENOSYS) {
				if (get_syscall_number(&args) >= 0 &&
				    get_syscall_number(&args) < 512) {
					syscalls[get_syscall_number(&args)]++;
				}
			}
#endif

			if (get_syscall_number(&args) == __NR_ioctl &&
			    get_syscall_return(&args) == -ENOSYS &&
			    get_syscall_arg1(&args) == fd &&
			    get_syscall_arg2(&args) == MCEXEC_UP_SIG_THREAD) {
				mode = get_syscall_arg3(&args);
			}

			if (mode) {
				continue;
			}

			switch (get_syscall_number(&args)) {
			    case __NR_gettid:
				set_syscall_number(&args, -1);
				set_syscall_return(&args, mck_tid);
				set_syscall_args(tid, &args);
				continue;
			    case __NR_futex:
			    case __NR_brk:
			    case __NR_mmap:
			    case __NR_munmap:
			    case __NR_mprotect:
			    case __NR_mremap:
				break;
			    case __NR_exit_group:
				exited++;
			    case __NR_exit:
				exited++;
				continue;
			    case __NR_clone:
			    case __NR_fork:
			    case __NR_vfork:
			    case __NR_execve:
				set_syscall_number(&args, -1);
				set_syscall_args(tid, &args);
				continue;
			    case __NR_ioctl:
				param = (struct syscall_struct *)
					                get_syscall_arg3(&args);
				if (get_syscall_return(&args) != -ENOSYS &&
				    get_syscall_arg1(&args) == fd &&
				    get_syscall_arg2(&args) ==
				                     MCEXEC_UP_SYSCALL_THREAD &&
				    samepage(wp, param)) {
					set_syscall_arg1(&args, param->args[0]);
					set_syscall_arg2(&args, param->args[1]);
					set_syscall_arg3(&args, param->args[2]);
					set_syscall_arg4(&args, param->args[3]);
					set_syscall_arg5(&args, param->args[4]);
					set_syscall_arg6(&args, param->args[5]);
					set_syscall_return(&args, param->ret);
					*(void **)param = param_top;
					param_top = param;
					set_syscall_args(tid, &args);
				}
				continue;
			    default:
				continue;
			}
			param = param_top;
			if (!param) {
				set_syscall_number(&args, -1);
				set_syscall_return(&args, -ENOMEM);
			}
			else {
				param_top = *(void **)param;
				param->number = get_syscall_number(&args);
				param->args[0] = get_syscall_arg1(&args);
				param->args[1] = get_syscall_arg2(&args);
				param->args[2] = get_syscall_arg3(&args);
				param->args[3] = get_syscall_arg4(&args);
				param->args[4] = get_syscall_arg5(&args);
				param->args[5] = get_syscall_arg6(&args);
				param->ret = -EINVAL;
				set_syscall_number(&args, __NR_ioctl);
				set_syscall_arg1(&args, fd);
				set_syscall_arg2(&args,
				                      MCEXEC_UP_SYSCALL_THREAD);
				set_syscall_arg3(&args, (unsigned long)param);
			}
			set_syscall_args(tid, &args);
		}
		else { // signal
			sig = WSTOPSIG(st) & 0x7f;
		}
	}

#ifdef DEBUG_UTI
	fprintf(stderr, "offloaded thread called these syscalls\n");
	debug_sig(0);
#endif

	exit(0);
}

static void
util_thread_setaffinity(unsigned long pattr)
{
	struct kuti_attr kattr;
	unsigned long args[3];

	args[0] = (unsigned long)&kattr;
	args[1] = pattr;
	args[2] = sizeof kattr;
	if (ioctl(fd, MCEXEC_UP_COPY_FROM_MCK, args) == -1) {
		return;
	}




}

static long
util_thread(unsigned long uctx_pa, int remote_tid, unsigned long pattr)
{
	void *lctx;
	void *rctx;
	void *wp;
	void *param[6];
	int rc = 0;

	wp = mmap(NULL, PAGE_SIZE * 3, PROT_READ | PROT_WRITE,
	          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (wp == (void *)-1) {
		rc = -errno;
		goto out;
	}
	lctx = (char *)wp + PAGE_SIZE;
	rctx = (char *)lctx + PAGE_SIZE;

	param[0] = (void *)uctx_pa;
	param[1] = rctx;
	param[2] = lctx;
	param[4] = wp;
	param[5] = (void *)(PAGE_SIZE * 3);
	if ((rc = ioctl(fd, MCEXEC_UP_UTIL_THREAD1, param)) == -1) {
		fprintf(stderr, "util_thread1: %d errno=%d\n", rc, errno);
		rc = -errno;
		goto out;
	}

	create_worker_thread(NULL);
	if ((rc = create_tracer(wp, remote_tid, (unsigned long)param[3]))) {
		fprintf(stderr, "create tracer %d\n", rc);
		rc = -errno;
		goto out;
	}

	if (pattr) {
		util_thread_setaffinity(pattr);
	}

	if ((rc = switch_ctx(fd, MCEXEC_UP_UTIL_THREAD2, param, lctx, rctx))
	    < 0) {
		fprintf(stderr, "util_thread2: %d\n", rc);
	}
	fprintf(stderr, "return from util_thread2 rc=%d\n", rc);
	pthread_exit(NULL);

out:
	if (wp)
		munmap(wp, PAGE_SIZE * 3);
	return rc;
}

static long do_strncpy_from_user(int fd, void *dest, void *src, unsigned long n)
{
	struct strncpy_from_user_desc desc;
	int ret;

	memset(&desc, '\0', sizeof desc);
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

int close_cloexec_fds(int mcos_fd)
{
	int fd;
	int max_fd = sysconf(_SC_OPEN_MAX);
	
	for (fd = 0; fd < max_fd; ++fd) {
		int flags;

		if (fd == mcos_fd)
			continue;
		
		flags = fcntl(fd, F_GETFD, 0);
		if (flags & FD_CLOEXEC) {
			close(fd);
		}
	}

	/*
	 * NOTE: a much more elegant solution would be to iterate fds in proc,
	 * but opendir() seems to change some state in glibc which makes some
	 * of the execve() LTP tests fail. 
	 * TODO: investigate this later.
	 *
	DIR *d;
	struct dirent *de;
	struct dirent __de;

	if ((d = opendir("/proc/self/fd")) == NULL) {
		fprintf(stderr, "error: opening /proc/self/fd \n");
		return -1;
	}

	while (!readdir_r(d, &__de, &de) && de != NULL) {
		long l;
		char *e = NULL;
		int flags;
		
		if (de->d_name[0] == '.')
			continue;

		errno = 0;
		l = strtol(de->d_name, &e, 10);
		if (errno != 0 || !e || *e) {
			closedir(d);
			return -1;
		}

		fd = (int)l;

		if ((long)fd != l) {
			closedir(d);
			return -1;
		}

		if (fd == dirfd(d))
			continue;

		if (fd == mcos_fd)
			continue;
		
		fprintf(stderr, "checking: %d\n", fd);

		flags = fcntl(fd, F_GETFD, 0);
		if (flags & FD_CLOEXEC) {
			fprintf(stderr, "closing: %d\n", fd);
			close(fd);
		}
	}

	closedir(d);
	*/
	
	return 0;
}

void chgdevpath(char *in, char *buf)
{
	if(!strcmp(in, "/dev/xpmem")){
		sprintf(in, "/dev/null");
	}
}

char *
chgpath(char *in, char *buf)
{
	chgdevpath(in, buf);

#ifdef ENABLE_MCOVERLAYFS
	return in;
#endif // ENABLE_MCOVERLAYFS
	char	*fn = in;
	struct stat	sb;

	if (!strncmp(fn, "/proc/self/", 11)){
		sprintf(buf, "/proc/mcos%d/%d/%s", mcosid, getpid(), fn + 11);
		fn = buf;
	}
	else if(!strncmp(fn, "/proc/", 6)){
		sprintf(buf, "/proc/mcos%d/%s", mcosid, fn + 6);
		fn = buf;
	}
	else if(!strcmp(fn, "/sys/devices/system/cpu/online")){
		fn = "/admin/fs/attached/files/sys/devices/system/cpu/online";
	}
	else
		return in;

	if(stat(fn, &sb) == -1)
		return in;
	return fn;
}

int main_loop(struct thread_data_s *my_thread)
{
	struct syscall_wait_desc w;
	long ret;
	char *fn;
	int sig;
	int term;
	struct timespec tv;
	char pathbuf[PATH_MAX];
	char tmpbuf[PATH_MAX];
	int cpu = my_thread->cpu;

	memset(&w, '\0', sizeof w);
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

		my_thread->remote_tid = w.sr.rtid;
		my_thread->remote_cpu = w.cpu;

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

			fn = chgpath(pathbuf, tmpbuf);

			ret = open(fn, w.sr.args[1], w.sr.args[2]);
			SET_ERR(ret);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_futex:
			ret = clock_gettime(w.sr.args[1], &tv);
			SET_ERR(ret);
			__dprintf("clock_gettime=%016ld,%09ld\n",
					tv.tv_sec,
					tv.tv_nsec);
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)&tv,
			                  w.sr.args[0], sizeof(struct timespec));
			break;

		case __NR_kill: // interrupt syscall
			kill_thread(w.sr.args[1], w.sr.args[2]);
			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);
			break;
		case __NR_exit:
		case __NR_exit_group:
			sig = 0;
			term = 0;
			
			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);

			/* Drop executable file */
			if ((ret = ioctl(fd, MCEXEC_UP_CLOSE_EXEC)) != 0) {
				fprintf(stderr, "WARNING: close_exec() couldn't find exec file?\n");
			}

			__dprintf("__NR_exit/__NR_exit_group: %ld (cpu_id: %d)\n",
					w.sr.args[0], cpu);
			if(w.sr.number == __NR_exit_group){
				sig = w.sr.args[0] & 0x7f;
				term = (w.sr.args[0] & 0xff00) >> 8;
				if(isatty(2)){
					if(sig){
						if(!ischild)
							fprintf(stderr, "Terminate by signal %d\n", sig);
					}
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

		case __NR_gettid:{
			/*
			 * Number of TIDs and the remote physical address where TIDs are
			 * expected are passed in arg 4 and 5, respectively.
			 */
			if (w.sr.args[4] > 0) {
				struct remote_transfer trans;
				struct thread_data_s *tp;
				int i = 0;
				int *tids = malloc(sizeof(int) * w.sr.args[4]);
				if (!tids) {
					fprintf(stderr, "__NR_gettid(): error allocating TIDs\n");
					goto gettid_out;
				}

				for (tp = thread_data; tp && i < w.sr.args[4];
				     tp = tp->next) {
					if (tp->joined || tp->terminate)
						continue;
					tids[i++] = tp->tid;
				}

				for (; i < ncpu; ++i) {
					tids[i] = 0;
				}

				trans.userp = (void*)tids;
				trans.rphys = w.sr.args[5];
				trans.size = sizeof(int) * w.sr.args[4];
				trans.direction = MCEXEC_UP_TRANSFER_TO_REMOTE;

				if (ioctl(fd, MCEXEC_UP_TRANSFER, &trans) != 0) {
					fprintf(stderr, "__NR_gettid(): error transfering TIDs\n");
				}

				free(tids);
			}
gettid_out:
			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);
			break;
		}

		case __NR_fork: {
			struct fork_sync *fs;
			struct fork_sync_container *fsc;
			struct fork_sync_container *fp;
			struct fork_sync_container *fb;
			int flag = w.sr.args[0];
			int rc = -1;
			pid_t pid;

			fsc = malloc(sizeof(struct fork_sync_container));
			memset(fsc, '\0', sizeof(struct fork_sync_container));
			pthread_mutex_lock(&fork_sync_mutex);
			fsc->next = fork_sync_top;
			fork_sync_top = fsc;
			pthread_mutex_unlock(&fork_sync_mutex);
			fsc->fs = fs = mmap(NULL, sizeof(struct fork_sync),
			          PROT_READ | PROT_WRITE,
			          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
			if(fs == (void *)-1){
				goto fork_err;
			}

			memset(fs, '\0', sizeof(struct fork_sync));
			sem_init(&fs->sem, 1, 0);

			if(flag){
				int pipefds[2];

				if(pipe(pipefds) == -1){
					rc = -errno;
					sem_destroy(&fs->sem);
					goto fork_err;
				}
				pid = fork();
				if(pid == 0){
					close(pipefds[0]);
					pid = fork();
					if(pid != 0){
						if (write(pipefds[1], &pid, sizeof pid) != sizeof(pid)) {
							fprintf(stderr, "error: writing pipefds\n");
						}
						exit(0);
					}
				}
				else if(pid != -1){
					int npid;
					int st;

					close(pipefds[1]);
					if (read(pipefds[0], &npid, sizeof npid) != sizeof(npid)) {
						fprintf(stderr, "error: reading pipefds\n");
					}
					close(pipefds[0]);
					waitpid(pid, &st, 0);
					pid = npid;
				}
				else{
					rc = -errno;
					sem_destroy(&fs->sem);
					goto fork_err;
				}
			}
			else
				pid = fork();

			switch (pid) {
			    /* Error */
			    case -1:
				fprintf(stderr, "fork(): error forking child process\n");
				rc = -errno;
				break;

			    /* Child process */
			    case 0: {
				int ret = 1;
				struct newprocess_desc npdesc;

				ischild = 1;
				/* Reopen device fd */
				close(fd);
				fd = opendev();
				if (fd < 0) {
					fs->status = -errno;
					fprintf(stderr, "ERROR: opening %s\n", dev);
					
					goto fork_child_sync_pipe;
				}

				if (ioctl(fd, MCEXEC_UP_CREATE_PPD) != 0) {
					fs->status = -errno;
					fprintf(stderr, "ERROR: creating PPD %s\n", dev);

					goto fork_child_sync_pipe;
				}

				/* Reinit signals and syscall threads */
				init_sigaction();

				__dprintf("pid(%d): signals and syscall threads OK\n", 
						getpid());

				/* Hold executable also in the child process */
				if ((ret = ioctl(fd, MCEXEC_UP_OPEN_EXEC, exec_path)) 
					!= 0) {
					fprintf(stderr, "Error: open_exec() fails for %s: %d (fd: %d)\n", 
							exec_path, ret, fd);
					fs->status = -errno;
					goto fork_child_sync_pipe;
				}

				/* Check if we need to limit number of threads in the pool */
				if ((ret = ioctl(fd, MCEXEC_UP_GET_NUM_POOL_THREADS)) < 0) {
					fprintf(stderr, "Error: obtaining thread pool count\n");
				}

				/* Limit number of threads */
				if (ret == 1) {
					n_threads = 4;
				}

				ret = 0;
				if (init_worker_threads(fd) < 0) {
					perror("worker threads: ");
					close(fd);
					ret = -1;
				}

fork_child_sync_pipe:
				sem_post(&fs->sem);
				if (fs->status)
					exit(1);

				for (fp = fork_sync_top; fp;) {
					fb = fp->next;
					if (fp->fs)
						munmap(fp->fs, sizeof(struct fork_sync));
					free(fp);
					fp = fb;
				}
				fork_sync_top = NULL;
				pthread_mutex_init(&fork_sync_mutex, NULL);

				npdesc.pid = getpid();
				ioctl(fd, MCEXEC_UP_NEW_PROCESS, &npdesc);

				/* TODO: does the forked thread run in a pthread context? */
				join_all_threads();

				return ret;
			    }
				
			    /* Parent */
			    default:
				fs->pid = pid;
				while ((rc = sem_trywait(&fs->sem)) == -1 && (errno == EAGAIN || errno == EINTR)) {
					int st;
					int wrc;

					wrc = waitpid(pid, &st, WNOHANG);
					if(wrc == pid) {
						fs->status = -ENOMEM;
						break;
					}
					sched_yield();
				}

				if (fs->status != 0) {
					fprintf(stderr, "fork(): error with child process after fork\n");
					rc = fs->status;
					break;
				}

				rc = pid;
				break;
			}

			sem_destroy(&fs->sem);
			munmap(fs, sizeof(struct fork_sync));
fork_err:
			pthread_mutex_lock(&fork_sync_mutex);
			for (fp = fork_sync_top, fb = NULL; fp; fb = fp, fp = fp->next)
				if (fp == fsc)
					break;
			if (fp) {
				if (fb)
					fb->next = fsc->next;
				else
					fork_sync_top = fsc->next;
			}
			pthread_mutex_unlock(&fork_sync_mutex);
			do_syscall_return(fd, cpu, rc, 0, 0, 0, 0);
			break;
		}

		case __NR_wait4: {
			int ret;
			pid_t pid = w.sr.args[0];
			int options = w.sr.args[2];
			siginfo_t info;
			int opt;

			opt = WEXITED | (options & WNOWAIT);
			memset(&info, '\0', sizeof info);
			while ((ret = waitid(P_PID, pid, &info, opt)) == -1 &&
			       errno == EINTR);
			if (ret == 0) {
				ret = info.si_pid;
			}

			if (ret != pid) {
				fprintf(stderr, "ERROR: waiting for %lu rc=%d errno=%d\n", w.sr.args[0], ret, errno);
			}

			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;
		}

		case __NR_execve: {

			/* Execve phase */
			switch (w.sr.args[0]) {
				struct program_load_desc *desc;
				struct remote_transfer trans;
				char path[1024];
				char *filename;
				int ret;
				char *shell;
				char shell_path[1024];

				/* Load descriptor phase */
				case 1:
					
					shell = NULL;
					filename = (char *)w.sr.args[1];
					
					if ((ret = lookup_exec_path(filename, path, sizeof(path), 0)) 
						!= 0) {
						goto return_execve1;
					}

					if ((ret = load_elf_desc(path, &desc, &shell)) != 0) {
						fprintf(stderr, 
							"execve(): error loading ELF for file %s\n", path);
						goto return_execve1;
					}
					
					/* Check whether shell script */
					if (shell) {
						if ((ret = lookup_exec_path(shell, shell_path, 
									sizeof(shell_path), 0)) != 0) {
							fprintf(stderr, "execve(): error: finding file: %s\n", shell);
							goto return_execve1;
						}

						if ((ret = load_elf_desc(shell_path, &desc, &shell)) 
								!= 0) {
							fprintf(stderr, "execve(): error: loading file: %s\n", shell);
							goto return_execve1;
						}

						if (strlen(shell_path) >= SHELL_PATH_MAX_LEN) {
							fprintf(stderr, "execve(): error: shell path too long: %s\n", shell_path);
							ret = ENAMETOOLONG;
							goto return_execve1;
						}

						/* Let the LWK know the shell interpreter */
						strcpy(desc->shell_path, shell_path);
					}

					desc->enable_vdso = enable_vdso;
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
					
					ret = -1;
					/* Alloc descriptor */
					desc = malloc(w.sr.args[2]);
					if (!desc) {
						fprintf(stderr, "execve(): error allocating desc\n");
						goto return_execve2;
					}
					memset(desc, '\0', w.sr.args[2]);

					/* Copy descriptor from co-kernel side */
					trans.userp = (void*)desc;
					trans.rphys = w.sr.args[1];
					trans.size = w.sr.args[2];
					trans.direction = MCEXEC_UP_TRANSFER_FROM_REMOTE;
					
					if (ioctl(fd, MCEXEC_UP_TRANSFER, &trans) != 0) {
						fprintf(stderr, 
							"execve(): error obtaining ELF descriptor\n");
						ret = EINVAL;
						goto return_execve2;
					}
					
					__dprintf("%s", "execve(): transfer ELF desc OK\n");

					if (transfer_image(fd, desc) != 0) {
						fprintf(stderr, "error: transferring image\n");
						return -1;
					}
					__dprintf("%s", "execve(): image transferred\n");

					if (close_cloexec_fds(fd) < 0) {
						ret = EINVAL;
						goto return_execve2;
					}

					ret = 0;
return_execve2:					
#ifdef ENABLE_MCOVERLAYFS
				{
					struct sys_mount_desc mount_desc;

					mount_desc.dev_name = NULL;
					mount_desc.dir_name = "/proc";
					mount_desc.type = NULL;
					mount_desc.flags = MS_REMOUNT;
					mount_desc.data = NULL;
					if (ioctl(fd, MCEXEC_UP_SYS_MOUNT,
								(unsigned long)&mount_desc) != 0) {
						fprintf(stderr,
								"WARNING: failed to remount /proc (%s)\n",
								strerror(errno));
					}
				}
#endif
					do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
					break;

				default:
					fprintf(stderr, "execve(): ERROR: invalid execve phase\n");
					break;
			}

			break;
		}

		case __NR_signalfd4:
			ret = act_signalfd4(&w);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_perf_event_open:
			ret = open("/dev/null", O_RDONLY);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_rt_sigaction:
			act_sigaction(&w);
			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);
			break;

		case __NR_rt_sigprocmask:
			act_sigprocmask(&w);
			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);
			break;

		case __NR_setfsuid:
			if(w.sr.args[1] == 1){
				ioctl(fd, MCEXEC_UP_GET_CRED, w.sr.args[0]);
				ret = 0;
			}
			else{
				ret = setfsuid(w.sr.args[0]);
			}
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_setresuid:
			ret = setresuid(w.sr.args[0], w.sr.args[1], w.sr.args[2]);
			if(ret == -1)
				ret = -errno;
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_setreuid:
			ret = setreuid(w.sr.args[0], w.sr.args[1]);
			if(ret == -1)
				ret = -errno;
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_setuid:
			ret = setuid(w.sr.args[0]);
			if(ret == -1)
				ret = -errno;
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_setresgid:
			ret = setresgid(w.sr.args[0], w.sr.args[1], w.sr.args[2]);
			if(ret == -1)
				ret = -errno;
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_setregid:
			ret = setregid(w.sr.args[0], w.sr.args[1]);
			if(ret == -1)
				ret = -errno;
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_setgid:
			ret = setgid(w.sr.args[0]);
			if(ret == -1)
				ret = -errno;
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_setfsgid:
			ret = setfsgid(w.sr.args[0]);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_close:
			if(w.sr.args[0] == fd)
				ret = -EBADF;
			else
				ret = do_generic_syscall(&w);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_readlink:
			ret = do_strncpy_from_user(fd, pathbuf, (void *)w.sr.args[0], PATH_MAX);
			if (ret >= PATH_MAX) {
				ret = -ENAMETOOLONG;
			}
			if (ret < 0) {
				do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
				break;
			}

			fn = chgpath(pathbuf, tmpbuf);

			ret = readlink(fn, (char *)w.sr.args[1], w.sr.args[2]);
			__dprintf("readlink: path=%s, buf=%s, ret=%ld\n", 
				fn, (char *)w.sr.args[1], ret);
			SET_ERR(ret);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_stat:
			ret = do_strncpy_from_user(fd, pathbuf, (void *)w.sr.args[0], PATH_MAX);
			if (ret >= PATH_MAX) {
				ret = -ENAMETOOLONG;
			}
			if (ret < 0) {
				do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
				break;
			}

			fn = chgpath(pathbuf, tmpbuf);

			ret = stat(fn, (struct stat *)w.sr.args[1]);
			__dprintf("stat: path=%s, ret=%ld\n", fn, ret);
			SET_ERR(ret);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_sched_setaffinity:
			if (w.sr.args[0] == 0) {
				ret = util_thread(w.sr.args[1], w.sr.rtid,
				                  w.sr.args[2]);
			}
			else {
				ret = munmap((void *)w.sr.args[1],
				             w.sr.args[2]);
if(ret == -1)fprintf(stderr, "munmap rc=%ld errno=%d addr=%p size=%d\n", ret, errno, (void *)w.sr.args[1], (int)w.sr.args[2]);
				if (ret == -1)
					ret = -errno;
			}
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		default:
			ret = do_generic_syscall(&w);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		}

		my_thread->remote_tid = -1;

		//pthread_mutex_unlock(lock);
	}
	__dprint("timed out.\n");
	return 1;
}

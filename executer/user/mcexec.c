/* mcexec.c COPYRIGHT FUJITSU LIMITED 2015-2017 */
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
#ifdef POSTK_DEBUG_ARCH_DEP_35
#ifndef __aarch64__
#include <sys/user.h>
#endif /* !__aarch64__ */
#else /* POSTK_DEBUG_ARCH_DEP_35 */
#include <sys/user.h>
#endif	/* POSTK_DEBUG_ARCH_DEP_35 */
#include <sys/prctl.h>
#ifndef POSTK_DEBUG_ARCH_DEP_77 /* arch depend hide */
#include <asm/prctl.h>
#endif /* !POSTK_DEBUG_ARCH_DEP_77 */
#include "../include/uprotocol.h"
#include <ihk/ihk_host_user.h>
#include "../include/uti.h"
#include <getopt.h>
#include "archdep.h"
#include "arch_args.h"
#include "../../config.h"
#include <numa.h>
#include <numaif.h>
#include <spawn.h>
#include <sys/personality.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "../include/pmi.h"
#include "../include/qlmpi.h"
#include <ihk/ihklib.h>
#include <sys/epoll.h>

//#define DEBUG
#define ADD_ENVS_OPTION

#ifdef DEBUG
static int debug = 1;
#else
static int debug;
#endif

#define __dprintf(format, args...) do {                  \
	if (debug) {                                     \
		printf("%s: " format, __func__, ##args); \
		fflush(stdout);                          \
	}                                                \
} while (0)
#define __eprintf(format, args...) do {                   \
	fprintf(stderr, "%s: " format, __func__, ##args); \
	fflush(stderr);                                   \
} while (0)

#define CHKANDJUMPF(cond, err, format, ...)             \
	do {                                            \
		if (cond) {                             \
			__eprintf(format, __VA_ARGS__); \
			ret = err;                      \
			goto fn_fail;                   \
		}                                       \
	} while(0)

#define CHKANDJUMP(cond, err, msg)      \
	do {                            \
		if (cond) {             \
			__eprintf(msg); \
			ret = err;      \
			goto fn_fail;   \
		}                       \
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

typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;

struct sigfd {
	struct sigfd *next;
	int sigpipe[2];
};

struct sigfd *sigfdtop;

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

struct thread_data_s;
int main_loop(struct thread_data_s *);

static int mcosid;
int fd;
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
static long stack_premap = (2ULL << 20);
static long stack_max = -1;
static struct rlimit rlim_stack;
static char *mpol_bind_nodes = NULL;
static int uti_thread_rank = 0;
static int uti_use_last_cpu = 0;
static int enable_uti = 0;

/* Partitioned execution (e.g., for MPI) */
static int nr_processes = 0;
static int nr_threads = -1;

struct fork_sync {
	int status;
	volatile int success;
	sem_t sem;
};

struct fork_sync_container {
	pid_t pid;
	struct fork_sync_container *next;
	struct fork_sync *fs;
};

struct fork_sync_container *fork_sync_top;
pthread_mutex_t fork_sync_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef POSTK_DEBUG_ARCH_DEP_35
unsigned long page_size;
unsigned long page_mask;
#endif	/* POSTK_DEBUG_ARCH_DEP_35 */

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
		__eprintf("Cannot read Ehdr.\n");
		return NULL;
	}
	if (memcmp(hdr.e_ident, ELFMAG, SELFMAG)) {
		__eprintf("ELFMAG mismatched.\n");
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
				__eprintf("too large PT_INTERP segment\n");
				return NULL;
			}
			ss = pread(fileno(fp), interp_path, phdr.p_filesz,
					phdr.p_offset);
			if (ss <= 0) {
				__eprintf("cannot read PT_INTERP segment\n");
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
		__eprintf("Cannot read Ehdr.\n");
		return NULL;
	}
	if (memcmp(hdr.e_ident, ELFMAG, SELFMAG)) {
		__eprintf("ELFMAG mismatched.\n");
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
			free(desc);
			return NULL;
		}
		if (phdr.p_type == PT_INTERP) {
			__eprintf("PT_INTERP on interp\n");
			free(desc);
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

	found = 0;

	/* Is file not absolute path? */
	if (strncmp(filename, "/", 1)) {
		
		/* Is filename a single component without path? */
		while (strncmp(filename, ".", 1) && !strchr(filename, '/')) {

			char *token, *string, *tofree;
			char *PATH = getenv("COKERNEL_PATH");

			if (!execvp) {
				if (strlen(filename) + 1 > max_len) {
					free(link_path);
					return ENAMETOOLONG;
				}
				strcpy(path, filename);
				error = access(path, X_OK);
				if (error) {
					free(link_path);
					return errno;
				}
				found = 1;
				break;
			}

			if (!(PATH = getenv("COKERNEL_PATH"))) {
				PATH = getenv("PATH");
			}

			if (strlen(filename) >= 255) {
				free(link_path);
				return ENAMETOOLONG;
			}

			__dprintf("PATH: %s\n", PATH);

			/* strsep() modifies string! */
			tofree = string = strdup(PATH);
			if (string == NULL) {
				printf("lookup_exec_path(): copying PATH, not enough memory?\n");
				free(link_path);
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
			if (!found) {
				free(link_path);
				return ENOENT;
			}
			break;
		}

		/* Not in path, file to be open from the working directory */
		if (!found) {
			error = snprintf(path, max_len, "%s", filename);

			if (error < 0 || error >= max_len) {
				fprintf(stderr, "lookup_exec_path(): array too small?\n");
				free(link_path);
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
			free(link_path);
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
		error = errno;
		__dprintf("lookup_exec_path(): error stat for %s: %d\n",
			  path, error);
		return error;
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
		char **shebang_p)
{
	FILE *fp;
	FILE *interp = NULL;
	char *interp_path;
	char *shebang = NULL;
	size_t shebang_len = 0;
	struct program_load_desc *desc;
	int ret = 0;
	struct stat sb;
	char header[1024];

	if ((ret = access(filename, X_OK)) != 0) {
		__dprintf("Error: %s is not an executable?, errno: %d\n",
			filename, errno);
		return errno;
	}
	
	if ((ret = stat(filename, &sb)) == -1) {
		__dprintf("Error: failed to stat %s\n", filename);
		return errno;
	}
	
	if (sb.st_size == 0) {
		__dprintf("Error: file %s is zero length\n", filename);
		return ENOEXEC;
	}

	fp = fopen(filename, "rb");
	if (!fp) {
		__dprintf("Error: Failed to open %s\n", filename);
		return errno;
	}

	if (fread(&header, 1, 2, fp) != 2) {
		__dprintf("Error: Failed to read header from %s\n", filename);
		fclose(fp);
		return errno;
	}

	if (!strncmp(header, "#!", 2)) {
		if (getline(&shebang, &shebang_len, fp) == -1) {
			__dprintf("Error: reading shebang path %s\n",
				filename);
		}

		fclose(fp);

		/* Delete new line character and any trailing/leading spaces */
		shebang_len = strlen(shebang) - 1;
		shebang[shebang_len] = '\0';
		while (shebang_len > 0 &&
				strpbrk(shebang + shebang_len - 1, " \t")) {
			shebang_len--;
			shebang[shebang_len] = '\0';
		}
		while (shebang_len > 0 && strpbrk(shebang, " \t") == shebang) {
			shebang_len--;
			shebang++;
		}
		*shebang_p = shebang;
		return 0;
	}

	rewind(fp);
	
	if ((ret = ioctl(fd, MCEXEC_UP_OPEN_EXEC, filename)) != 0) {
		fprintf(stderr, "Error: open_exec() fails for %s: %d (fd: %d)\n", 
			filename, ret, fd);
		fclose(fp);
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
			fclose(fp);
			return ENOMEM;
		}
	}
	else {
		char *cwd = getcwd(NULL, 0);
		if (!cwd) {
			fprintf(stderr, "Error: getting current working dir pathname\n");
			fclose(fp);
			return ENOMEM;
		}

		exec_path = malloc(strlen(cwd) + strlen(filename) + 2);
		if (!exec_path) {
			fprintf(stderr, "Error: allocating exec_path\n");
			fclose(fp);
			return ENOMEM;
		}

		sprintf(exec_path, "%s/%s", cwd, filename);
		free(cwd);
	}
	
	desc = load_elf(fp, &interp_path);
	if (!desc) {
		fprintf(stderr, "Error: Failed to parse ELF!\n");
		fclose(fp);
		return 1;
	}

	if (interp_path) {
		char *path;

		path = search_file(interp_path, X_OK);
		if (!path) {
			fprintf(stderr, "Error: interp not found: %s\n", interp_path);
			fclose(fp);
			return 1;
		}

		interp = fopen(path, "rb");
		if (!interp) {
			fprintf(stderr, "Error: Failed to open %s\n", path);
			fclose(fp);
			return 1;
		}

		desc = load_interp(desc, interp);
		if (!desc) {
			fprintf(stderr, "Error: Failed to parse interp!\n");
			fclose(fp);
			fclose(interp);
			return 1;
		}
	}

	__dprintf("# of sections: %d\n", desc->num_sections);
	
	*desc_p = desc;
	return 0;
}

/* recursively resolve shebangs
 *
 * Note: shebang_argv_p must point to reallocable memory or be NULL
 */
int load_elf_desc_shebang(char *shebang_argv0,
			  struct program_load_desc **desc_p,
			  char ***shebang_argv_p,
			  int execvp)
{
	char path[PATH_MAX];
	char *shebang = NULL;
	int ret;

	if ((ret = lookup_exec_path(shebang_argv0, path, sizeof(path), execvp))
			!= 0) {
		__dprintf("error: finding file: %s\n", shebang_argv0);
		return ret;
	}

	if ((ret = load_elf_desc(path, desc_p, &shebang)) != 0) {
		__dprintf("error: loading file: %s\n", shebang_argv0);
		return ret;
	}

	if (shebang) {
		char *shebang_params;
		size_t shebang_param_count = 1;
		size_t shebang_argv_count = 0;
		char **shebang_argv;

		if (!shebang_argv_p)
			return load_elf_desc_shebang(shebang, desc_p,
						     NULL, execvp);

		shebang_argv = *shebang_argv_p;

		/* if there is a space, add whatever follows as extra arg */
		shebang_params = strchr(shebang, ' ');
		if (shebang_params) {
			shebang_params[0] = '\0';
			shebang_params++;
			shebang_param_count++;
		}

		if (shebang_argv == NULL) {
			shebang_argv_count = shebang_param_count + 1;
			shebang_argv = malloc(shebang_argv_count *
					      sizeof(void *));
			shebang_argv[shebang_param_count] = 0;
		} else {
			while (shebang_argv[shebang_argv_count++])
				;

			shebang_argv_count += shebang_param_count + 1;
			shebang_argv = realloc(shebang_argv,
					    shebang_argv_count * sizeof(void *));
			memmove(shebang_argv + shebang_param_count,
				shebang_argv,
				(shebang_argv_count - shebang_param_count)
					* sizeof(void *));
		}
		shebang_argv[0] = shebang;
		if (shebang_params)
			shebang_argv[1] = shebang_params;

		*shebang_argv_p = shebang_argv;

		return load_elf_desc_shebang(shebang, desc_p, shebang_argv_p,
					     execvp);
	}

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
#ifdef POSTK_DEBUG_ARCH_DEP_35
		s = (desc->sections[i].vaddr) & page_mask;
		e = (desc->sections[i].vaddr + desc->sections[i].len
		     + page_size - 1) & page_mask;
#else	/* POSTK_DEBUG_ARCH_DEP_35 */
		s = (desc->sections[i].vaddr) & PAGE_MASK;
		e = (desc->sections[i].vaddr + desc->sections[i].len
		     + PAGE_SIZE - 1) & PAGE_MASK;
#endif	/* POSTK_DEBUG_ARCH_DEP_35 */
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
#ifdef POSTK_DEBUG_ARCH_DEP_35
			pt.size = page_size;
#else	/* POSTK_DEBUG_ARCH_DEP_35 */
			pt.size = PAGE_SIZE;
#endif	/* POSTK_DEBUG_ARCH_DEP_35 */
			pt.direction = MCEXEC_UP_TRANSFER_TO_REMOTE;
			lr = 0;
			
#ifdef POSTK_DEBUG_ARCH_DEP_35
			memset(dma_buf, 0, page_size);
#else	/* POSTK_DEBUG_ARCH_DEP_35 */
			memset(dma_buf, 0, PAGE_SIZE);
#endif	/* POSTK_DEBUG_ARCH_DEP_35 */
			if (s < desc->sections[i].vaddr) {
#ifdef POSTK_DEBUG_ARCH_DEP_35
				l = desc->sections[i].vaddr 
					& (page_size - 1);
				lr = page_size - l;
#else	/* POSTK_DEBUG_ARCH_DEP_35 */
				l = desc->sections[i].vaddr 
					& (PAGE_SIZE - 1);
				lr = PAGE_SIZE - l;
#endif	/* POSTK_DEBUG_ARCH_DEP_35 */
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
#ifdef POSTK_DEBUG_ARCH_DEP_35
				if (flen > page_size) {
					lr = page_size;
#else	/* POSTK_DEBUG_ARCH_DEP_35 */
				if (flen > PAGE_SIZE) {
					lr = PAGE_SIZE;
#endif	/*POSTK_DEBUG_ARCH_DEP_35 */
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
#ifdef POSTK_DEBUG_ARCH_DEP_35
			s += page_size;
			rpa += page_size;
#else	/* POSTK_DEBUG_ARCH_DEP_35 */
			s += PAGE_SIZE;
			rpa += PAGE_SIZE;
#endif	/* POSTK_DEBUG_ARCH_DEP_35 */
			
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
	__dprintf("CPU = %d, pid = %d, entry = %lx, rp = %lx\n",
		  desc->cpu, desc->pid, desc->entry, desc->rprocess);
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
	long i, count;
	long *_flat = (long *)flat;

	count = _flat[0];
	__dprintf("counter: %ld\n", count);

	for (i = 0; i < count; i++) {
		__dprintf("%s\n", (flat + _flat[i + 1]));
	}
}

/* 
 * Flatten out a (char **) string array into the following format:
 * [nr_strings][char *offset of string_0]...[char *offset of string_n-1][char *offset of end of string][string0]...[stringn_1]
 * if nr_strings == -1, we assume the last item is NULL 
 *
 * sizes all are longs.
 *
 * NOTE: copy this string somewhere, add the address of the string to each offset
 * and we get back a valid argv or envp array.
 *
 * pre_strings is already flattened, so we just need to manage counts and copy
 * the string part appropriately.
 *
 * returns the total length of the flat string and updates flat to
 * point to the beginning.
 */
int flatten_strings(char *pre_strings, char **strings, char **flat)
{
	int full_len, len, i;
	int nr_strings;
	int pre_strings_count = 0;
	int pre_strings_len = 0;
	long *_flat;
	long *pre_strings_flat;
	char *p;

	for (nr_strings = 0; strings[nr_strings]; ++nr_strings)
		;

	/* Count full length */
	full_len = sizeof(long) + sizeof(char *); // Counter and terminating NULL
	if (pre_strings) {
		pre_strings_flat = (long *)pre_strings;
		pre_strings_count = pre_strings_flat[0];

		pre_strings_len = pre_strings_flat[pre_strings_count + 1];
		pre_strings_len -= sizeof(long) * (pre_strings_count + 2);

		full_len += pre_strings_count * sizeof(long) + pre_strings_len;
	}

	for (i = 0; strings[i]; ++i) {
		// Pointer + actual value
		full_len += sizeof(char *) + strlen(strings[i]) + 1;
	}

	full_len = (full_len + sizeof(long) - 1) & ~(sizeof(long) - 1);

	_flat = malloc(full_len);
	if (!_flat) {
		return 0;
	}

	memset(_flat, 0, full_len);

	/* Number of strings */
	_flat[0] = nr_strings + pre_strings_count;
	
	// Actual offset
	p = (char *)(_flat + nr_strings + pre_strings_count + 2);

	if (pre_strings) {
		for (i = 0; i < pre_strings_count; i++) {
			_flat[i + 1] = pre_strings_flat[i + 1] +
					nr_strings * sizeof(long);
		}
		memcpy(p, pre_strings + pre_strings_flat[1],
		       pre_strings_len);
		p += pre_strings_len;
	}

	for (i = 0; i < nr_strings; ++i) {
		int len = strlen(strings[i]) + 1;

		_flat[i + pre_strings_count + 1] = p - (char *)_flat;

		memcpy(p, strings[i], len);
		p += len;
	}
	_flat[nr_strings + pre_strings_count + 1] = p - (char *)_flat;

	*flat = (char *)_flat;
	len = p - (char *)_flat;
	if (len < full_len)
		memset(p, 0, full_len - len);

	return len;
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
	int joined, detached;
	pthread_mutex_t *lock;
	pthread_barrier_t *init_ready;
} *thread_data;

int ncpu;
int n_threads;

pid_t master_tid;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_barrier_t init_ready;
pthread_barrier_t uti_init_ready;

pthread_attr_t watchdog_thread_attr;
pthread_t watchdog_thread;

/* Detects hang of McKernel */
static void *watchdog_thread_func(void *arg) {
    int ret = 0;
	int evfd = -1;
    int epfd = -1;
    struct epoll_event event_in;
    struct epoll_event event_out;

	if ((evfd = ihk_os_get_eventfd(0, IHK_OS_EVENTFD_TYPE_STATUS)) < 0) {
		fprintf(stderr, "%s: Error: geteventfd failed (%d)\n", __FUNCTION__, evfd);
		goto out;
	}

    if ((epfd = epoll_create(1)) == -1) {
		fprintf(stderr, "%s: Error: epoll_create failed (%d)\n", __FUNCTION__, epfd);
		goto out;
	}

	memset(&event_in, 0, sizeof(struct epoll_event));
	event_in.events = EPOLLIN;
	event_in.data.fd = evfd;
	if ((ret = epoll_ctl(epfd, EPOLL_CTL_ADD, evfd, &event_in)) != 0) {
		fprintf(stderr, "%s: Error: epoll_ctl failed (%d)\n", __FUNCTION__, ret);
		goto out;
	}

    do {
        int nfd;
		uint64_t counter;
		ssize_t nread;

		nfd = epoll_wait(epfd, &event_out, 1, -1);
		if (nfd == -1) {
			if (errno == EINTR) {
				continue;
			}
			fprintf(stderr, "%s: Error: epoll_wait failed (%s)\n", __FUNCTION__, strerror(errno));
			goto out;
		}

		if (nfd == 0) {
			fprintf(stderr, "%s: Error: epoll_wait timed out unexpectedly\n", __FUNCTION__);
			goto out;
		}
		
		if (nfd > 1) {
			fprintf(stderr, "%s: Error: Too many (%d) events\n", __FUNCTION__, nfd);
			goto out;
		}
		
		if (event_out.data.fd != evfd) {
			fprintf(stderr, "%s: Error: Unknown event (fd:%d)\n", __FUNCTION__, event_out.data.fd);
			goto out;
		}

		nread = read(evfd, &counter, sizeof(counter));
		if (nread == 0) {
			fprintf(stderr, "%s: Error: read got EOF\n", __FUNCTION__);
			goto out;
		}
		
		if (nread == -1) {
			fprintf(stderr, "%s: Error: read failed (%s)\n", __FUNCTION__, strerror(errno));
			goto out;
		}
		
		fprintf(stderr, "mcexec detected hang of McKernel\n");
		exit(EXIT_FAILURE);
    } while (1);

 out:
	if (evfd != -1) {
		close(evfd);
	}
	if (epfd != -1) {
		close(epfd);
	}
    return NULL;
}

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
	int not_uti;

	not_uti = ioctl(fd, MCEXEC_UP_SIG_THREAD, 1);
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

	if (not_uti) { /* target isn't uti thread, ask McKernel to call the handler */
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
	else { /* target is uti thread, mcexec calls the handler */
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
	if (!not_uti)
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
	char path[PATH_MAX];
	int error;
	struct rlimit new_rlim;

	/* save original value to environment variable */
	n = snprintf(newval, sizeof(newval), "%ld,%ld",
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
		__eprintf("failed to setrlimit(RLIMIT_STACK)\n");
		return 1;
	}

	error = readlink("/proc/self/exe", path, sizeof(path));
	if (error < 0) {
		__eprintf("Could not readlink /proc/self/exe? %m\n");
		return 1;
	} else if (error >= sizeof(path)) {
		strcpy(path, "/proc/self/exe");
	} else {
		path[error] = '\0';
	}

	execv(path, argv);

	__eprintf("failed to execv(myself)\n");
	return 1;
}

void print_usage(char **argv)
{
#ifdef ADD_ENVS_OPTION
	fprintf(stderr, "usage: %s [-c target_core] [-n nr_partitions] [<-e ENV_NAME=value>...] [--mpol-threshold=N] [--enable-straight-map] [--extend-heap-by=N] [-s (--stack-premap=)[premap_size][,max]] [--mpol-no-heap] [--mpol-no-bss] [--mpol-no-stack] [--mpol-shm-premap] [--disable-sched-yield] [--enable-uti] [--uti-thread-rank=N] [--uti-use-last-cpu] [<mcos-id>] (program) [args...]\n", argv[0]);
#else /* ADD_ENVS_OPTION */
	fprintf(stderr, "usage: %s [-c target_core] [-n nr_partitions] [--mpol-threshold=N] [--enable-straight-map] [--extend-heap-by=N] [-s (--stack-premap=)[premap_size][,max]] [--mpol-no-heap] [--mpol-no-bss] [--mpol-no-stack] [--mpol-shm-premap] [--disable-sched-yield]  [--enable-uti] [--uti-thread-rank=N] [--uti-use-last-cpu] [<mcos-id>] (program) [args...]\n", argv[0]);
#endif /* ADD_ENVS_OPTION */
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

static int create_worker_thread(struct thread_data_s **tp_out, pthread_barrier_t *init_ready)
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

	if (tp_out) {
		*tp_out = tp;
	}

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
		int ret = create_worker_thread(NULL, &init_ready);

		if (ret) {
			printf("ERROR: creating worker threads (%d), check ulimit?\n",
			       ret);
			return -ret;
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

#ifdef ADD_ENVS_OPTION
struct env_list_entry {
	char* str;
	char* name;
	char* value;
	struct env_list_entry *next;
};

static int get_env_list_entry_count(struct env_list_entry *head)
{
	int list_count = 0;
	struct env_list_entry *current = head;

	while (current) {
		list_count++;
		current = current->next;
	}
	return list_count;
}

static struct env_list_entry *search_env_list(struct env_list_entry *head, char *name)
{
	struct env_list_entry *current = head;

	while (current) {
		if (!(strcmp(name, current->name))) {
			return current;
		}
		current = current->next;
	}
	return NULL;
}

static void add_env_list(struct env_list_entry **head, char *add_string)
{
	struct env_list_entry *current = NULL;
	char *value = NULL;
	char *name = NULL;
	struct env_list_entry *exist = NULL;

	name = (char *)malloc(strlen(add_string) + 1);
	strcpy(name, add_string);

	/* include '=' ? */
	if (!(value = strchr(name, '='))) {
		printf("\"%s\" is not env value.\n", add_string);
		free(name);
		return;
	}
	*value = '\0';
	value++;

	/* name overlap serch */
	if (*head) {
		exist = search_env_list(*head, name);
		if (exist) {
			free(name);
			return;
		}
	}

	/* ADD env_list */
	current = (struct env_list_entry *)malloc(sizeof(struct env_list_entry));
	current->str = add_string;
	current->name = name;
	current->value = value;
	if (*head) {
		current->next = *head;
	} else {
		current->next = NULL;
	}
	*head = current;
	return;
}

static void destroy_env_list(struct env_list_entry *head)
{
	struct env_list_entry *current = head;
	struct env_list_entry *next = NULL;

	while (current) {
		next = current->next;
		free(current->name);
		free(current);
		current = next;
	}
}

static char **create_local_environ(struct env_list_entry *inc_list)
{
	int list_count = 0;
	int i = 0;
	struct env_list_entry *current = inc_list;
	char **local_env = NULL;

	list_count = get_env_list_entry_count(inc_list);
	local_env = (char **)malloc(sizeof(char **) * (list_count + 1));
	local_env[list_count] = NULL;

	while (current) {
		local_env[i] = (char *)malloc(strlen(current->str) + 1);
		strcpy(local_env[i], current->str);
		current = current->next;
		i++;
	}
	return local_env;
}

static void destroy_local_environ(char **local_env)
{
	int i = 0;

	if (!local_env) {
		return;
	}

	for (i = 0; local_env[i]; i++) {
		free(local_env[i]);
		local_env[i] = NULL;
	}
	free(local_env);
}
#endif /* ADD_ENVS_OPTION */

unsigned long atobytes(char *string)
{
	unsigned long mult = 1;
	unsigned long ret;
	char orig_postfix = 0;
	char *postfix;
	errno = ERANGE;

	if (!strlen(string)) {
		return 0;
	}

	postfix = &string[strlen(string) - 1];

	if (*postfix == 'k' || *postfix == 'K') {
		mult = 1024;
		orig_postfix = *postfix;
		*postfix = 0;
	}
	else if (*postfix == 'm' || *postfix == 'M') {
		mult = 1024 * 1024;
		orig_postfix = *postfix;
		*postfix = 0;
	}
	else if (*postfix == 'g' || *postfix == 'G') {
		mult = 1024 * 1024 * 1024;
		orig_postfix = *postfix;
		*postfix = 0;
	}

	ret = atol(string) * mult;
	if (orig_postfix)
		*postfix = orig_postfix;

	errno = 0;
	return ret;
}

static struct option mcexec_options[] = {
#ifdef POSTK_DEBUG_ARCH_DEP_53
#ifndef __aarch64__
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
#endif /*__aarch64__*/
#endif /*POSTK_DEBUG_ARCH_DEP_53*/
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
		.val =		'M',
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
	{
		.name =		"stack-premap",
		.has_arg =	required_argument,
		.flag =		NULL,
		.val =		's',
	},
	{
		.name =		"uti-thread-rank",
		.has_arg =	required_argument,
		.flag =		NULL,
		.val =		'u',
	},
	{
		.name =		"uti-use-last-cpu",
		.has_arg =	no_argument,
		.flag =		&uti_use_last_cpu,
		.val =		1,
	},
	{
		.name =		"enable-uti",
		.has_arg =	no_argument,
		.flag =		&enable_uti,
		.val =		1,
	},
	{
		.name =		"debug-mcexec",
		.has_arg =	no_argument,
		.flag =		&debug,
		.val =		1,
	},
	/* end */
	{ NULL, 0, NULL, 0, },
};

#ifdef ENABLE_MCOVERLAYFS
/* bind-mount files under <root>/<prefix> over <prefix> recursively */
void bind_mount_recursive(const char *root, char *prefix)
{
	DIR *dir;
	struct dirent *entry;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", root, prefix);
	path[sizeof(path) - 1] = 0;

	if (!(dir = opendir(path))) {
		return;
	}

	while ((entry = readdir(dir))) {
		char fullpath[PATH_MAX];
		char shortpath[PATH_MAX];
		struct stat st;

		/* Use lstat instead of checking dt_type of readdir
		   result because the latter reports DT_UNKNOWN for
		   files on some file systems */
		snprintf(fullpath, sizeof(fullpath),
			       "%s/%s/%s", root, prefix, entry->d_name);
		fullpath[sizeof(fullpath) - 1] = 0;

		if (lstat(fullpath, &st)) {
			fprintf(stderr, "%s: error: lstat %s: %s\n",
				__func__, fullpath, strerror(errno));
			continue;
		}

		/* Traverse target or mount point */
		snprintf(shortpath, sizeof(shortpath),
			       "%s/%s", prefix, entry->d_name);
		shortpath[sizeof(shortpath) - 1] = 0;

		if (S_ISDIR(st.st_mode)) {
			__dprintf("dir found: %s\n", fullpath);

			if (strcmp(entry->d_name, ".") == 0 ||
					strcmp(entry->d_name, "..") == 0)
				continue;

			bind_mount_recursive(root, shortpath);
		}
		else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
			int ret;
			struct sys_mount_desc mount_desc;

			__dprintf("reg/symlink found: %s\n", fullpath);

			if (lstat(shortpath, &st)) {
				fprintf(stderr, "%s: warning: lstat of mount point (%s) failed: %s\n",
					__func__, shortpath, strerror(errno));
				continue;
			}

			memset(&mount_desc, '\0', sizeof(mount_desc));
			mount_desc.dev_name = fullpath;
			mount_desc.dir_name = shortpath;
			mount_desc.type = NULL;
			mount_desc.flags = MS_BIND | MS_PRIVATE;
			mount_desc.data = NULL;

			if ((ret = ioctl(fd, MCEXEC_UP_SYS_MOUNT,
						(unsigned long)&mount_desc)) != 0) {
				fprintf(stderr, "%s: warning: failed to bind mount %s over %s: %d\n",
					__func__, fullpath, shortpath, ret);
			}
		}
	}

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
			if (tp->joined || tp->detached)
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
	char buildid[] = BUILDID;
    char query_result[sizeof(BUILDID)];

	sprintf(dev, "/dev/mcos%d", mcosid);

	/* Open OS chardev for ioctl() */
	f = open(dev, O_RDWR);
	if (f < 0) {
		fprintf(stderr, "Error: Failed to open %s.\n", dev);
		return -1;
	}
	fd = f;

	if (ioctl(fd, IHK_OS_GET_BUILDID, query_result)) {
		fprintf(stderr, "Error: IHK_OS_GET_BUILDID failed");
		close(fd);
		return -1;
	}

	if (strncmp(buildid, query_result, sizeof(buildid))) {
		fprintf(stderr, "Error: build-id of mcexec (%s) didn't match that of IHK (%s)\n", buildid, query_result);
		close(fd);
		return -1;
	}

	return fd;
}

#define LD_PRELOAD_PREPARE(name) do { \
		sprintf(elembuf, "%s%s/" name, nelem > 0 ? ":" : "", MCKERNEL_LIBDIR); \
	} while (0)

#define LD_PRELOAD_APPEND do {	\
		if (strlen(elembuf) + 1 > remainder) { \
			fprintf(stderr, "%s: warning: LD_PRELOAD line is too long\n", __FUNCTION__); \
			return; \
		} \
		strncat(envbuf, elembuf, remainder); \
		remainder = PATH_MAX - (strlen(envbuf) + 1); \
		nelem++; \
	} while (0)

static void ld_preload_init()
{
	char envbuf[PATH_MAX];
	char *ld_preload_str;
	size_t remainder = PATH_MAX;
	int nelem = 0;
	char elembuf[PATH_MAX];

	memset(envbuf, 0, PATH_MAX);

	if (enable_uti) {
		LD_PRELOAD_PREPARE("syscall_intercept.so");
		LD_PRELOAD_APPEND;
	}

	if (disable_sched_yield) {
		LD_PRELOAD_PREPARE("libsched_yield.so.1.0.0");
		LD_PRELOAD_APPEND;
	}

#ifdef ENABLE_QLMPI
	LD_PRELOAD_PREPARE("libqlfort.so");
	LD_PRELOAD_APPEND;
#endif

	/* Set LD_PRELOAD to McKernel specific value */
	ld_preload_str = getenv(ld_preload_envname);
	if (ld_preload_str) {
		sprintf(elembuf, "%s%s", nelem > 0 ? ":" : "", ld_preload_str);
		LD_PRELOAD_APPEND;
	}

	if (strlen(envbuf)) {
		if (setenv("LD_PRELOAD", envbuf, 1) < 0) {
			printf("%s: warning: failed to set LD_PRELOAD environment variable\n",
					__FUNCTION__);
		}
		__dprintf("%s: preload library: %s\n", __FUNCTION__, envbuf);
	}

	if (getenv("ld_preload_envname")) {
		unsetenv(ld_preload_envname);
	}
}

int main(int argc, char **argv)
{
	int ret = 0;
	struct program_load_desc *desc;
	int envs_len;
	char *envs;
	char *p;
	int i;
	int error;
	unsigned long lcur;
	unsigned long lmax;
	int target_core = 0;
	int opt;
	char **shebang_argv = NULL;
	char *shebang_argv_flat = NULL;
	int num = 0;
	int persona;
#ifdef ADD_ENVS_OPTION
	char **local_env = NULL;
	struct env_list_entry *extra_env = NULL;
#endif /* ADD_ENVS_OPTION */

#ifdef USE_SYSCALL_MOD_CALL
	__glob_argc = argc;
	__glob_argv = argv;
#endif

#ifdef POSTK_DEBUG_ARCH_DEP_35
	page_size = sysconf(_SC_PAGESIZE);
	page_mask = ~(page_size - 1);
#endif	/* POSTK_DEBUG_ARCH_DEP_35 */

	altroot = getenv("MCEXEC_ALT_ROOT");
	if (!altroot) {
		altroot = "/usr/linux-k1om-4.7/linux-k1om";
	}

	/* Disable READ_IMPLIES_EXEC */
	persona = personality(0xffffffff);
	if (persona & READ_IMPLIES_EXEC) {
		persona &= ~READ_IMPLIES_EXEC;
		persona = personality(persona);
	}

	/* Disable address space layout randomization */
	__dprintf("persona=%08x\n", persona);
	if ((persona & (PER_LINUX | ADDR_NO_RANDOMIZE)) == 0) {
		char path[PATH_MAX];

		CHKANDJUMP(getenv("MCEXEC_ADDR_NO_RANDOMIZE"), 1, "personality() and then execv() failed\n");

		persona = personality(persona | PER_LINUX | ADDR_NO_RANDOMIZE);
		CHKANDJUMPF(persona == -1, 1, "personality failed, persona=%08x, strerror=%s\n", persona, strerror(errno));

		error = setenv("MCEXEC_ADDR_NO_RANDOMIZE", "1", 1);
		CHKANDJUMP(error == -1, 1, "setenv failed\n");

		error = readlink("/proc/self/exe", path, sizeof(path));
		CHKANDJUMP(error == -1, 1, "readlink failed: %m\n");
		if (error >= sizeof(path)) {
			strcpy(path, "/proc/self/exe");
		} else {
			path[error] = '\0';
		}

		error = execv(path, argv);
		CHKANDJUMPF(error == -1, 1, "execv failed, error=%d,strerror=%s\n", error, strerror(errno));
	}
	if (getenv("MCEXEC_ADDR_NO_RANDOMIZE")) {
		error = unsetenv("MCEXEC_ADDR_NO_RANDOMIZE");
		CHKANDJUMP(error == -1, 1, "unsetenv failed");
	}

	/* Inherit ulimit settings to McKernel process */
	if (getrlimit(RLIMIT_STACK, &rlim_stack)) {
		fprintf(stderr, "getrlimit failed\n");
		return 1;
	}
    __dprintf("rlim_stack=%ld,%ld\n", rlim_stack.rlim_cur, rlim_stack.rlim_max);

	/* Shrink mcexec stack if it leaves too small room for McKernel process */
#define	MCEXEC_MAX_STACK_SIZE	(16 * 1024 * 1024)	/* 1 GiB */
	if (rlim_stack.rlim_cur > MCEXEC_MAX_STACK_SIZE) {
		/* need to call reduce_stack() before modifying the argv[] */
		(void)reduce_stack(&rlim_stack, argv);	/* no return, unless failure */
		fprintf(stderr, "Error: Failed to reduce stack.\n");
		return 1;
	}

	/* Parse options ("+" denotes stop at the first non-option) */
#ifdef ADD_ENVS_OPTION
	while ((opt = getopt_long(argc, argv, "+c:n:t:M:h:e:s:m:u:",
				  mcexec_options, NULL)) != -1) {
#else /* ADD_ENVS_OPTION */
	while ((opt = getopt_long(argc, argv, "+c:n:t:M:h:s:m:u:",
				  mcexec_options, NULL)) != -1) {
#endif /* ADD_ENVS_OPTION */
		switch (opt) {
			char *tmp;

			case 'c':
				target_core = strtol(optarg, &tmp, 0);
				if (*tmp != '\0') {
					fprintf(stderr, "error: -c: invalid target CPU\n");
					exit(EXIT_FAILURE);
				}
				break;

			case 'n':
				nr_processes = strtol(optarg, &tmp, 0);
				if (*tmp != '\0' || nr_processes <= 0) {
					fprintf(stderr, "error: -n: invalid number of processes\n");
					exit(EXIT_FAILURE);
				}
				break;

			case 't':
				nr_threads = strtol(optarg, &tmp, 0);
				if (*tmp != '\0' || nr_threads <= 0) {
					fprintf(stderr, "error: -t: invalid number of threads\n");
					exit(EXIT_FAILURE);
				}
				break;

			case 'M':
				mpol_threshold = atobytes(optarg);
				break;

			case 'm':
				mpol_bind_nodes = optarg;
				break;

			case 'h':
				heap_extension = atobytes(optarg);
				break;

#ifdef ADD_ENVS_OPTION
			case 'e':
				add_env_list(&extra_env, optarg);
				break;
#endif /* ADD_ENVS_OPTION */
			
			case 's': {
				char *token, *dup, *line;

				dup = strdup(optarg);
				line = dup;
				token = strsep(&line, ",");
				if (token != NULL && *token != 0) {
					stack_premap = atobytes(token);
				}
				token = strsep(&line, ",");
				if (token != NULL && *token != 0) {
					stack_max = atobytes(token);
				}
				free(dup);
				__dprintf("stack_premap=%ld,stack_max=%ld\n",
					  stack_premap, stack_max);
				break;
			}

			case 'u':
				uti_thread_rank = atoi(optarg);
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

#ifndef WITH_SYSCALL_INTERCEPT
	if (enable_uti) {
		__eprintf("ERROR: uti is not available when not configured with --with-syscall_intercept=<path>\n");
		exit(EXIT_FAILURE);
	}
#endif

	ld_preload_init();

#ifdef ADD_ENVS_OPTION
#else /* ADD_ENVS_OPTION */
	/* Collect environment variables */
	envs_len = flatten_strings(NULL, environ, &envs);
#endif /* ADD_ENVS_OPTION */

#ifdef ENABLE_MCOVERLAYFS
	__dprintf("mcoverlay enable\n");
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

	if ((ret = load_elf_desc_shebang(argv[optind], &desc,
					 &shebang_argv, 1 /* execvp */))) {
		fprintf(stderr, "%s: could not load program: %s\n",
			argv[optind], strerror(ret));
		return 1;
	}

#ifdef ADD_ENVS_OPTION
	/* Collect environment variables */
	for (i = 0; environ[i]; i++) {
		add_env_list(&extra_env, environ[i]);
	}
	local_env = create_local_environ(extra_env);
	envs_len = flatten_strings(NULL, local_env, &envs);
	destroy_local_environ(local_env);
	local_env = NULL;
	destroy_env_list(extra_env);
	extra_env = NULL;
#endif /* ADD_ENVS_OPTION */

	for(i = 0; i < sizeof(rlimits) / sizeof(int); i += 2)
		getrlimit(rlimits[i], &desc->rlimit[rlimits[i + 1]]);
	desc->envs_len = envs_len;
	desc->envs = envs;
	//print_flat(envs);

	if (shebang_argv)
		flatten_strings(NULL, shebang_argv, &shebang_argv_flat);

	desc->args_len = flatten_strings(shebang_argv_flat, argv + optind,
					 &desc->args);
	//print_flat(desc->args);
	free(shebang_argv);
	free(shebang_argv_flat);

	desc->cpu = target_core;
	desc->enable_vdso = enable_vdso;

	/* Restore the stack size when mcexec stack was shrinked */
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

	/* Overwrite the max with <max> of "--stack-premap <premap>,<max>" */
	if (stack_max != -1) {
		rlim_stack.rlim_cur = stack_max;
		if (rlim_stack.rlim_max != -1 && rlim_stack.rlim_max < rlim_stack.rlim_cur) {
			rlim_stack.rlim_max = rlim_stack.rlim_cur;
		}
	}

	desc->rlimit[MCK_RLIMIT_STACK].rlim_cur = rlim_stack.rlim_cur;
	desc->rlimit[MCK_RLIMIT_STACK].rlim_max = rlim_stack.rlim_max;
	desc->stack_premap = stack_premap;
	__dprintf("desc->rlimit[MCK_RLIMIT_STACK]=%ld,%ld\n", desc->rlimit[MCK_RLIMIT_STACK].rlim_cur, desc->rlimit[MCK_RLIMIT_STACK].rlim_max);

	ncpu = ioctl(fd, MCEXEC_UP_GET_CPU, 0);
	if(ncpu == -1){
		fprintf(stderr, "No CPU found.\n");
		return 1;
	}

	if (nr_processes > ncpu) {
		fprintf(stderr, "error: nr_processes can't exceed nr. of CPUs\n");
		return EINVAL;
	}

	if (nr_threads > 0) {
		n_threads = nr_threads;
	}
	else if (getenv("OMP_NUM_THREADS")) {
		/* Leave some headroom for helper threads.. */
		n_threads = atoi(getenv("OMP_NUM_THREADS")) + 4;
	}
	else {
		/*
		 * When running with partitioned execution, do not allow
		 * more threads then the corresponding number of CPUs.
		 */
		if (nr_processes > 0 && nr_processes < ncpu) {
			n_threads = (ncpu / nr_processes) + 4;

			if (n_threads == 0) {
				n_threads = 2;
			}
		}
		else if (nr_processes == ncpu) {
			n_threads = 1;
		}
		else {
			n_threads = ncpu;
		}
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
		__dprintf("error: allocating DMA area\n");
		exit(1);
	}
	
	/* PIN buffer */
	if (mlock(dma_buf, (size_t)PIN_SIZE)) {
		__dprintf("ERROR: locking dma_buf\n");
		exit(1);
	}

	/* Register per-process structure in mcctrl */
	if (ioctl(fd, MCEXEC_UP_CREATE_PPD, NULL)) {
		perror("creating mcctrl per-process structure");
		close(fd);
		exit(1);
	}

	/* Partitioned execution, obtain CPU set */
	if (nr_processes > 0) {
		struct get_cpu_set_arg cpu_set_arg;
		int mcexec_linux_numa = 0;
		int ikc_mapped = 0;
		int process_rank = -1;
		cpu_set_t mcexec_cpu_set;

		CPU_ZERO(&mcexec_cpu_set);

		cpu_set_arg.cpu_set = (void *)&desc->cpu_set;
		cpu_set_arg.cpu_set_size = sizeof(desc->cpu_set);
		cpu_set_arg.nr_processes = nr_processes;
		cpu_set_arg.target_core = &target_core;
		cpu_set_arg.process_rank = &process_rank;
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
		desc->process_rank = process_rank;

		/* Bind to CPU cores where the LWK process' IKC target maps to */
		if (ikc_mapped && !no_bind_ikc_map) {
			/* This call may not succeed, but that is fine */
			if (sched_setaffinity(0, sizeof(mcexec_cpu_set),
						&mcexec_cpu_set) < 0) {
				__dprintf("WARNING: couldn't bind to mcexec_cpu_set\n");
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

	desc->mpol_bind_mask = 0;
	if (mpol_bind_nodes) {
		struct bitmask *bind_mask;
		bind_mask = numa_parse_nodestring_all(mpol_bind_nodes);

		if (bind_mask) {
			int node;
			for (node = 0; node <= numa_max_possible_node(); ++node) {
				if (numa_bitmask_isbitset(bind_mask, node)) {
					desc->mpol_bind_mask |= (1UL << node);
				}
			}
		}
	}

	desc->uti_thread_rank = uti_thread_rank;
	desc->uti_use_last_cpu = uti_use_last_cpu;

	/* user_start and user_end are set by this call */
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
	__dprintf("mccmd server initialized\n");
#endif

	init_sigaction();

	/* Initialize watchdog thread which detects hang of McKernel */

	if ((error = pthread_attr_init(&watchdog_thread_attr))) {
		fprintf(stderr, "Error: pthread_attr_init failed (%d)\n", error);
		close(fd);
		return 1;
	}
	
	if ((error = pthread_attr_setdetachstate(&watchdog_thread_attr, PTHREAD_CREATE_DETACHED))) {
		fprintf(stderr, "Error: pthread_attr_getdetachstate failed (%d)\n", error);
		close(fd);
		return 1;
	}

	if ((error = pthread_create(&watchdog_thread, &watchdog_thread_attr, watchdog_thread_func, NULL))) {
		fprintf(stderr, "Error: pthread_create failed (%d)\n", error);
		close(fd);
		return 1;
	}

	if ((error = init_worker_threads(fd)) != 0) {
		fprintf(stderr, "%s: Error: creating worker threads: %s\n",
			__func__, strerror(-error));
		close(fd);
		return 1;
	}

	if (ioctl(fd, MCEXEC_UP_START_IMAGE, (unsigned long)desc) != 0) {
		perror("exec");
		close(fd);
		return 1;
	}

#if 1 /* debug : thread killed by exit_group() are still joinable? */
	join_all_threads();
#endif
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

	ret = syscall(w->sr.number, w->sr.args[0], w->sr.args[1], w->sr.args[2],
		 w->sr.args[3], w->sr.args[4], w->sr.args[5]);
	if (ret == -1) {
		ret = -errno;
	}

	/* Overlayfs /sys/X directory lseek() problem work around */
	if (w->sr.number == __NR_lseek && ret == -EINVAL) {
		char proc_path[PATH_MAX];
		char path[PATH_MAX];
		struct stat sb;
		int len;

		sprintf(proc_path, "/proc/self/fd/%d", (int)w->sr.args[0]);

		/* Get filename */
		if ((len = readlink(proc_path, path, sizeof(path))) < 0) {
			fprintf(stderr, "%s: error: readlink() failed for %s\n",
				__FUNCTION__, proc_path);
			perror(": ");
			goto out;
		}

		path[len] = 0;

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
#ifdef POSTK_DEBUG_ARCH_DEP_55
# ifdef __aarch64__
#  define __nr_getdents __NR_getdents64
# else
#  define __nr_getdents __NR_getdents
# endif
	else if (w->sr.number == __nr_getdents && ret > 0) {
#else  /*POSTK_DEBUG_ARCH_DEP_55*/
	else if (w->sr.number == __NR_getdents && ret > 0) {
#endif /*POSTK_DEBUG_ARCH_DEP_55*/
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
		len = readlink(proc_path, path, sizeof(path));
		if (len < 0 || len >= sizeof(path)) {
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

static struct uti_desc *uti_desc;

static void kill_thread(unsigned long tid, int sig,
			struct thread_data_s *my_thread)
{
	struct thread_data_s *tp;

	if (sig == 0)
		sig = LOCALSIG;

	for (tp = thread_data; tp; tp = tp->next) {
		if (tp == my_thread)
			continue;
		if (tp->remote_tid == tid) {
			if (pthread_kill(tp->thread_id, sig) == ESRCH) {
				printf("%s: ERROR: Thread not found (tid=%ld,sig=%d)\n", __FUNCTION__, tid, sig);
			}
		}
	}
}

static long util_thread(struct thread_data_s *my_thread, unsigned long rp_rctx, int remote_tid, unsigned long pattr, unsigned long uti_clv, unsigned long _uti_desc)
{
	struct uti_get_ctx_desc get_ctx_desc;
	struct uti_save_fs_desc save_fs_desc;
	int rc = 0;

	struct thread_data_s *tp;

	uti_desc = (struct uti_desc *)_uti_desc;
	if (!uti_desc) {
		printf("%s: ERROR: uti_desc not found. Add --enable-uti option to mcexec.\n",
		       __func__);
		rc = -EINVAL;
		goto out;
	}
	__dprintf("%s: uti_desc=%p\n", __FUNCTION__, uti_desc);

	pthread_barrier_init(&uti_init_ready, NULL, 2);
	if ((rc = create_worker_thread(&tp, &uti_init_ready))) {
		printf("%s: Error: create_worker_thread failed (%d)\n", __FUNCTION__, rc);
		rc = -EINVAL;
		goto out;
	}
	pthread_barrier_wait(&uti_init_ready);
	__dprintf("%s: worker tid: %d\n", __FUNCTION__, tp->tid);


	/* Initialize uti related variables for syscall_intercept */
	uti_desc->fd = fd;

	rc = syscall(888);
	if (rc != -1) {
		fprintf(stderr, "%s: WARNING: syscall_intercept returned %x\n", __FUNCTION__, rc);
	}

	/* Get the remote context, record refill tid */
	get_ctx_desc.rp_rctx = rp_rctx;
	get_ctx_desc.rctx = uti_desc->rctx;
	get_ctx_desc.lctx = uti_desc->lctx;
	get_ctx_desc.uti_refill_tid = tp->tid;

	if ((rc = ioctl(fd, MCEXEC_UP_UTI_GET_CTX, &get_ctx_desc))) {
		fprintf(stderr, "%s: Error: MCEXEC_UP_UTI_GET_CTX failed (%d)\n", __FUNCTION__, errno);
		rc = -errno;
		goto out;
	}

	/* Initialize uti thread info */
	uti_desc->mck_tid = remote_tid;
	uti_desc->key = get_ctx_desc.key;
	uti_desc->pid = getpid();
	uti_desc->tid = gettid();
	uti_desc->uti_clv = uti_clv;
	
	/* Initialize list of syscall arguments for syscall_intercept */
	if (sizeof(struct syscall_struct) * 11 > PAGE_SIZE) {
		fprintf(stderr, "%s: ERROR: param is too large\n", __FUNCTION__);
		rc = -ENOMEM;
		goto out;
	}

	if (pattr) {
		struct uti_attr_desc desc;

		desc.phys_attr = pattr;
		desc.uti_cpu_set_str = getenv("UTI_CPU_SET");
		desc.uti_cpu_set_len = strlen(desc.uti_cpu_set_str) + 1;

		if ((rc = ioctl(fd, MCEXEC_UP_UTI_ATTR, &desc))) {
			fprintf(stderr, "%s: error: MCEXEC_UP_UTI_ATTR: %s\n",
				__func__, strerror(errno));
			rc = -errno;
			goto out;
		}
	}

	/* Start intercepting syscalls. Note that it dereferences pointers in uti_desc. */
	uti_desc->start_syscall_intercept = 1;

	/* Save remote and local FS and then contex-switch */
	save_fs_desc.rctx = uti_desc->rctx;
	save_fs_desc.lctx = uti_desc->lctx;

	if ((rc = switch_ctx(fd, MCEXEC_UP_UTI_SAVE_FS, &save_fs_desc, uti_desc->lctx, uti_desc->rctx))
	    < 0) {
		fprintf(stderr, "%s: ERROR switch_ctx failed (%d)\n", __FUNCTION__, rc);
		goto out;
	}
	fprintf(stderr, "%s: ERROR: Returned from switch_ctx (%d)\n", __FUNCTION__, rc);
	rc = -EINVAL;

out:
	return rc;
}

long do_strncpy_from_user(int fd, void *dest, void *src, unsigned long n)
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

#ifdef POSTK_DEBUG_ARCH_DEP_72 /* add __NR_newfstat */
static int
syscall_pathname(int dirfd, char *pathname, size_t size)
{
	int ret = 0;
	char *tempbuf = NULL;
	size_t tempbuf_size;

	if (pathname[0] == '/') {
		goto out;
	}

	if (dirfd != AT_FDCWD) {
		int len;
		char dfdpath[64];
		snprintf(dfdpath, sizeof(dfdpath), "/proc/self/fd/%d", dirfd);

		tempbuf_size = size;
		tempbuf = malloc(tempbuf_size);
		if (tempbuf == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		ret = readlink(dfdpath, tempbuf, tempbuf_size);
		if (ret == -1) {
			ret = -errno;
			goto out;
		}

		len = strlen(pathname);
		if (tempbuf_size <= ret + 1 + len + 1) {
			ret = -ENAMETOOLONG;
			goto out;
		}
		tempbuf[ret] = '/';
		strncpy(&tempbuf[ret+1], pathname, len+1);

		strcpy(pathname, tempbuf);
	}
out:
	if (tempbuf) {
		free(tempbuf);
	}
	return ret;
}
#endif /*POSTK_DEBUG_ARCH_DEP_72*/

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
		if (!(w.sr.number == __NR_write && w.sr.args[0] == 1)) {
			__dprintf("[%d] got syscall: %ld\n", cpu, w.sr.number);
		}
		//pthread_mutex_lock(lock);

		my_thread->remote_tid = w.sr.rtid;
		my_thread->remote_cpu = w.cpu;

		switch (w.sr.number) {
		case __NR_openat:
			/* initialize buffer */
			memset(tmpbuf, '\0', sizeof(tmpbuf));
			memset(pathbuf, '\0', sizeof(pathbuf));

			/* check argument 1 dirfd */
			ret = do_strncpy_from_user(fd, pathbuf,
			                           (void *)w.sr.args[1],
			                           PATH_MAX);
			__dprintf("openat(dirfd == AT_FDCWD)\n");
			if (ret >= PATH_MAX) {
				ret = -ENAMETOOLONG;
			}
			if (ret < 0) {
				do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
				break;
			}

			if ((int)w.sr.args[0] != AT_FDCWD &&
			    pathbuf[0] != '/') {
				/* dirfd != AT_FDCWD */
				__dprintf("openat(dirfd != AT_FDCWD)\n");
				snprintf(tmpbuf, sizeof(tmpbuf),
				         "/proc/self/fd/%d", (int)w.sr.args[0]);
				ret = readlink(tmpbuf, pathbuf,
				               sizeof(pathbuf) - 1);
				if (ret == -1 &&
				    (errno == ENOENT ||
				     errno == EINVAL)) {
					do_syscall_return(fd, cpu, -EBADF, 0, 0,
					                  0, 0);
					break;
				}
				if (ret < 0) {
					do_syscall_return(fd, cpu, -errno, 0, 0,
					                  0, 0);
					break;
				}
				__dprintf("  %s -> %s\n", tmpbuf, pathbuf);
				ret = do_strncpy_from_user(fd, tmpbuf,
				                           (void *)w.sr.args[1],
				                           PATH_MAX);
				if (ret >= PATH_MAX) {
					ret = -ENAMETOOLONG;
				}
				if (ret < 0) {
					do_syscall_return(fd, cpu, ret, 0, 0, 0,
					                  0);
					break;
				}
				strncat(pathbuf, "/",
					sizeof(pathbuf) - strlen(pathbuf) - 1);
				strncat(pathbuf, tmpbuf,
					sizeof(pathbuf) - strlen(pathbuf) - 1);
			}
			else {
			}
			__dprintf("openat: %s,tid=%d\n", pathbuf, my_thread->remote_tid);

			fn = chgpath(pathbuf, tmpbuf);

			ret = open(fn, w.sr.args[2], w.sr.args[3]);
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
			kill_thread(w.sr.args[1], w.sr.args[2], my_thread);
			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);
			break;
		case __NR_exit:
		case __NR_exit_group:
			sig = 0;
			term = 0;
			
			/* Enforce the order in which mcexec is destroyed and then 
			   McKernel process is destroyed to prevent
			   migrated-to-Linux thread from accessing stale memory values.
			   It is done by not calling do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);
			   here and making McKernel side wait until release_handler() is called. */

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
						if(!ischild) {
							fprintf(stderr, "Terminate by signal %d\n", sig);
						}
					}
					else if(term) {
						__dprintf("Exit status: %d\n", term);
					}
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
			__dprintf("mccmd server exited\n");
#endif
			if(sig){
				signal(sig, SIG_DFL);
				kill(getpid(), sig);
				pause();
			}

			exit(term); /* Call release_handler() and proceed terminate() */

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

				for (; i < w.sr.args[4]; ++i) {
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

		case __NR_clone: {
			struct fork_sync *fs;
			struct fork_sync_container *fsc = NULL;
			struct fork_sync_container *fp;
			struct fork_sync_container *fb;
			int flag = w.sr.args[0];
			int rc = -1;
			pid_t pid;

			if (flag == 1) {
				pid = w.sr.args[1];
				rc = 0;
				pthread_mutex_lock(&fork_sync_mutex);
				for (fp = fork_sync_top, fb = NULL; fp; fb = fp, fp = fp->next)
					if (fp->pid == pid)
						break;
				if (fp) {
					fs = fp->fs;
					if (fb)
						fb->next = fp->next;
					else
						fork_sync_top = fp->next;
					fs->success = 1;
					munmap(fs, sizeof(struct fork_sync));
					free(fp);
				}
				pthread_mutex_unlock(&fork_sync_mutex);
				do_syscall_return(fd, cpu, rc, 0, 0, 0, 0);
				break;
			}

			fs = mmap(NULL, sizeof(struct fork_sync),
			          PROT_READ | PROT_WRITE,
			          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
			if (fs == (void *)-1) {
				goto fork_err;
			}
			memset(fs, '\0', sizeof(struct fork_sync));
			sem_init(&fs->sem, 1, 0);

			fsc = malloc(sizeof(struct fork_sync_container));
			if (!fsc) {
				goto fork_err;
			}
			memset(fsc, '\0', sizeof(struct fork_sync_container));
			pthread_mutex_lock(&fork_sync_mutex);
			fsc->next = fork_sync_top;
			fork_sync_top = fsc;
			pthread_mutex_unlock(&fork_sync_mutex);
			fsc->fs = fs;

			fsc->pid = pid = fork();

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
				struct rpgtable_desc rpt;

				ischild = 1;
				/* Reopen device fd */
				close(fd);
				fd = opendev();
				if (fd < 0) {
					fs->status = -errno;
					fprintf(stderr, "ERROR: opening %s\n", dev);
					
					goto fork_child_sync_pipe;
				}

				rpt.start = w.sr.args[1];
				rpt.len = w.sr.args[2];
				rpt.rpgtable = w.sr.args[3];
				if (ioctl(fd, MCEXEC_UP_CREATE_PPD, &rpt)) {
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

				if ((ret = init_worker_threads(fd)) != 0) {
					fprintf(stderr, "%s: Error: creating worker threads: %s\n",
						__func__, strerror(-ret));
					close(fd);
					exit(1);
				}

fork_child_sync_pipe:
				sem_post(&fs->sem);
				sem_destroy(&fs->sem);
				if (fs->status)
					exit(1);

				for (fp = fork_sync_top; fp;) {
					fb = fp->next;
					if (fp->fs && fp->fs != fs)
						munmap(fp->fs, sizeof(struct fork_sync));
					free(fp);
					fp = fb;
				}
				fork_sync_top = NULL;
				pthread_mutex_init(&fork_sync_mutex, NULL);

				npdesc.pid = getpid();
				ioctl(fd, MCEXEC_UP_NEW_PROCESS, &npdesc);

				/* TODO: does the forked thread run in a pthread context? */
				while (getppid() != 1 &&
				       fs->success == 0) {
					sched_yield();
				}

				if (fs->success == 0) {
					exit(1);
				}

				munmap(fs, sizeof(struct fork_sync));
#if 1 /* debug : thread killed by exit_group() are still joinable? */
				join_all_threads();
#endif
				return ret;
			    }
				
			    /* Parent */
			    default:
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

fork_err:
			if (fs) {
				sem_destroy(&fs->sem);
				if (rc < 0) {
					munmap(fs, sizeof(struct fork_sync));
					pthread_mutex_lock(&fork_sync_mutex);
					for (fp = fork_sync_top, fb = NULL; fp; fb = fp, fp = fp->next)
						if (fp == fsc)
							break;
					if (fp) {
						if (fb)
							fb->next = fsc->next;
						else
							fork_sync_top = fsc->next;
						free(fp);
					}
					pthread_mutex_unlock(&fork_sync_mutex);
				}
			}
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
				char *filename;
				char **shebang_argv;
				char *shebang_argv_flat;
				char *buffer;
				size_t size;
				int ret;

				/* Load descriptor phase */
				case 1:
					shebang_argv = NULL;
					buffer = NULL;
					desc = NULL;
					filename = (char *)w.sr.args[1];
					
					if ((ret = load_elf_desc_shebang(filename, &desc,
									 &shebang_argv, 0)) != 0) {
						goto return_execve1;
					}

					desc->enable_vdso = enable_vdso;
					__dprintf("execve(): load_elf_desc() for %s OK, num sections: %d\n",
						filename, desc->num_sections);

					desc->rlimit[MCK_RLIMIT_STACK].rlim_cur = rlim_stack.rlim_cur;
					desc->rlimit[MCK_RLIMIT_STACK].rlim_max = rlim_stack.rlim_max;
					desc->stack_premap = stack_premap;

					buffer = (char *)desc;
					size = sizeof(struct program_load_desc) +
					       sizeof(struct program_image_section) *
					       desc->num_sections;
					if (shebang_argv) {
						desc->args_len = flatten_strings(NULL, shebang_argv,
										 &shebang_argv_flat);
						buffer = malloc(size + desc->args_len);
						if (!buffer) {
							fprintf(stderr,
								"execve(): could not alloc transfer buffer for file %s\n",
								filename);
							free(shebang_argv_flat);
							ret = ENOMEM;
							goto return_execve1;
						}
						memcpy(buffer, desc, size);
						memcpy(buffer + size, shebang_argv_flat,
						       desc->args_len);
						free(shebang_argv_flat);
						size += desc->args_len;
					}

					/* Copy descriptor to co-kernel side */
					trans.userp = buffer;
					trans.rphys = w.sr.args[2];
					trans.size = size;
					trans.direction = MCEXEC_UP_TRANSFER_TO_REMOTE;
					
					if (ioctl(fd, MCEXEC_UP_TRANSFER, &trans) != 0) {
						fprintf(stderr, 
							"execve(): error transfering ELF for file %s\n", 
							filename);
						ret = -errno;
						goto return_execve1;
					}
					
					__dprintf("execve(): load_elf_desc() for %s OK\n",
						  filename);

					ret = 0;
return_execve1:
					/* We can't be sure next phase will succeed */
					/* TODO: what shall we do with fp in desc?? */
					if (buffer != (char *)desc)
						free(buffer);
					free(desc);

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
#ifdef POSTK_DEBUG_TEMP_FIX_45 /* setfsgid()/setfsuid() mismatch fix. */
				ret |= (long)gettid() << 32;
#endif /* POSTK_DEBUG_TEMP_FIX_45 */
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
#ifdef POSTK_DEBUG_TEMP_FIX_45 /* setfsgid()/setfsuid() mismatch fix. */
			ret |= (long)gettid() << 32;
#endif /*POSTK_DEBUG_TEMP_FIX_45 */
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_close:
			if(w.sr.args[0] == fd)
				ret = -EBADF;
			else
				ret = do_generic_syscall(&w);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;
#ifdef POSTK_DEBUG_ARCH_DEP_36
#ifdef __aarch64__
		case __NR_readlinkat:
			/* initialize buffer */
			memset(tmpbuf, '\0', sizeof(tmpbuf));
			memset(pathbuf, '\0', sizeof(pathbuf));

			/* check argument 1 dirfd */
			if ((int)w.sr.args[0] != AT_FDCWD) {
				/* dirfd != AT_FDCWD */
				__dprintf("readlinkat(dirfd != AT_FDCWD)\n");
				snprintf(tmpbuf, sizeof(tmpbuf), "/proc/self/fd/%d", (int)w.sr.args[0]);
				ret = readlink(tmpbuf, pathbuf, sizeof(pathbuf) - 1);
				if (ret < 0) {
					do_syscall_return(fd, cpu, -errno, 0, 0, 0, 0);
					break;
				}
				__dprintf("  %s -> %s\n", tmpbuf, pathbuf);
				ret = do_strncpy_from_user(fd, tmpbuf, (void *)w.sr.args[1], PATH_MAX);
				if (ret >= PATH_MAX) {
					ret = -ENAMETOOLONG;
				}
				if (ret < 0) {
					do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
					break;
				}
				strncat(pathbuf, "/", 1);
				strncat(pathbuf, tmpbuf, strlen(tmpbuf) + 1);
			} else {
				/* dirfd == AT_FDCWD */
				__dprintf("readlinkat(dirfd == AT_FDCWD)\n");
				ret = do_strncpy_from_user(fd, pathbuf, (void *)w.sr.args[1], PATH_MAX);
				if (ret >= PATH_MAX) {
					ret = -ENAMETOOLONG;
				}
				if (ret < 0) {
					do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
					break;
				}
			}
			__dprintf("readlinkat: %s\n", pathbuf);

			fn = chgpath(pathbuf, tmpbuf);

			ret = readlink(fn, (char *)w.sr.args[2], w.sr.args[3]);
			__dprintf("readlinkat: dirfd=%d, path=%s, buf=%s, ret=%ld\n", 
				(int)w.sr.args[0], fn, (char *)w.sr.args[2], ret);
			SET_ERR(ret);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;
#else	/* __aarch64__ */
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
#endif	/* __aarch64__ */
#else	/* POSTK_DEBUG_ARCH_DEP_36 */
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
#endif	/* POSTK_DEBUG_ARCH_DEP_36 */

#ifdef POSTK_DEBUG_ARCH_DEP_72 /* add __NR_newfstat */
		case __NR_newfstatat:
			/* initialize buffer */
			memset(tmpbuf, '\0', sizeof(tmpbuf));
			memset(pathbuf, '\0', sizeof(pathbuf));

			ret = do_strncpy_from_user(fd, pathbuf, (void *)w.sr.args[1], PATH_MAX);
			if (ret >= PATH_MAX) {
				ret = -ENAMETOOLONG;
			}
			if (ret < 0) {
				do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
				break;
			}

			if (pathbuf[0] == '\0') {
				// empty string
				if ((int)w.sr.args[3] & AT_EMPTY_PATH) {
					if ((int)w.sr.args[0] == AT_FDCWD) {
						if (NULL == getcwd(pathbuf, PATH_MAX)) {
							do_syscall_return(fd, cpu, -errno, 0, 0, 0, 0);
							break;
						}
					} else {
						char dfdpath[64];
						snprintf(dfdpath, sizeof(dfdpath), "/proc/self/fd/%d", (int)w.sr.args[0]);
						ret = readlink(dfdpath, pathbuf, PATH_MAX);
						if (ret == -1) {
							do_syscall_return(fd, cpu, -errno, 0, 0, 0, 0);
							break;
						}
						pathbuf[ret] = '\0';
					}
				}
			} else if (pathbuf[0] != '/') {
				// relative path
				ret = syscall_pathname((int)w.sr.args[0], pathbuf, PATH_MAX);
				if (ret < 0) {
					do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
					break;
				}
			}

			fn = chgpath(pathbuf, tmpbuf);
			if (fn[0] == '/') {
				ret = fstatat((int)w.sr.args[0],
					      fn,
					      (struct stat*)w.sr.args[2],
					      (int)w.sr.args[3]);
				__dprintf("fstatat: dirfd=%d, pathname=%s, buf=%p, flags=%x, ret=%ld\n",
					  (int)w.sr.args[0], fn, (void*)w.sr.args[2], (int)w.sr.args[3], ret);
			} else {
				ret = fstatat((int)w.sr.args[0],
					      (const char*)w.sr.args[1],
					      (struct stat*)w.sr.args[2],
					      (int)w.sr.args[3]);
				__dprintf("fstatat: dirfd=%d, pathname=%s, buf=%p, flags=%x, ret=%ld\n",
					  (int)w.sr.args[0], (char*)w.sr.args[1], (void*)w.sr.args[2], (int)w.sr.args[3], ret);
			}

			SET_ERR(ret);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;
#ifdef __NR_stat
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
#endif /* __NR_stat */
#else /* POSTK_DEBUG_ARCH_DEP_72 */
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
#endif /* POSTK_DEBUG_ARCH_DEP_72 */

		case __NR_sched_setaffinity:
			if (w.sr.args[0] == 0) {
				ret = util_thread(my_thread, w.sr.args[1], w.sr.rtid,
				                  w.sr.args[2], w.sr.args[3], w.sr.args[4]);
			}
			else {
				__eprintf("__NR_sched_setaffinity: invalid argument (%lx)\n", w.sr.args[0]);
				ret = -EINVAL;
			}
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;
		case 801: {// swapout
#ifdef ENABLE_QLMPI
			int rc;
			int spawned;
			int rank;
			int ql_fd = -1;
			int len;
			struct sockaddr_un unix_addr;
			char msg_buf[QL_BUF_MAX];
			char *ql_name;

			rc = PMI_Init(&spawned);
			if (rc != 0) {
				fprintf(stderr, "swapout(): ERROR: failed to init PMI\n");
				ret = -1;
				goto return_swapout;
			}
			rc = PMI_Get_rank(&rank);
			if (rc != 0) {
				fprintf(stderr, "swapout(): ERROR: failed to get Rank\n");
				ret = -1;
				goto return_swapout;
			}

			// swap synchronization 
			rc = PMI_Barrier();

			if (rank == 0) {
				// tell ql_server what calculation is done.
				ql_fd = socket(AF_UNIX, SOCK_STREAM, 0);
				if (ql_fd < 0) {
					fprintf(stderr, "swapout(): ERROR: failed to open socket\n");
					ret = -1;
					goto return_swapout;
				}

				unix_addr.sun_family = AF_UNIX;
				strcpy(unix_addr.sun_path, getenv("QL_SOCKET_FILE"));
				len = sizeof(unix_addr.sun_family) + strlen(unix_addr.sun_path) + 1;
				rc = connect(ql_fd, (struct sockaddr*)&unix_addr, len);
				if (rc < 0) {
					fprintf(stderr, "swapout(): ERROR: failed to connect ql_server\n");
					ret = -1;
					goto return_swapout;
				}

				ql_name = getenv(QL_NAME);
				sprintf(msg_buf, "%c %04x %s",
				        QL_EXEC_END, (unsigned int)strlen(ql_name), ql_name);
				rc = send(ql_fd, msg_buf, strlen(msg_buf) + 1, 0);
				if (rc < 0) {
					fprintf(stderr, "swapout(): ERROR: failed to send QL_EXEC_END\n");
					ret = -1;
					goto return_swapout;
				}
				
				// wait resume-req from ql_server.
#ifdef QL_DEBUG
				fprintf(stdout, "INFO: waiting resume-req ...\n");
#endif
				rc = recv(ql_fd, msg_buf, strlen(msg_buf) + 1, 0);

				if (rc < 0) {
					fprintf(stderr, "swapout(): ERROR: failed to recieve\n");
					ret = -1;
					goto return_swapout;
				}

				// parse message
				if (msg_buf[0] == QL_RET_RESUME) {
#ifdef QL_DEBUG
					fprintf(stdout, "INFO: recieved resume-req\n");
#endif
				}
				else {
					fprintf(stderr, "swapout(): ERROR: recieved unexpected requsest from ql_server\n");
					ret = -1;
					goto return_swapout;
				}

				// resume-req synchronization
				rc = PMI_Barrier();
			}
			else {
				// resume-req synchronization 
				rc = PMI_Barrier();
			}
			
			ret = 0;

return_swapout:
			if (ql_fd >= 0) {
				close(ql_fd);
			}

			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
#else
			printf("mcexec has not been compiled with ENABLE_QLMPI\n");
			ret = -1;
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
#endif // ENABLE_QLMPI
			break;
		}
		case 802: /* debugging purpose */
			printf("linux mlock(%p, %ld)\n",
			       (void *)w.sr.args[0], w.sr.args[1]);
			printf("str(%p)=%s", (void*)w.sr.args[0], (char*)w.sr.args[0]);
			ret = mlock((void *)w.sr.args[0], w.sr.args[1]);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

#ifndef ARG_MAX
#define ARG_MAX 256
#endif
		case 811: { // linux_spawn
			int rc, i;
			pid_t pid;
			size_t slen;
			char *exec_path = NULL;
			char* argv[ARG_MAX];
			char** spawn_args = (char**)w.sr.args[1];

			if (!w.sr.args[0] || ! spawn_args) {
				fprintf(stderr, "linux_spawn(): ERROR: invalid argument \n");
				ret = -1;
				goto return_linux_spawn;
			}

			// copy exec_path
			slen = strlen((char*)w.sr.args[0]) + 1;
			if (slen <= 0 || slen >= PATH_MAX) {
				fprintf(stderr, "linux_spawn(): ERROR: invalid exec_path \n");
				ret = -1;
				goto return_linux_spawn;
			}
			exec_path = malloc(slen);
			if (!exec_path) {
				fprintf(stderr, "linux_spawn(): ERROR: failed to allocating exec_path\n");
				ret = -1;
				goto return_linux_spawn;
			}
			memset(exec_path, '\0', slen);

			rc = do_strncpy_from_user(fd, exec_path, (void *)w.sr.args[0], slen);
			if (rc < 0) {
				fprintf(stderr, "linux_spawn(): ERROR: failed to strncpy from user\n");
				ret = -1;
				goto return_linux_spawn;
			}

			// copy args to argv[]
			for (i = 0; spawn_args[i] != NULL; i++) {
				slen = strlen(spawn_args[i]) + 1;
				argv[i] = malloc(slen);
				if (!argv[i]) {
					fprintf(stderr, "linux_spawn(): ERROR: failed to allocating argv[%d]\n", i);
					ret = -1;
					goto return_linux_spawn;
				}
				memset(argv[i], '\0', slen);
				rc = do_strncpy_from_user(fd, argv[i], spawn_args[i], slen);
				if (rc < 0) {
					fprintf(stderr, "linux_spawn(): ERROR: failed to strncpy from user\n");
					ret = -1;
					goto return_linux_spawn;
				}
			}

			rc = posix_spawn(&pid, exec_path, NULL, NULL, argv, NULL);
			if (rc != 0) {
				fprintf(stderr, "linux_spawn(): ERROR: posix_spawn returned %d\n", rc);
				ret = -1;
				goto return_linux_spawn;
			}

			ret = 0;
return_linux_spawn:
			// free allocated memory
			if (exec_path) {
				free(exec_path);
			}
			for (i = 0; argv[i] != NULL; i++) {
				free(argv[i]);
			}

			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;
		}

		default:
			if (archdep_syscall(&w, &ret)) {
				ret = do_generic_syscall(&w);
			}
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		}

		my_thread->remote_tid = -1;

		//pthread_mutex_unlock(lock);
	}
	__dprintf("timed out.\n");
	return 1;
}

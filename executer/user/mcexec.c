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
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/mount.h>
#include <include/generated/uapi/linux/version.h>
#include "../include/uprotocol.h"

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

int main_loop(int fd, int cpu, pthread_mutex_t *lock);

static int mcosid;
static int fd;
static char *exec_path = NULL;
static char *altroot;
static const char rlimit_stack_envname[] = "MCKERNEL_RLIMIT_STACK";
static int ischild;

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
	memset(desc, '\0', sizeof(struct program_load_desc));
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

int lookup_exec_path(char *filename, char *path, int max_len) 
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
			if (!PATH) {
				PATH = getenv("PATH");
			}

			if (strlen(filename) >= 255) {
				return ENAMETOOLONG;
			}
			
			/* See first whether file is available in current working dir */
			error = access(filename, X_OK);
			if (error == 0) {
				__dprintf("lookup_exec_path(): found %s in cwd\n", filename);
				error = snprintf(path, max_len, "%s", filename);

				if (error < 0 || error >= max_len) {
					fprintf(stderr, "lookup_exec_path(): array too small?\n");
					return ENOMEM;
				}

				found = 1;
				break;
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
		fprintf(stderr, "lookup_exec_path(): error stat\n");
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
	full_len = sizeof(int) + sizeof(char *); // Counter and terminating NULL
	if (first) {
		full_len += sizeof(char *) + strlen(first) + 1; 
	}

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
	*((int*)_flat) = nr_strings + (first ? 1 : 0);
	
	// Actual offset
	flat_offset = sizeof(int) + sizeof(char *) * (nr_strings + 1 + 
			(first ? 1 : 0)); 

	if (first) {
		*((char **)(_flat + sizeof(int))) = (void *)flat_offset;
		memcpy(_flat + flat_offset, first, strlen(first) + 1);
		flat_offset += strlen(first) + 1;
	}

	for (string_i = 0; string_i < nr_strings; ++string_i) {
		
		/* Fabricate the string */
		*((char **)(_flat + sizeof(int) + (string_i + (first ? 1 : 0)) 
					* sizeof(char *))) = (void *)flat_offset;
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
	int remote_tid;
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
	td->remote_tid = (int)td->tid;
	pthread_barrier_wait(&init_ready);
	td->ret = main_loop(td->fd, td->cpu, td->lock);

	return NULL;
}

#define LOCALSIG SIGURG

void
sendsig(int sig, siginfo_t *siginfo, void *context)
{
	pid_t	pid = getpid();
	pid_t	tid = gettid();
	int	remote_tid;
	int	i;
	int	cpu;
	struct signal_desc sigdesc;

	if(siginfo->si_pid == pid &&
	   siginfo->si_signo == LOCALSIG)
		return;

	if(siginfo->si_signo == SIGCHLD)
		return;

	for(i = 0; i < ncpu; i++){
		if(siginfo->si_pid == pid &&
		   thread_data[i].tid == tid){
			if(thread_data[i].terminate)
				return;
			break;
		}
		if(siginfo->si_pid != pid &&
		   thread_data[i].remote_tid == tid){
			if(thread_data[i].terminate)
				return;
			break;
		}
	}
	if(i != ncpu){
		remote_tid = thread_data[i].remote_tid;
		cpu = thread_data[i].cpu;
	}
	else{
		cpu = 0;
		remote_tid = -1;
	}

	sigdesc.cpu = cpu;
	sigdesc.pid = (int)pid;
	sigdesc.tid = remote_tid;
	sigdesc.sig = sig;
	memcpy(&sigdesc.info, siginfo, 128);
	if (ioctl(fd, MCEXEC_UP_SEND_SIGNAL, &sigdesc) != 0) {
		perror("send_signal");
		close(fd);
		exit(1);
	}
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
		tmp = w->sr.args[1];
		flags = 0;
		if(tmp & SFD_NONBLOCK)
			flags |= O_NONBLOCK;
		if(tmp & SFD_CLOEXEC)
			flags |= O_CLOEXEC;
		pipe2(sfd->sigpipe, flags);
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
			write(sfd->sigpipe[1], info, sizeof(struct signalfd_siginfo));
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
	fprintf(stderr, "Usage: %s [-c target_core] [<mcos-id>] (program) [args...]\n", argv[0]);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
#define READ_BUFSIZE 1024
static int isunshare(void)
{
	int err = 0;
	int ret;
	int fd;
	char proc_path[PATH_MAX];
	ssize_t len_read;
	char buf_read[READ_BUFSIZE + 1];
	char *buf_read_off;
	char *buf_find;
	char buf_cmp[READ_BUFSIZE + 1];
	char *buf_cmp_off;
	ssize_t len_copy;

	snprintf(proc_path, sizeof(proc_path), "/proc/%d/mounts", getpid());
	fd = open(proc_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error: Failed to open %s.\n", proc_path);
		return -1;
	}

	buf_cmp_off = buf_cmp;
	while (1) {
		len_read = read(fd, buf_read, READ_BUFSIZE);
		if (len_read == -1) {
			fprintf(stderr, "Error: Failed to read.\n");
			err = -1;
			break;
		}

		buf_read_off = buf_read;
		while (1) {
			if ((len_read - (buf_read_off - buf_read)) <= 0) {
				break;
			}
			buf_find = memchr(buf_read_off, '\n', 
				len_read - (buf_read_off - buf_read));
			if (buf_find) {
				len_copy = buf_find - buf_read_off;	
			} else {
				len_copy = len_read - (buf_read_off - buf_read);
			}
			memcpy(buf_cmp_off, buf_read_off, len_copy);
			*(buf_cmp_off + len_copy) = '\0';

			if (buf_find) {
				buf_read_off = buf_read_off + len_copy + 1;
				buf_cmp_off = buf_cmp;
				ret = strncmp(buf_cmp, "mcoverlay /proc ", 16);
				if (!ret) {
					err = 1;
					break;
				}
			} else {
				buf_read_off = buf_read_off + len_copy;
				buf_cmp_off = buf_cmp_off + len_copy;
				break;
			}
		}

		if (err == 1 || len_read == 0) {
			break;
		}
	}

	close(fd);

	__dprintf("err=%d\n", err);
	return err;
}
#endif

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
	int opt;
	char path[1024];
	char *shell = NULL;
	char shell_path[1024];

#ifdef USE_SYSCALL_MOD_CALL
	__glob_argc = argc;
	__glob_argv = argv;
#endif

	altroot = getenv("MCEXEC_ALT_ROOT");
	if (!altroot) {
		altroot = "/usr/linux-k1om-4.7/linux-k1om";
	}
	
	/* Collect environment variables */
	envs_len = flatten_strings(-1, NULL, environ, &envs);
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
	__dprintf("%s", "\n");

	/* Open OS chardev for ioctl() */
	fd = open(dev, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Error: Failed to open %s.\n", dev);
		return 1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	__dprintf("mcoverlay enable\n");
	char mcos_procdir[PATH_MAX];
	char mcos_sysdir[PATH_MAX];
	struct sys_unshare_desc unshare_desc;
	struct sys_mount_desc mount_desc;

	error = isunshare();
	if (error == 0) {
		unshare_desc.unshare_flags = CLONE_NEWNS;
		if (ioctl(fd, MCEXEC_UP_SYS_UNSHARE, 
			(unsigned long)&unshare_desc) != 0) {
			fprintf(stderr, "Error: Failed to unshare. (%s)\n", 
				strerror(errno));
			return 1;
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
	} else if (error == -1) {
		return 1;
	}
#else
	__dprintf("mcoverlay disable\n");
#endif

	if (lookup_exec_path(argv[optind], path, sizeof(path)) != 0) {
		fprintf(stderr, "error: finding file: %s\n", argv[optind]);
		return 1;
	}

	if (load_elf_desc(path, &desc, &shell) != 0) {
		fprintf(stderr, "error: loading file: %s\n", argv[optind]);
		return 1;
	}

	/* Check whether shell script */
	if (shell) {
		if (lookup_exec_path(shell, shell_path, sizeof(shell_path)) != 0) {
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
	desc->rlimit[MCK_RLIMIT_STACK].rlim_cur = rlim_stack.rlim_cur;
	desc->rlimit[MCK_RLIMIT_STACK].rlim_max = rlim_stack.rlim_max;

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
		pthread_kill(thread_data[cpu].thread_id, LOCALSIG);
	}
	else{
		int	i;

		for (i = 0; i < ncpu; ++i) {
			pthread_kill(thread_data[i].thread_id, LOCALSIG);
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

char *
chgpath(char *in, char *buf)
{
	char	*fn = in;
	struct stat	sb;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	if(!strcmp(fn, "/sys/devices/system/cpu/online")){
#else
	if (!strncmp(fn, "/proc/self/", 11)){
		sprintf(buf, "/proc/mcos%d/%d/%s", mcosid, getpid(), fn + 11);
		fn = buf;
	}
	else if(!strncmp(fn, "/proc/", 6)){
		sprintf(buf, "/proc/mcos%d/%s", mcosid, fn + 6);
		fn = buf;
	}
	else if(!strcmp(fn, "/sys/devices/system/cpu/online")){
#endif
		fn = "/admin/fs/attached/files/sys/devices/system/cpu/online";
	}
	else
		return in;

	if(stat(fn, &sb) == -1)
		return in;
	return fn;
}

int main_loop(int fd, int cpu, pthread_mutex_t *lock)
{
	struct syscall_wait_desc w;
	long ret;
	char *fn;
	int sig;
	int term;
	struct timespec tv;
	char pathbuf[PATH_MAX];
	char tmpbuf[PATH_MAX];

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
			kill_thread(w.sr.args[1]);
			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);
			break;
		case __NR_exit:
		case __NR_exit_group:
			sig = 0;
			term = 0;
			
			/* Drop executable file */
			if ((ret = ioctl(fd, MCEXEC_UP_CLOSE_EXEC)) != 0) {
				fprintf(stderr, "WARNING: close_exec() couldn't find exec file?\n");
			}

			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);

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
		case __NR_mprotect:
			/* reserved for internal use */
			do_syscall_return(fd, cpu, -ENOSYS, 0, 0, 0, 0);
			break;

		case __NR_munmap:
			ret = madvise((void *)w.sr.args[0], w.sr.args[1], MADV_DONTNEED);
			SET_ERR(ret);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

#ifdef USE_SYSCALL_MOD_CALL
		case 303:{
			__dprintf("mcexec.c,mod_cal,mod=%ld,cmd=%ld\n", w.sr.args[0], w.sr.args[1]);
			mc_cmd_handle(fd, cpu, w.sr.args);
			break;
		}
#endif

		case __NR_gettid:{
			int mode = w.sr.args[0];
			int remote_pid = w.sr.args[1];
			int newcpuid = w.sr.args[2];
			int oldcpuid = w.sr.args[3];
			int wtid = thread_data[newcpuid].remote_tid;

			if(mode == 0){
				thread_data[ncpu].remote_tid = wtid;
				thread_data[newcpuid].remote_tid = remote_pid;
			}
			else if(mode == 2){
				thread_data[newcpuid].remote_tid = thread_data[oldcpuid].remote_tid;
				thread_data[oldcpuid].remote_tid = wtid;
			}

			do_syscall_return(fd, cpu, thread_data[newcpuid].remote_tid, 0, 0, 0, 0);
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
						write(pipefds[1], &pid, sizeof pid);
						exit(0);
					}
				}
				else if(pid != -1){
					int npid;
					int st;

					close(pipefds[1]);
					read(pipefds[0], &npid, sizeof npid);
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
				int i;
				int ret = 1;
				struct newprocess_desc npdesc;

				ischild = 1;
				/* Reopen device fd */
				close(fd);
				fd = open(dev, O_RDWR);
				if (fd < 0) {
					fs->status = -errno;
					fprintf(stderr, "ERROR: opening %s\n", dev);
					
					goto fork_child_sync_pipe;
				}

				/* Reinit signals and syscall threads */
				init_sigaction();
				init_worker_threads(fd);

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
				for (i = 0; i <= ncpu; ++i) {
					pthread_join(thread_data[i].thread_id, NULL);
				}

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
			for(fp = fork_sync_top, fb = NULL; fp; fb = fp, fp = fp->next)
				if(fp == fsc)
					break;
			if(fp){
				if(fb)
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
			while((ret = waitid(P_PID, pid, &info, opt)) == -1 &&
			      errno == EINTR);
			if(ret == 0){
				ret = info.si_pid;
			}

			if(ret != pid) {
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
					
					if ((ret = lookup_exec_path(filename, path, sizeof(path))) 
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
									sizeof(shell_path))) != 0) {
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

					transfer_image(fd, desc);	
					__dprintf("%s", "execve(): image transferred\n");

					if (close_cloexec_fds(fd) < 0) {
						ret = EINVAL;
						goto return_execve2;
					}

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

		case __NR_signalfd4:
			ret = act_signalfd4(&w);
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

		case __NR_close:
			if(w.sr.args[0] == fd)
				ret = -EBADF;
			else
				ret = do_generic_syscall(&w);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <asm/unistd.h>
#include "../include/uprotocol.h"
#include <sched.h>

#include <termios.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <signal.h>

#define DEBUG

#ifndef DEBUG
#define __dprint(msg, ...)
#define __dprintf(arg, ...)
#define __eprint(msg, ...)
#define __eprinf(format, ...)
#else
#define __dprint(msg, ...)  printf("%s: " msg, __FUNCTION__)
#define __dprintf(format, ...)  printf("%s: " format, __FUNCTION__, \
                                       __VA_ARGS__)
#define __eprint(msg, ...)  fprintf(stderr, "%s: " msg, __FUNCTION__)
#define __eprintf(format, ...)  fprintf(stderr, "%s: " format, __FUNCTION__, \
                                        __VA_ARGS__)
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

struct program_load_desc *load_elf(FILE *fp)
{
	Elf64_Ehdr hdr;
	Elf64_Phdr phdr;
	int i, j, nhdrs = 0;
	struct program_load_desc *desc;
	unsigned long load_addr = 0;
	int load_addr_set = 0;

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
	for (i = 0; i < hdr.e_phnum; i++) {
		if (fread(&phdr, sizeof(phdr), 1, fp) < 1) {
			__eprintf("Loading phdr failed (%d)\n", i);
			return NULL;
		}
		if (phdr.p_type == PT_LOAD) {
			desc->sections[j].vaddr = phdr.p_vaddr;
			desc->sections[j].filesz = phdr.p_filesz;
			desc->sections[j].offset = phdr.p_offset;
			desc->sections[j].len = phdr.p_memsz;

			__dprintf("%d: (%s) %lx, %lx, %lx, %lx\n",
			          j, (phdr.p_type == PT_LOAD ? "PT_LOAD" : "PT_TLS"), 
					  desc->sections[j].vaddr,
			          desc->sections[j].filesz,
			          desc->sections[j].offset,
			          desc->sections[j].len);
			j++;

			if (!load_addr_set) {
				load_addr_set = 1;
				load_addr = phdr.p_vaddr - phdr.p_offset;
			}
		}
	}
	desc->pid = getpid();
	desc->entry = hdr.e_entry;

	desc->at_phdr = load_addr + hdr.e_phoff;
	desc->at_phent = sizeof(phdr);
	desc->at_phnum = hdr.e_phnum;

	return desc;
}

unsigned char *dma_buf;


#define PAGE_SIZE 4096
#define PAGE_MASK ~((unsigned long)PAGE_SIZE - 1)

void transfer_image(FILE *fp, int fd, struct program_load_desc *desc)
{
	struct program_transfer pt;
	unsigned long s, e, flen, rpa;
	int i, l, lr;

	for (i = 0; i < desc->num_sections; i++) {
		s = (desc->sections[i].vaddr) & PAGE_MASK;
		e = (desc->sections[i].vaddr + desc->sections[i].len
		     + PAGE_SIZE - 1) & PAGE_MASK;
		rpa = desc->sections[i].remote_pa;

		fseek(fp, desc->sections[i].offset, SEEK_SET);
		flen = desc->sections[i].filesz;

		__dprintf("seeked to %lx | size %ld\n",
		          desc->sections[i].offset, flen);

		while (s < e) {
			pt.dest = rpa;
			pt.src = dma_buf;
			pt.sz = PAGE_SIZE;
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

			if (ioctl(fd, MCEXEC_UP_LOAD_IMAGE,
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

#define PIN_SHIFT  28
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

#define NUM_HANDLER_THREADS	64

struct thread_data_s {
	pthread_t thread_id;
	int fd;
	int cpu;
	int ret;
	pthread_mutex_t *lock;
} thread_data[NUM_HANDLER_THREADS];

static void *main_loop_thread_func(void *arg)
{
	struct thread_data_s *td = (struct thread_data_s *)arg;
	
	td->ret = main_loop(td->fd, td->cpu, td->lock);
	return NULL;
}

int main(int argc, char **argv)
{
	int fd;
#if 0	
	int fdm;
	long r;
#endif
	FILE *fp;
	struct program_load_desc *desc;
	char *envs;
	char *args;
	int i;
	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s (program) [args...]\n",
		        argv[0]);
		return 1;
	}
	
	fp = fopen(argv[1], "rb");
	if (!fp) {
		fprintf(stderr, "Error: Failed to open %s\n", argv[1]);
		return 1;
	}
	desc = load_elf(fp);
	if (!desc) {
		fclose(fp);
		fprintf(stderr, "Error: Failed to parse ELF!\n");
		return 1;
	}

	__dprintf("# of sections: %d\n", desc->num_sections);
	
	desc->envs_len = flatten_strings(-1, environ, &envs);
	desc->envs = envs;
	//print_flat(envs);

	desc->args_len = flatten_strings(-1, argv + 1, &args);
	desc->args = args;
	//print_flat(args);

	fd = open("/dev/mcos0", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Error: Failed to open /dev/mcctrl.\n");
		return 1;
	}

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
	if (!dma_buf) {
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
	transfer_image(fp, fd, desc);
	fflush(stdout);
	fflush(stderr);
	
	for (i = 0; i < NUM_HANDLER_THREADS; ++i) {
		int ret;

		thread_data[i].fd = fd;
		thread_data[i].cpu = i;
		thread_data[i].lock = &lock;
		ret = pthread_create(&thread_data[i].thread_id, NULL, 
		                     &main_loop_thread_func, &thread_data[i]);

		if (ret < 0) {
			printf("ERROR: creating syscall threads\n");
			exit(1);
		}
	}

	if (ioctl(fd, MCEXEC_UP_START_IMAGE, (unsigned long)desc) != 0) {
		perror("exec");
		close(fd);
		return 1;
	}

	for (i = 0; i < NUM_HANDLER_THREADS; ++i) {
		int ret;
		ret = pthread_join(thread_data[i].thread_id, NULL);
	}

	return 0;
}


void do_syscall_return(int fd, int cpu,
                       int ret, int n, unsigned long src, unsigned long dest,
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

#define SET_ERR(ret) if (ret == -1) ret = -errno

int main_loop(int fd, int cpu, pthread_mutex_t *lock)
{
	struct syscall_wait_desc w;
	int ret;
	
	w.cpu = cpu;

	while (ioctl(fd, MCEXEC_UP_WAIT_SYSCALL, (unsigned long)&w) == 0) {

		/* Don't print when got a msg to stdout */
		if (!(w.sr.number == __NR_write && w.sr.args[0] == 1))
			__dprintf("[%d] got syscall: %ld\n", cpu, w.sr.number);
		
		pthread_mutex_lock(lock);

		switch (w.sr.number) {
		case __NR_open:
			dma_buf[256] = 0;
			
			do_syscall_load(fd, cpu, (unsigned long)dma_buf, w.sr.args[0], 256);
			/*
			while (!dma_buf[256]) {
				asm volatile ("" : : : "memory");
			}
			*/
			
			printf("open: %s\n", dma_buf);

			ret = open((char *)dma_buf, w.sr.args[1], w.sr.args[2]);
			SET_ERR(ret);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_close:
			__dprintf("mcexec.c,close,fd=%lx\n", w.sr.args[0]);
			ret = close(w.sr.args[0]);
			SET_ERR(ret);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_read:
			ret = read(w.sr.args[0], dma_buf, w.sr.args[2]);
			SET_ERR(ret);
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf,
			                  w.sr.args[1], w.sr.args[2]);
			break;

		case __NR_write:
			dma_buf[w.sr.args[2]] = 0;
			SET_ERR(ret);
			do_syscall_load(fd, cpu, (unsigned long)dma_buf,
			                w.sr.args[1], w.sr.args[2]);

			/*
			while (!dma_buf[w.sr.args[2]]) {
				asm volatile ("" : : : "memory");
			}
			*/

			ret = write(w.sr.args[0], dma_buf, w.sr.args[2]);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_lseek:
			ret = lseek64(w.sr.args[0], w.sr.args[1], w.sr.args[2]);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_pread64:
			ret = pread(w.sr.args[0], dma_buf, w.sr.args[2],
			            w.sr.args[3]);
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf,
			                  w.sr.args[1], w.sr.args[2]);
			break;

		case __NR_pwrite64:
			dma_buf[w.sr.args[2]] = 0;
			do_syscall_load(fd, cpu, (unsigned long)dma_buf,
			                w.sr.args[1], w.sr.args[2]);

			/*
			while (!dma_buf[w.sr.args[2]]) {
				asm volatile ("" : : : "memory");
			}
			*/

			ret = pwrite(w.sr.args[0], dma_buf, w.sr.args[2],
			             w.sr.args[3]);
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;


		case __NR_stat:
			{
			char filename[256];
			
			do_syscall_load(fd, cpu, (unsigned long)&filename[0],
					        w.sr.args[0], 256);
			
			ret = stat(filename, (void *)dma_buf);
			if (ret == -1) {
				ret = -errno;
			}

			do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf,
			                  w.sr.args[1], sizeof(struct stat));
			break;
			}
		case __NR_fstat:
			ret = fstat(w.sr.args[0], (void *)dma_buf);
            __dprintf("mcexec.c:main_loop,arg[0]=%ld,ret=%d\n", w.sr.args[0], ret);
			if (ret == -1) {
				ret = -errno;
			}
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf,
			                  w.sr.args[1], sizeof(struct stat));
			break;

		case __NR_ioctl:
			if (w.sr.args[1] == TCGETS) {
				ret = ioctl(w.sr.args[0], w.sr.args[1],
				            (unsigned long)dma_buf);
				if (ret == -1) {
					ret = -errno;
				}
				do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf,
				                  w.sr.args[2],
				                  sizeof(struct kernel_termios)
					);
			}
			break;
		
            /*
              glibc-2.14.90/sysdeps/unix/sysv/linux/x86_64/time.S
             linux-2.6.34.13/arch/x86/kernel/vsyscall_64.c
             /usr/include/time.h
               /usr/include/bits/types.h
                 /usr/include/bits/typesizes.h
                   #define __TIME_T_TYPE           __SLONGWORD_TYPE
            */
		case __NR_time: {
            time_t ret;
            if(w.sr.args[0]) {
                ret = time((time_t *)dma_buf);
            } else {
                ret = time(NULL);
            }
			SET_ERR(ret);
            __dprintf("time=%ld\n", ret);
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf,
			                  w.sr.args[0], sizeof(time_t));
			break; }

		case __NR_gettimeofday:
			ret = gettimeofday((struct timeval *)dma_buf, NULL);
			SET_ERR(ret);
            __dprintf("gettimeofday=%016ld,%09ld\n", ((struct timeval *)dma_buf)->tv_sec, ((struct timeval *)dma_buf)->tv_usec);
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf,
			                  w.sr.args[0], sizeof(struct timeval));
			break;


		case __NR_getgid:
		case __NR_getuid:
		case __NR_geteuid:
		case __NR_getegid:
		case __NR_getppid:
		case __NR_getpgrp:
			ret = syscall(w.sr.number);
			if (ret == -1) {
				ret = -errno;
			}
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
			break;

		case __NR_clone:

			__dprintf("MIC clone(), new thread's cpu_id: %ld\n", w.sr.args[0]);


			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);
			break;
			

		case __NR_exit:
		case __NR_exit_group:
			do_syscall_return(fd, cpu, 0, 0, 0, 0, 0);
		
			exit(0);

			pthread_mutex_unlock(lock);
			return w.sr.args[0];

		case __NR_uname:
			ret = uname((void *)dma_buf);
			if (ret == -1) {
				ret = -errno;
			}
			do_syscall_return(fd,
			                  cpu, ret, 1, (unsigned long)dma_buf, w.sr.args[0],
			                  sizeof(struct utsname));
			break;

		case __NR_getcwd: {
            // note that return type is different between glibc-getcwd and sys_getcwd
			char* c = getcwd((void *)dma_buf, w.sr.args[1]); 
            ret = (c == 0) ? -errno : strnlen((const char*)dma_buf, w.sr.args[1]);
            __dprintf("getcwd result: %s\n", dma_buf);
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf, w.sr.args[0], c == 0 ? 0 : ret + 1);
            break; }

            // see linux-2.6.34.13/fs/open.c
		case __NR_access: {
			dma_buf[256] = 0;
			do_syscall_load(fd, cpu, (unsigned long)dma_buf, w.sr.args[0], 256);
			__dprintf("access: %s\n", dma_buf);
			int c = access((void *)dma_buf, w.sr.args[1]);
            ret = (c < 0) ? -errno : c;
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
            break; }

		case __NR_fcntl: {
            int c;
            switch(w.sr.args[1]) {
            case F_GETFD:
                c = fcntl(w.sr.args[0], w.sr.args[1]);
                __dprintf("fcntl,F_GETFD,c=%x\n", c);
                ret = (c < 0) ? -errno : c;
                break;
            default:
                ret = -EINVAL; 
                break;
            }
			do_syscall_return(fd, cpu, ret, 0, 0, 0, 0);
            break; }

		case __NR_getdents64: { // linux-2.6.34.13/fs/readdir.c
			long c = syscall((int)__NR_getdents64, (unsigned int)w.sr.args[0], (void *)dma_buf, (unsigned int)w.sr.args[2]);
            ret = (c < 0) ? -errno : c;
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf, w.sr.args[1], c < 0 ? 0 : c);
            break; }

		case __NR_readlink: {
			dma_buf[256] = 0;
			do_syscall_load(fd, cpu, (unsigned long)dma_buf, w.sr.args[0], 256);
			__dprintf("readlink: %s\n", dma_buf);
            char* dup = strndup((char *)dma_buf, 256);
			int c = readlink(dup, (void *)dma_buf, w.sr.args[2]);
            free(dup);
            ret = (c < 0) ? -errno : c;
            if(c > 0) {
                dup = strndup((char *)dma_buf, c); // readlink does not append NULL at the end
                //                printf("readlink result:c=%d,s=%s\n", c, dup);
                free(dup);
            } else {
                //                printf("readlink result: c=%d,s=<NULL>\n", c);
            }
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf, w.sr.args[1], c < 0 ? 0 : c);
            break; }

		case __NR_mmap: {
            // w.sr.args[0] is converted to MIC physical address
            __dprintf("mcexec.c,mmap,MIC-paddr=%lx,len=%lx,prot=%lx,flags=%lx,fd=%lx,offset=%lx\n",
                   w.sr.args[0], w.sr.args[1], w.sr.args[2], w.sr.args[3], w.sr.args[4], w.sr.args[5]);
            off_t old_off = lseek(w.sr.args[4], 0, SEEK_CUR);
            if(old_off == -1) { __dprint("mcexec.c,mmap,lseek failed\n"); ret = -errno; goto mmap_out; }
            off_t rlseek = lseek(w.sr.args[4], w.sr.args[5], SEEK_SET);
            if(rlseek == -1) { __dprint("mcexec.c,mmap,lseek failed\n"); ret = -errno; goto mmap_out; }
            ssize_t toread = w.sr.args[1];
            ret = 0;
            while(toread > 0) {
                __dprintf("mcexec.c,mmap,read,addr=%lx,len=%lx\n", (long int)((void *)dma_buf + w.sr.args[1] - toread), toread);
                ssize_t rread = read(w.sr.args[4], (void *)dma_buf + w.sr.args[1] - toread, toread);
                if(rread == 0) {
                    __dprint("mcexec.c,mmap,read==0\n");
                    goto mmap_zero_out;
                } else if(rread < 0) {
                    __dprint("mcexec.c,mmap,read failed\n"); ret = -errno; break;
                }
                toread -= rread;
            }
            mmap_zero_out:
            rlseek = lseek(w.sr.args[4], old_off, SEEK_SET);
            if(rlseek == -1) { __dprint("mcexec.c,mmap,lseek failed\n"); ret = -errno; }
            mmap_out:
			do_syscall_return(fd, cpu, ret, 1, (unsigned long)dma_buf, w.sr.args[0], w.sr.args[1]);
            break; }
		default:
			__dprintf("Unhandled system calls: %ld\n", w.sr.number);
			break;

		}
		
		pthread_mutex_unlock(lock);
	}
	__dprint("timed out.\n");
	return 1;
}

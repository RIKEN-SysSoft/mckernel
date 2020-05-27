/**
 * \file syscall.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Structures and macros for system call on McKernel
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */
/* syscall.h COPYRIGHT FUJITSU LIMITED 2015-2018 */

#ifndef __HEADER_SYSCALL_H
#define __HEADER_SYSCALL_H

#include <ihk/atomic.h>
#include <ihk/context.h>
#include <ihk/memconst.h>
#include <ihk/ikc.h>
#include <rlimit.h>
#include <time.h>

#define NUM_SYSCALLS 255

#define REQUEST_PAGE_COUNT              16
#define RESPONSE_PAGE_COUNT             16
#define DOORBELL_PAGE_COUNT             1

#define SCD_MSG_PREPARE_PROCESS         0x1
#define SCD_MSG_PREPARE_PROCESS_ACKED   0x2
#define SCD_MSG_SCHEDULE_PROCESS        0x3
#define SCD_MSG_WAKE_UP_SYSCALL_THREAD  0x14

#define SCD_MSG_INIT_CHANNEL            0x5
#define SCD_MSG_INIT_CHANNEL_ACKED      0x6

#define SCD_MSG_SYSCALL_ONESIDE         0x4
#define SCD_MSG_SEND_SIGNAL             0x7
#define SCD_MSG_SEND_SIGNAL_ACK         0x8
#define SCD_MSG_CLEANUP_PROCESS         0x9
#define SCD_MSG_GET_VDSO_INFO           0xa

#define SCD_MSG_GET_CPU_MAPPING         0xc
#define SCD_MSG_REPLY_GET_CPU_MAPPING   0xd

#define	SCD_MSG_PROCFS_CREATE		0x10
#define	SCD_MSG_PROCFS_DELETE		0x11
#define	SCD_MSG_PROCFS_REQUEST		0x12
#define	SCD_MSG_PROCFS_ANSWER		0x13
#define	SCD_MSG_PROCFS_RELEASE		0x15

#define SCD_MSG_REMOTE_PAGE_FAULT	0x18
#define SCD_MSG_REMOTE_PAGE_FAULT_ANSWER 0x19

#define	SCD_MSG_DEBUG_LOG		0x20

#define SCD_MSG_SYSFS_REQ_CREATE        0x30
/* #define SCD_MSG_SYSFS_RESP_CREATE    0x31 */
#define SCD_MSG_SYSFS_REQ_MKDIR         0x32
/* #define SCD_MSG_SYSFS_RESP_MKDIR     0x33 */
#define SCD_MSG_SYSFS_REQ_SYMLINK       0x34
/* #define SCD_MSG_SYSFS_RESP_SYMLINK   0x35 */
#define SCD_MSG_SYSFS_REQ_LOOKUP        0x36
/* #define SCD_MSG_SYSFS_RESP_LOOKUP    0x37 */
#define SCD_MSG_SYSFS_REQ_UNLINK        0x38
/* #define SCD_MSG_SYSFS_RESP_UNLINK    0x39 */
#define SCD_MSG_SYSFS_REQ_SHOW          0x3a
#define SCD_MSG_SYSFS_RESP_SHOW         0x3b
#define SCD_MSG_SYSFS_REQ_STORE         0x3c
#define SCD_MSG_SYSFS_RESP_STORE        0x3d
#define SCD_MSG_SYSFS_REQ_RELEASE       0x3e
#define SCD_MSG_SYSFS_RESP_RELEASE      0x3f
#define SCD_MSG_SYSFS_REQ_SETUP         0x40
#define SCD_MSG_SYSFS_RESP_SETUP        0x41
/* #define SCD_MSG_SYSFS_REQ_CLEANUP    0x42 */
/* #define SCD_MSG_SYSFS_RESP_CLEANUP   0x43 */
#define SCD_MSG_PROCFS_TID_CREATE	0x44
#define SCD_MSG_PROCFS_TID_DELETE	0x45
#define SCD_MSG_EVENTFD			0x46

#define SCD_MSG_PERF_CTRL               0x50
#define SCD_MSG_PERF_ACK                0x51

#define SCD_MSG_CPU_RW_REG              0x52
#define SCD_MSG_CPU_RW_REG_RESP         0x53

#define SCD_MSG_FUTEX_WAKE              0x60

/* For prctl() */
#define PR_SET_THP_DISABLE 41
#define PR_GET_THP_DISABLE 42

/* Cloning flags.  */
# define CSIGNAL       0x000000ff /* Signal mask to be sent at exit.  */
# define CLONE_VM      0x00000100 /* Set if VM shared between processes.  */
# define CLONE_FS      0x00000200 /* Set if fs info shared between processes.  */
# define CLONE_FILES   0x00000400 /* Set if open files shared between processes.  */
# define CLONE_SIGHAND 0x00000800 /* Set if signal handlers shared.  */
# define CLONE_PTRACE  0x00002000 /* Set if tracing continues on the child.  */
# define CLONE_VFORK   0x00004000 /* Set if the parent wants the child to
				     wake it up on mm_release.  */
# define CLONE_PARENT  0x00008000 /* Set if we want to have the same
				     parent as the cloner.  */
# define CLONE_THREAD  0x00010000 /* Set to add to same thread group.  */
# define CLONE_NEWNS   0x00020000 /* Set to create new namespace.  */
# define CLONE_SYSVSEM 0x00040000 /* Set to shared SVID SEM_UNDO semantics.  */
# define CLONE_SETTLS  0x00080000 /* Set TLS info.  */
# define CLONE_PARENT_SETTID 0x00100000 /* Store TID in userlevel buffer
					   before MM copy.  */
# define CLONE_CHILD_CLEARTID 0x00200000 /* Register exit futex and memory
					    location to clear.  */
# define CLONE_DETACHED 0x00400000 /* Create clone detached.  */
# define CLONE_UNTRACED 0x00800000 /* Set if the tracing process can't
				      force CLONE_PTRACE on this clone.  */
# define CLONE_CHILD_SETTID 0x01000000 /* Store TID in userlevel buffer in
					  the child.  */
# define CLONE_NEWUTS	0x04000000	/* New utsname group.  */
# define CLONE_NEWIPC	0x08000000	/* New ipcs.  */
# define CLONE_NEWUSER	0x10000000	/* New user namespace.  */
# define CLONE_NEWPID	0x20000000	/* New pid namespace.  */
# define CLONE_NEWNET	0x40000000	/* New network namespace.  */
# define CLONE_IO	0x80000000	/* Clone I/O context.  */

/* for execveat() */
#define AT_FDCWD	-100
#define AT_SYMLINK_NOFOLLOW	0x100
#define AT_EMPTY_PATH	0x1000

struct user_desc {
	unsigned int  entry_number;
	unsigned int  base_addr;
	unsigned int  limit;
	unsigned int  seg_32bit:1;
	unsigned int  contents:2;
	unsigned int  read_exec_only:1;
	unsigned int  limit_in_pages:1;
	unsigned int  seg_not_present:1;
	unsigned int  useable:1;
	unsigned int  lm:1;
};

struct program_image_section {
	unsigned long vaddr;
	unsigned long len;
	unsigned long remote_pa;
	unsigned long filesz, offset;
	int prot;
	unsigned char interp;
	unsigned char padding[3];
	void *fp;
};

#define SHELL_PATH_MAX_LEN	1024
#define MCK_RLIM_MAX	20

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

#define PLD_CPU_SET_MAX_CPUS 1024
typedef unsigned long __cpu_set_unit;
#define PLD_CPU_SET_SIZE (PLD_CPU_SET_MAX_CPUS / (8 * sizeof(__cpu_set_unit)))

#define MPOL_NO_HEAP              0x01
#define MPOL_NO_STACK             0x02
#define MPOL_NO_BSS               0x04
#define MPOL_SHM_PREMAP           0x08

#define PLD_MAGIC 0xcafecafe44332211UL

struct program_load_desc {
	unsigned long magic;
	int num_sections;
	int cpu;
	int pid;
	int stack_prot;
	int pgid;
	int cred[8];
	int reloc;
	char enable_vdso;
	char padding[7];
	unsigned long entry;
	unsigned long user_start;
	unsigned long user_end;
	unsigned long rprocess;
	unsigned long rpgtable;
	unsigned long at_phdr;
	unsigned long at_phent;
	unsigned long at_phnum;
	unsigned long at_entry;
	unsigned long at_clktck;
	char *args;
	unsigned long args_len;
	char *envs;
	unsigned long envs_len;
	struct rlimit rlimit[MCK_RLIM_MAX];
	unsigned long interp_align;
	unsigned long mpol_flags;
	unsigned long mpol_threshold;
	unsigned long heap_extension;
	long stack_premap;
	unsigned long mpol_bind_mask;
	int thp_disable;
	int uti_thread_rank; /* N-th clone() spawns a thread on Linux CPU */
	int uti_use_last_cpu; /* Work-around not to share CPU with OpenMP thread */
	int straight_map;
	size_t straight_map_threshold;
	int nr_processes;
	int process_rank;
	__cpu_set_unit cpu_set[PLD_CPU_SET_SIZE];
	int profile;
	struct program_image_section sections[0];
};

struct ikc_scd_init_param {
	unsigned long request_page;
	unsigned long response_page;
	unsigned long doorbell_page;
	unsigned long post_page;
};

struct syscall_request {
	/* TID of requesting thread */
	int rtid;
	/*
	 * TID of target thread. Remote page fault response needs to designate the
	 * thread that must serve the request, 0 indicates any thread from the pool
	 */
	int ttid;
	unsigned long valid;
	unsigned long number;
	unsigned long args[6];
};

struct ihk_os_cpu_register {
	unsigned long addr;
	unsigned long val;
	unsigned long addr_ext;
	int sync; /* atomic_t in Linux counterpart */
};

enum mcctrl_os_cpu_operation {
	MCCTRL_OS_CPU_READ_REGISTER,
	MCCTRL_OS_CPU_WRITE_REGISTER,
	MCCTRL_OS_CPU_MAX_OP
};

struct ikc_scd_packet {
	struct ihk_ikc_packet_header header;
	int msg;
	int err;
	void *reply;
	union {
		/* for traditional SCD_MSG_* */
		struct {
			int ref;
			int osnum;
			int pid;
			unsigned long arg;
			struct syscall_request req;
			unsigned long resp_pa;
		};

		/* for SCD_MSG_SYSFS_* */
		struct {
			long sysfs_arg1;
			long sysfs_arg2;
			long sysfs_arg3;
		};

		/* SCD_MSG_WAKE_UP_SYSCALL_THREAD */
		struct {
			int ttid;
		};

		/* SCD_MSG_CPU_RW_REG */
		struct {
			unsigned long pdesc; /* Physical addr of the descriptor */
			enum mcctrl_os_cpu_operation op;
			void *resp;
		};

		/* SCD_MSG_EVENTFD */
		struct {
			int eventfd_type;
		};

		/* SCD_MSG_FUTEX_WAKE */
		struct {
			void *resp;
			int *spin_sleep; /* 1: waiting in linux_wait_event() 0: woken up by someone else */
		} futex;

		/* SCD_MSG_REMOTE_PAGE_FAULT */
		struct {
			int target_cpu;
			int fault_tid;
			unsigned long fault_address;
			unsigned long fault_reason;
		};
	};
	/* char padding[8]; */ /* We want the size to be 128 bytes */
};

#define IHK_SCD_REQ_THREAD_SPINNING         0
#define IHK_SCD_REQ_THREAD_TO_BE_WOKEN      1
#define IHK_SCD_REQ_THREAD_DESCHEDULED      2

struct syscall_response {
	/* TID of the thread that requested the service */
	int ttid;
	/* TID of the mcexec thread that is serving the request */
	int stid;
	unsigned long status;
	unsigned long req_thread_status;
	long ret;
	unsigned long fault_address;
};

struct syscall_post {
	unsigned long v[8];
};

#define SYSCALL_DECLARE(name) long sys_##name(int n, ihk_mc_user_context_t *ctx)
#define SYSCALL_HEADER struct syscall_request request IHK_DMA_ALIGN; \
	request.number = n
#define SYSCALL_ARG_D(n)    request.args[n] = ihk_mc_syscall_arg##n(ctx)
#define SYSCALL_ARG_MO(n) \
	do { \
	unsigned long __phys; \
	if (ihk_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, \
	                           (void *)ihk_mc_syscall_arg##n(ctx),\
	                           &__phys)) { \
		return -EFAULT; \
	}\
	request.args[n] = __phys; \
	} while(0)
#define SYSCALL_ARG_MI(n) \
	do { \
	unsigned long __phys; \
	if (ihk_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, \
	                           (void *)ihk_mc_syscall_arg##n(ctx),\
	                           &__phys)) { \
		return -EFAULT; \
	}\
	request.args[n] = __phys; \
	} while(0)


#define SYSCALL_ARGS_1(a0)          SYSCALL_ARG_##a0(0)
#define SYSCALL_ARGS_2(a0, a1)      SYSCALL_ARG_##a0(0); SYSCALL_ARG_##a1(1)
#define SYSCALL_ARGS_3(a0, a1, a2)  SYSCALL_ARG_##a0(0); SYSCALL_ARG_##a1(1); \
	                            SYSCALL_ARG_##a2(2)
#define SYSCALL_ARGS_4(a0, a1, a2, a3) \
	SYSCALL_ARG_##a0(0); SYSCALL_ARG_##a1(1); \
	SYSCALL_ARG_##a2(2); SYSCALL_ARG_##a3(3)
#define SYSCALL_ARGS_6(a0, a1, a2, a3, a4, a5) \
	SYSCALL_ARG_##a0(0); SYSCALL_ARG_##a1(1); \
	SYSCALL_ARG_##a2(2); SYSCALL_ARG_##a3(3); \
	SYSCALL_ARG_##a4(4); SYSCALL_ARG_##a5(5);

#define SYSCALL_FOOTER return do_syscall(&request, ihk_mc_get_processor_id())

extern long do_syscall(struct syscall_request *req, int cpu);
int obtain_clone_cpuid(cpu_set_t *cpu_set, int use_last);
extern long syscall_generic_forwarding(int n, ihk_mc_user_context_t *ctx);

#define DECLARATOR(number,name)		__NR_##name = number,
#define	SYSCALL_HANDLED(number,name)	DECLARATOR(number,name)
#define	SYSCALL_DELEGATED(number,name)	DECLARATOR(number,name)
enum {
#include <syscall_list.h>
};
#undef	DECLARATOR
#undef	SYSCALL_HANDLED
#undef	SYSCALL_DELEGATED

#define	__NR_coredump 999	/* pseudo syscall for coredump */
struct coretable {		/* table entry for a core chunk */
	off_t len;		/* length of the chunk */
	unsigned long addr;	/* physical addr of the chunk */
};

void create_proc_procfs_files(int pid, int cpuid);
void delete_proc_procfs_files(int pid);
void create_os_procfs_files(void);
void delete_os_procfs_files(void);

#define PROCFS_NAME_MAX 768

struct procfs_read {
	unsigned long pbuf;	/* physical address of the host buffer (request) */
	unsigned long offset;	/* offset to read (request) */
	int count;		/* bytes to read (request) */
	int eof;		/* if eof is detected, 1 otherwise 0. (answer)*/
	int ret;		/* read bytes (answer) */
	int newcpu;		/* migrated new cpu (answer) */
	int readwrite;		/* 0:read, 1:write */
	char fname[PROCFS_NAME_MAX];	/* procfs filename (request) */
};

struct procfs_file {
	int status;			/* status of processing (answer) */
	int mode;			/* file mode (request) */
	char fname[PROCFS_NAME_MAX];	/* procfs filename (request) */
};

int process_procfs_request(struct ikc_scd_packet *rpacket);
void send_procfs_answer(struct ikc_scd_packet *packet, int err);

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN -1
#define RUSAGE_THREAD 1

struct rusage {
	struct timeval ru_utime;
	struct timeval ru_stime;
	long   ru_maxrss;
	long   ru_ixrss;
	long   ru_idrss;
	long   ru_isrss;
	long   ru_minflt;
	long   ru_majflt;
	long   ru_nswap;
	long   ru_inblock;
	long   ru_oublock;
	long   ru_msgsnd;
	long   ru_msgrcv;
	long   ru_nsignals;
	long   ru_nvcsw;
	long   ru_nivcsw;
};

extern void terminate(int, int);

struct tod_data_s {
	int8_t do_local;
	int8_t padding[7];
	ihk_atomic64_t version;
	unsigned long clocks_per_sec;
	struct timespec origin;		/* realtime when tsc=0 */
};
extern struct tod_data_s tod_data;	/* residing in arch-dependent file */

static inline void tsc_to_ts(unsigned long tsc, struct timespec *ts)
{
	time_t sec_delta;
	long ns_delta;

	sec_delta = tsc / tod_data.clocks_per_sec;
	ns_delta = NS_PER_SEC * (tsc % tod_data.clocks_per_sec)
	           / tod_data.clocks_per_sec;
	/* calc. of ns_delta overflows if clocks_per_sec exceeds 18.44 GHz */

	ts->tv_sec = sec_delta;
	ts->tv_nsec = ns_delta;
	if (ts->tv_nsec >= NS_PER_SEC) {
		ts->tv_nsec -= NS_PER_SEC;
		++ts->tv_sec;
	}
}

static inline unsigned long timeval_to_jiffy(const struct timeval *ats)
{
	return ats->tv_sec * 100 + ats->tv_usec / 10000;
}

static inline unsigned long timespec_to_jiffy(const struct timespec *ats)
{
	return ats->tv_sec * 100 + ats->tv_nsec / 10000000;
}

void reset_cputime(void);
enum set_cputime_mode {
	CPUTIME_MODE_K2U = 0,
	CPUTIME_MODE_U2K,
	CPUTIME_MODE_K2K_IN,
	CPUTIME_MODE_K2K_OUT,
};
void set_cputime(enum set_cputime_mode mode);
int do_munmap(void *addr, size_t len, int holding_memory_range_lock);
intptr_t do_mmap(uintptr_t addr0, size_t len0, int prot, int flags, int fd,
		off_t off0);
void clear_host_pte(uintptr_t addr, size_t len, int holding_memory_range_lock);
typedef int32_t key_t;
int do_shmget(key_t key, size_t size, int shmflg);
struct process_vm;
int arch_map_vdso(struct process_vm *vm);	/* arch dependent */
int arch_setup_vdso(void);
int arch_cpu_read_write_register(struct ihk_os_cpu_register *desc,
		enum mcctrl_os_cpu_operation op);
struct vm_range_numa_policy *vm_range_policy_search(struct process_vm *vm, uintptr_t addr);
void calculate_time_from_tsc(struct timespec *ts);
time_t time(void);
long do_futex(int n, unsigned long arg0, unsigned long arg1,
			  unsigned long arg2, unsigned long arg3,
			  unsigned long arg4, unsigned long arg5,
			  unsigned long _uti_clv,
			  void *uti_futex_resp,
			  void *_linux_wait_event,
			  void *_linux_printk,
			  void *_linux_clock_gettime);

struct cpu_mapping {
	int cpu_number;
	int hw_id;
};

struct get_cpu_mapping_req {
	int busy;		/* INOUT: */
	int error;		/* OUT: */
	long buf_rpa;		/* OUT: physical address of struct cpu_mapping */
	int buf_elems;		/* OUT: # of elements of buf */
	int padding;

	/* work for mcctrl */
#if 0
	wait_queue_head_t wq;
#endif
};

enum perf_ctrl_type {
	PERF_CTRL_SET,
	PERF_CTRL_GET,
	PERF_CTRL_ENABLE,
	PERF_CTRL_DISABLE,
};

struct perf_ctrl_desc {
	enum perf_ctrl_type ctrl_type;
	int err;
	union {
		/* for SET, GET */
		struct {
			unsigned int target_cntr;
			unsigned long config;
			unsigned long read_value;
			unsigned disabled        :1,
			         pinned          :1,
			         exclude_user    :1,
			         exclude_kernel  :1,
			         exclude_hv      :1,
			         exclude_idle    :1;
		};

		/* for START, STOP*/
		struct {
			unsigned long target_cntr_mask;
		};
	};
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

struct thread;
long arch_ptrace_syscall_event(struct thread *thread,
			       ihk_mc_user_context_t *ctx, long setret);

struct uti_ctx {
	union {
		char ctx[4096];
		struct {
			int uti_refill_tid;
		};
	};
}; 

struct move_pages_smp_req {
	unsigned long count;
	const void **user_virt_addr;
	int *user_status;
	const int *user_nodes;
	void **virt_addr;
	int *status;
	pte_t **ptep;
	int *nodes;
	int nodes_ready;
	int *nr_pages;
	unsigned long *dst_phys;
	struct process *proc;
	ihk_atomic_t phase_done;
	int phase_ret;
};

#define PROCESS_VM_READ		0
#define PROCESS_VM_WRITE	1

/* uti: function pointers pointing to Linux codes */
extern long (*linux_wait_event)(void *_resp, unsigned long nsec_timeout);
extern int (*linux_printk)(const char *fmt, ...);
extern int (*linux_clock_gettime)(clockid_t clk_id, struct timespec *tp);

/* coredump */
#define COREDUMP_RUNNING          0
#define COREDUMP_DESCHEDULED      1
#define COREDUMP_TO_BE_WOKEN      2

extern void terminate_host(int pid, struct thread *thread);
#endif

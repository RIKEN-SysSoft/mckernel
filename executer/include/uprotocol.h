/**
 * \file executer/include/uprotocol.h
 *  License details are found in the file LICENSE.
 * \brief
 *  define protocol
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
 *  2013/10/21 nakamura exclude interpreter's segment from data region
 *  2013/10/11 nakamura sys_getrlimit: modified to return mcexec's RLIMIT_STACK
 *  2013/10/11 nakamura mcexec: add a interpreter invocation
 *  2013/10/08 nakamura add a AT_ENTRY entry to the auxiliary vector
 *  2013/09/02 shirasawa add terminate thread
 *  2013/08/19 shirasawa mcexec forward signal to MIC process
 *  2013/08/07 nakamura add page fault forwarding
 *  2013/07/02 shirasawa add error handling for prepare_process
 *  2013/04/17 nakamura add generic system call forwarding
 */
#ifndef HEADER_UPROTOCOL_H
#define HEADER_UPROTOCOL_H

#define MCEXEC_UP_PREPARE_IMAGE  0x30a02900
#define MCEXEC_UP_TRANSFER       0x30a02901
#define MCEXEC_UP_START_IMAGE    0x30a02902
#define MCEXEC_UP_WAIT_SYSCALL   0x30a02903
#define MCEXEC_UP_RET_SYSCALL    0x30a02904
#define MCEXEC_UP_LOAD_SYSCALL   0x30a02905
#define MCEXEC_UP_SEND_SIGNAL    0x30a02906
#define MCEXEC_UP_GET_CPU        0x30a02907
#define MCEXEC_UP_STRNCPY_FROM_USER 0x30a02908
#define MCEXEC_UP_GET_CRED	 0x30a0290a
#define MCEXEC_UP_GET_CREDV	 0x30a0290b
#define MCEXEC_UP_GET_NODES  0x30a0290c
#define MCEXEC_UP_GET_CPUSET  0x30a0290d
#define MCEXEC_UP_CREATE_PPD  0x30a0290e

#define MCEXEC_UP_PREPARE_DMA    0x30a02910
#define MCEXEC_UP_FREE_DMA       0x30a02911

#define MCEXEC_UP_OPEN_EXEC      0x30a02912
#define MCEXEC_UP_CLOSE_EXEC     0x30a02913

#define MCEXEC_UP_SYS_MOUNT      0x30a02914
#define MCEXEC_UP_SYS_UMOUNT     0x30a02915
#define MCEXEC_UP_SYS_UNSHARE    0x30a02916

#define MCEXEC_UP_UTI_GET_CTX    0x30a02920
#define MCEXEC_UP_UTI_SWITCH_CTX 0x30a02921
#define MCEXEC_UP_SIG_THREAD     0x30a02922
#define MCEXEC_UP_SYSCALL_THREAD 0x30a02924
#define MCEXEC_UP_TERMINATE_THREAD 0x30a02925
#define MCEXEC_UP_GET_NUM_POOL_THREADS  0x30a02926
#define MCEXEC_UP_UTI_ATTR       0x30a02927
#define MCEXEC_UP_RELEASE_USER_SPACE 0x30a02928

#define MCEXEC_UP_DEBUG_LOG     0x40000000

#define MCEXEC_UP_TRANSFER_TO_REMOTE	0
#define MCEXEC_UP_TRANSFER_FROM_REMOTE	1

struct remote_transfer {
	unsigned long rphys;
	void *userp;
	unsigned long size;
	char direction;  
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

struct get_cpu_set_arg {
	int nr_processes;
	char *req_cpu_list;   // Requested by user-space
	int req_cpu_list_len; // Lenght of request string
	int *process_rank;
	void *cpu_set;
	size_t cpu_set_size;	// Size in bytes
	int *target_core;
	int *mcexec_linux_numa; // NUMA domain to bind mcexec to
	void *mcexec_cpu_set;
	size_t mcexec_cpu_set_size;	// Size in bytes
	int *ikc_mapped;
};

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
	int nr_processes;
	unsigned long exec_path_va;
	unsigned long interp_path_va;
	int process_rank;
	__cpu_set_unit cpu_set[PLD_CPU_SET_SIZE];
	int profile;
	struct program_image_section sections[0];
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

struct syscall_wait_desc {
	unsigned long cpu;
	struct syscall_request sr;
	int pid;
};

struct syscall_load_desc {
	unsigned long cpu;
	unsigned long src;
	unsigned long dest;
	unsigned long size;
};

#define IHK_SCD_REQ_THREAD_SPINNING         0
#define IHK_SCD_REQ_THREAD_TO_BE_WOKEN      1
#define IHK_SCD_REQ_THREAD_DESCHEDULED      2

struct syscall_response {
	/* TID of the thread that requested the service */
	int ttid;
	/* TID of the mcexec thread that is serving or has served the request */
	int stid;
	unsigned long status;
	unsigned long req_thread_status;
	long ret;
	unsigned long fault_address;
};

struct syscall_ret_desc {
	long cpu;
	long ret;
	unsigned long src;
	unsigned long dest;
	unsigned long size;
};

struct strncpy_from_user_desc {
	void *dest;
	void *src;
	unsigned long n;
	long result;
};

struct prepare_dma_desc {
	unsigned long size;
	unsigned long pa;
};

struct free_dma_desc {
	unsigned long pa;
	unsigned long size;
};

struct signal_desc {
	int cpu;
	int pid;
	int tid;
	int sig;
	char info[128];
};

struct sys_mount_desc {
	char *dev_name;
	char *dir_name;
	char *type;
	unsigned long flags;
	void *data;
};

struct sys_umount_desc {
	char *dir_name;
};

struct sys_unshare_desc {
	unsigned long unshare_flags;
};

struct release_user_space_desc {
	unsigned long user_start;
	unsigned long user_end;
};

struct terminate_thread_desc {
	int pid;
	int tid;

	long code; 
	/* 32------32  31--16  15--------8  7----0
       exit_group          exit-status  signal */

	unsigned long tsk; /* struct task_struct * */
};

struct rpgtable_desc {
	uintptr_t rpgtable;
	uintptr_t start;
	uintptr_t len;
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

#define UTI_FLAG_PREFER_LWK (1ULL << 14)
#define UTI_FLAG_PREFER_FWK (1ULL << 15)
#define UTI_FLAG_FABRIC_INTR_AFFINITY (1ULL << 16)

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

struct uti_attr_desc {
	unsigned long phys_attr;
	char *uti_cpu_set_str; /* UTI_CPU_SET environmental variable */
	size_t uti_cpu_set_len;
};

struct uti_ctx {
	union {
		char ctx[4096]; /* TODO: Get the size from config.h */
		struct {
			int uti_refill_tid;
		};
	};
}; 

struct uti_get_ctx_desc {
	unsigned long rp_rctx; /* Remote physical address of remote context */
	void *rctx; /* Remote context */
	void *lctx; /* Local context */
	int uti_refill_tid;
	unsigned long key; /* OUT: struct task_struct* of mcexec thread, used to search struct host_thread */
};

struct uti_switch_ctx_desc {
	void *rctx; /* Remote context */
	void *lctx; /* Local context */
};

#endif

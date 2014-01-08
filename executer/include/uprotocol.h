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
#define MCEXEC_UP_LOAD_IMAGE     0x30a02901
#define MCEXEC_UP_START_IMAGE    0x30a02902
#define MCEXEC_UP_WAIT_SYSCALL   0x30a02903
#define MCEXEC_UP_RET_SYSCALL    0x30a02904
#define MCEXEC_UP_LOAD_SYSCALL   0x30a02905
#define MCEXEC_UP_SEND_SIGNAL    0x30a02906
#define MCEXEC_UP_GET_CPU        0x30a02907
#define MCEXEC_UP_STRNCPY_FROM_USER 0x30a02908

#define MCEXEC_UP_PREPARE_DMA    0x30a02910
#define MCEXEC_UP_FREE_DMA       0x30a02911

struct program_transfer {
	unsigned long dest;
	void *src;
	unsigned long sz;
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

struct program_load_desc {
	int num_sections;
	int status;
	int cpu;
	int pid;
	int err;
	unsigned long entry;
	unsigned long user_start;
	unsigned long user_end;
	unsigned long rprocess;
	unsigned long rpgtable;
	unsigned long at_phdr;
	unsigned long at_phent;
	unsigned long at_phnum;
	unsigned long at_entry;
	char *args;
	unsigned long args_len;
	char *envs;
	unsigned long envs_len;
	unsigned long rlimit_stack_cur;
	unsigned long rlimit_stack_max;
	struct program_image_section sections[0];
};

struct syscall_request {
	unsigned long valid;
	unsigned long number;
	unsigned long args[6];
};

struct syscall_wait_desc {
	unsigned long cpu;
	struct syscall_request sr;
};

struct syscall_load_desc {
	unsigned long cpu;
	unsigned long src;
	unsigned long dest;
	unsigned long size;
};

struct syscall_response {
	unsigned long status;
	long ret;
	unsigned long fault_address;
	unsigned long fault_reason;
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

#endif

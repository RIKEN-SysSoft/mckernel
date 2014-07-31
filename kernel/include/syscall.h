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

#ifndef __HEADER_SYSCALL_H
#define __HEADER_SYSCALL_H

#include <ihk/context.h>
#include <ihk/memconst.h>

#define NUM_SYSCALLS 255

#define REQUEST_PAGE_COUNT              16
#define RESPONSE_PAGE_COUNT             16
#define DOORBELL_PAGE_COUNT             1
#define ARGENV_PAGE_COUNT               8
#define SCD_RESERVED_COUNT \
	(REQUEST_PAGE_COUNT + RESPONSE_PAGE_COUNT + DOORBELL_PAGE_COUNT + ARGENV_PAGE_COUNT)

#define SCD_MSG_PREPARE_PROCESS         0x1
#define SCD_MSG_PREPARE_PROCESS_ACKED   0x2
#define SCD_MSG_PREPARE_PROCESS_NACKED  0x7
#define SCD_MSG_SCHEDULE_PROCESS        0x3

#define SCD_MSG_INIT_CHANNEL            0x5
#define SCD_MSG_INIT_CHANNEL_ACKED      0x6

#define SCD_MSG_SYSCALL_ONESIDE         0x4
#define SCD_MSG_SEND_SIGNAL		0x8

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

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
struct ikc_scd_packet {
	int msg;
	int ref;
	int pid;
	int err;
	unsigned long arg;
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
	int stack_prot;
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
	unsigned long rlimit_stack_cur;
	unsigned long rlimit_stack_max;
	unsigned long interp_align;
	struct program_image_section sections[0];
};

struct ikc_scd_init_param {
	unsigned long request_page;
	unsigned long response_page;
	unsigned long doorbell_page;
	unsigned long post_page;
};

struct syscall_request {
	unsigned long valid;
	unsigned long number;
	unsigned long args[6];
};

struct syscall_response {
	unsigned long status;
	long ret;
	unsigned long fault_address;
	unsigned long fault_reason;
};

struct syscall_post {
	unsigned long v[8];
};

struct syscall_params {
	unsigned long request_rpa, request_pa;
	struct syscall_request *request_va;
	unsigned long response_pa;
	struct syscall_response *response_va;

	unsigned long doorbell_rpa, doorbell_pa;
	unsigned long *doorbell_va;

	unsigned int post_idx;
	unsigned long post_rpa, post_pa;
	struct syscall_post *post_va;
	unsigned long post_fin;
	struct syscall_post post_buf IHK_DMA_ALIGN;
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

#define SYSCALL_FOOTER return do_syscall(&request, ctx, ihk_mc_get_processor_id(), 0)

extern long do_syscall(struct syscall_request *req, ihk_mc_user_context_t *ctx, int cpu, int pid);
extern int obtain_clone_cpuid();
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
	int len;		/* length of the chunk */
	unsigned long addr;	/* physical addr of the chunk */
};

#endif

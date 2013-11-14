/**
 * \file mcctrl.h
 *  Licence details are found in the file LICENSE.
 * \brief
 *  define data structure
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
#ifndef HEADER_MCCTRL_H
#define HEADER_MCCTRL_H

#include <ihk/ihk_host_driver.h>
#include <uprotocol.h>
#include <linux/wait.h>
#include <ihk/ikc.h>
#include <ikc/master.h>

#define SCD_MSG_PREPARE_PROCESS         0x1
#define SCD_MSG_PREPARE_PROCESS_ACKED   0x2
#define SCD_MSG_PREPARE_PROCESS_NACKED  0x7
#define SCD_MSG_SCHEDULE_PROCESS        0x3

#define SCD_MSG_INIT_CHANNEL            0x5
#define SCD_MSG_INIT_CHANNEL_ACKED      0x6

#define SCD_MSG_SYSCALL_ONESIDE         0x4
#define SCD_MSG_SEND_SIGNAL     	0x8

#define DMA_PIN_SHIFT                   21

#define DO_USER_MODE

struct ikc_scd_packet {
	int msg;
	int ref;
	int err;
	unsigned long arg;
};

struct mcctrl_priv { 
	ihk_os_t os;
	struct program_load_desc *desc;
};

struct ikc_scd_init_param {
	unsigned long request_page;
	unsigned long response_page;
	unsigned long doorbell_page;
	unsigned long post_page;
};

struct syscall_post {
	unsigned long v[8];
};

struct syscall_params {
	unsigned long request_pa;
	struct syscall_request *request_va;
	unsigned long response_rpa, response_pa;
	struct syscall_response *response_va;
	unsigned long post_pa;
	struct syscall_post *post_va;
	
	unsigned long doorbell_pa;
	unsigned long *doorbell_va;
};

struct mcctrl_channel {
	struct ihk_ikc_channel_desc *c;
	struct syscall_params param;
	struct ikc_scd_init_param init;
	void *dma_buf;

	int req;
	wait_queue_head_t wq_syscall;
};

struct mcctrl_usrdata {
	struct ihk_ikc_listen_param listen_param;
	struct ihk_ikc_listen_param listen_param2;
	ihk_os_t	os;
	int	num_channels;
	struct mcctrl_channel	*channels;
	unsigned long	*mcctrl_doorbell_va;
	unsigned long	mcctrl_doorbell_pa;
	int	remaining_job;
	int	base_cpu;
	int	job_pos;
	int	mcctrl_dma_abort;
	unsigned long	last_thread_exec;
	wait_queue_head_t	wq_prepare;
	unsigned long	rpgtable;	/* per process, not per OS */
	void **keys;
};

int mcctrl_ikc_send(ihk_os_t os, int cpu, struct ikc_scd_packet *pisp);
int mcctrl_ikc_send_msg(ihk_os_t os, int cpu, int msg, int ref, unsigned long arg);
int mcctrl_ikc_is_valid_thread(ihk_os_t os, int cpu);
int reserve_user_space(struct mcctrl_usrdata *usrdata, unsigned long *startp,
		unsigned long *endp);

/* syscall.c */
int init_peer_channel_registry(struct mcctrl_usrdata *ud);
int register_peer_channel(struct mcctrl_usrdata *ud, void *key, struct mcctrl_channel *ch);
int deregister_peer_channel(struct mcctrl_usrdata *ud, void *key, struct mcctrl_channel *ch);
struct mcctrl_channel *get_peer_channel(struct mcctrl_usrdata *ud, void *key);
int __do_in_kernel_syscall(ihk_os_t os, struct mcctrl_channel *c, struct syscall_request *sc);

#endif

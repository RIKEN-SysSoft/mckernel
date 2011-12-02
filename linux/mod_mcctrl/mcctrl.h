#ifndef HEADER_MCCTRL_H
#define HEADER_MCCTRL_H

#include <aal/aal_host_driver.h>
#include <uprotocol.h>
#include <linux/wait.h>

#define SCD_MSG_PREPARE_PROCESS         0x1
#define SCD_MSG_PREPARE_PROCESS_ACKED   0x2
#define SCD_MSG_SCHEDULE_PROCESS        0x3

#define SCD_MSG_INIT_CHANNEL            0x5
#define SCD_MSG_INIT_CHANNEL_ACKED      0x6

#define SCD_MSG_SYSCALL_ONESIDE         0x4

#define DMA_PIN_SHIFT                   16

struct ikc_scd_packet {
	int msg;
	int ref;
	unsigned long arg;
};

struct mcctrl_priv { 
	aal_os_t os;
	struct program_load_desc *desc;
};

struct ikc_scd_init_param {
	unsigned long request_page;
	unsigned long response_page;
	unsigned long doorbell_page;
	unsigned long post_page;
};

struct syscall_post {
	unsigned long v[4];
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
	struct aal_ikc_channel_desc *c;
	struct syscall_params param;
	struct ikc_scd_init_param init;
	void *dma_buf;

	int req;
	wait_queue_head_t wq_syscall;
};

int mcctrl_ikc_send(int cpu, struct ikc_scd_packet *pisp);

#endif

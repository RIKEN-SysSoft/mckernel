#ifndef __HEADER_SYSCALL_H
#define __HEADER_SYSCALL_H

#define NUM_SYSCALLS 255

#define REQUEST_PAGE_COUNT              16
#define RESPONSE_PAGE_COUNT             16
#define DOORBELL_PAGE_COUNT             1
#define SCD_RESERVED_COUNT \
	(REQUEST_PAGE_COUNT + RESPONSE_PAGE_COUNT + DOORBELL_PAGE_COUNT)

#define SCD_MSG_PREPARE_PROCESS         0x1
#define SCD_MSG_PREPARE_PROCESS_ACKED   0x2
#define SCD_MSG_SCHEDULE_PROCESS        0x3

#define SCD_MSG_INIT_CHANNEL            0x5
#define SCD_MSG_INIT_CHANNEL_ACKED      0x6

#define SCD_MSG_SYSCALL_ONESIDE         0x4

struct ikc_scd_packet {
	int msg;
	int ref;
	unsigned long arg;
};

struct program_image_section {
	unsigned long vaddr;
	unsigned long len;
	unsigned long remote_pa;
	unsigned long filesz, offset;
	void *source;
};

struct program_load_desc {
	int num_sections;
	int status;
	int cpu;
	int pid;
	unsigned long entry;
	unsigned long rprocess;
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
};

struct syscall_post {
	unsigned long v[4];
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
	struct syscall_post post_buf;
};

#endif

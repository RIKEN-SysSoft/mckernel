#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "ibcomm.h"
#include "debug.h"
#include "mtype.h"
#include "mcons.h"
#include "mm_ib_test.h"

#define DEBUG_RDMA_RD
#ifdef DEBUG_RDMA_RD
#define dprintf(fmt, arg...) { printf("[DEBUG] " fmt, ##arg); }
#else
#define dprintf(fmt,arg...) {}
#endif

#define TEST_BUF_SIZE 16
#define TEST_SEND_BUF_NUM 3
#define TEST_RDMA_FLG_SIZE (sizeof(unsigned short))
#define TEST_REPEAT_TIME 1

enum rdma_buf_flg{
	RDMA_BUF_RESET_FLG = 0,
	RDMA_BUF_WRITE_FLG = 1,
};

static void printm(addr_t addr, int size) {
	int i;
	printf("print memory[0x%lx]\n", addr);
	for(i = 0; i < size; i++){
		printf("%02x ", *(unsigned char *)(addr+i));
	}
	printf("\n");
}

static void poll_magic(config_t config, void *buf, int tag){
	volatile unsigned short *flg_bit = (unsigned short *)(buf + config.buf_size - TEST_RDMA_FLG_SIZE);
	while(*flg_bit != tag+RDMA_BUF_WRITE_FLG);
}
/**
 * Alloc all MR buffers from MIC card memory
 *
 */
int main(int argc, char **argv) {
	config_t config;
	int i, j, tag = 0, rc = 0;
	char sync_res;
	double t0, t1, t;
	resource_t res;
	pdinfo_t pdinfo;
	qpinfo_t qpinfo;
	mrinfo_t *loc_mr_list = NULL;
	int entry;

	if (read_config(&config, argc, argv)) {
		goto main_exit;
	}

	config.use_rdma = 1;

	if(config.buf_size == 0) { config.buf_size = TEST_BUF_SIZE; }

	if (resource_create(config, &res) || pd_create(&res, &pdinfo) || qp_create(&res, &pdinfo, &qpinfo)) { goto main_exit; }
	dprintf("create all successfully..\n");

	// RDMA-read-from buffer
    dprintf("config.buf_size=%d\n", config.buf_size);
	void *rdma_buf = calloc(config.buf_size, sizeof(char));
    if(!config.server_flg) {
        memset(rdma_buf, '1', config.buf_size);
        *(uint16_t*)(rdma_buf + config.buf_size - sizeof(uint16_t)) = RDMA_BUF_WRITE_FLG;
    }
	if(mr_create(&res, &pdinfo, config.buf_size, rdma_buf, &res.rdma_mr)) { goto main_exit; }

	// RDMA-read-to buffer
	loc_mr_list = malloc(sizeof(mrinfo_t) * TEST_SEND_BUF_NUM);
	for (i = 0; i < TEST_SEND_BUF_NUM; i++) {
		void *loc_buf = calloc(config.buf_size, sizeof(char));
		if(mr_create(&res, &pdinfo, config.buf_size, loc_buf, &loc_mr_list[i])) { goto main_exit; }
	}

	/* Connect qp of each side and init them*/
	if(connect_qp(config, &res, &qpinfo)) { goto main_exit; }
	dprintf("connect done\n");
	debug_print_qp_conn_info(res, qpinfo, &config);

	/* Modify qp state to RTS */
	if(init_qp(config, &qpinfo) || rtr_qp(config, &qpinfo) || rts_qp(config, &qpinfo)) { goto main_exit; }
	dprintf("RTS done\n");

#if 1 /* barrier */
    for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
        if(sock_sync_data(qpinfo.sock[i], 1, "R", &sync_res)){
            error_perror("sock_sync_data");
        }
    }
#endif

	/* Initiator */
	if (config.server_flg) {
		t0 = cur_time();
		for (i = 0; i < TEST_REPEAT_TIME; i++) {
            for(j = 0; j < config.nremote; j++) {

                entry = j % TEST_SEND_BUF_NUM;
                
                // post RDMA_READ
                post_send_req(&qpinfo, &loc_mr_list[entry], IBV_WR_RDMA_READ, i, &qpinfo.remote_conn_info[j], 0);
                dprintf("post done\n");

                // wait for completion of command
                while(!poll_cq(&qpinfo, SEND_CQ_FLG, &tag) == IBCOMM_ERR_CODE) {}
                dprintf("poll_cq done\n");

                // wait for completion of DMA
                poll_magic(config, loc_mr_list[entry].buf, 0); /* magic is 16'h0001 */
                dprintf("poll_magic done\n");

                dprintf("initiator\n");
                printm((addr_t)loc_mr_list[entry].buf, config.buf_size);
            }
		}
		t1 = cur_time();
	} else {
        /* Responder */
		t0 = cur_time();
		for (i = 0; i < TEST_REPEAT_TIME; i++) {
			// print buffer data
			dprintf("responder\n");
			printm((addr_t)res.rdma_mr.buf, config.buf_size);
		}
		t1 = cur_time();
	}

#if 1 /* barrier */
    for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
        if(sock_sync_data(qpinfo.sock[i], 1, "R", &sync_res)){
            error_perror("sock_sync_data");
        }
    }
#endif

	t = (t1 - t0) * 1000;
	dprintf("%d\t%lf\t%lf\n", config.buf_size, t, t / TEST_REPEAT_TIME);

	main_exit:
	/*Can free all resources*/
	if (resource_destroy(&config, &res)) {
		dprintf("resource_destroy failed\n");
	}
	if(loc_mr_list) { free(loc_mr_list); }
    dprintf("bye\n");

	return rc;
}

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include "ibcomm.h"
#include "debug.h"
#include "mtype.h"
#include "mcons.h"
#include "mm_ib_test.h"

//#define DEBUG_RDMA_WR_WITH_IMM
#ifdef DEBUG_RDMA_WR_WITH_IMM
#define dprintf printf
#else
#define dprintf(...)
#endif

#define TEST_NRECVBUF 10
#define TEST_NSENDBUF 10
#define TEST_SZBUF 10
#define TEST_RDMA_FLG_SIZE (sizeof(unsigned short))
#define NTRIAL 120
#define PPOLLS 2 /* sweet spot is around 10 */
#define NSKIPS (PPOLLS*1)
#define PPOLLR 60 /* sweet spot is around 10 */
#define NSKIPR (PPOLLR*1)

enum rdma_buf_flg{
	RDMA_BUF_RESET_FLG = 0,
	RDMA_BUF_WRITE_FLG = 1,
};

static unsigned long rdtsc() {
    unsigned long x;
    __asm__ __volatile__("xorl %%eax, %%eax; cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx"); /* rdtsc cannot be executed earlier than this */
    __asm__ __volatile__("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(x) : : "memory"); /* rdtsc cannot be executed earlier than here */
    __asm__ __volatile__("xorl %%eax, %%eax; cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx"); /* following instructions cannot be executed earlier than this */
    return x;
}

static void set_written_flg(config_t config, void *buf, int tag){
	*(unsigned short *)(buf + config.buf_size - TEST_RDMA_FLG_SIZE)  = tag+RDMA_BUF_WRITE_FLG;
}

/**
 * Alloc all MR buffers from MIC card memory
 *
 */
int main(int argc, char **argv) {
	config_t config;
	int i, j, k, tag = 0, rc = 0;
	char sync_res;
    unsigned long tscs, tsce;
	resource_t res;
	pdinfo_t pdinfo;
	qpinfo_t qpinfo;
	mrinfo_t *loc_mr_list = NULL;
	int entry, wait_tag;
	mrinfo_t *mrinfo_recv_list = NULL;
    int mr_idx = 0;

    FILE* fp;
    fp = popen("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if(!fp) { printf("popen failed\n"); goto fn_fail; }
    char freq_str[256];
    int nread = fread(freq_str, sizeof(char), 256, fp);
    if(!nread) { printf("popen failed"); goto fn_fail; }
    freq_str[nread] = 0;
    //printf("%s", freq_str);
    long int freq = strtol(freq_str, NULL, 10) * 1000;
    printf("freq=%ld\n", freq);
    pclose(fp);
    //exit(1);

	if (read_config(&config, argc, argv)) {
		goto main_exit;
	}

	config.use_rdma = 1;

	if(config.buf_size == 0)
		config.buf_size = TEST_SZBUF;

	if (resource_create(config, &res) || pd_create(&res, &pdinfo)
			|| qp_create(&res, &pdinfo, &qpinfo)) {
		goto main_exit;
	}
	debug_printf("create all successfully..\n");

	/* create MR buffers */
	int buf_total_size = config.buf_size;

	// rdma r/w buffer
	// add rdma flag size
	void *rdma_buf = calloc(buf_total_size, sizeof(char));
	memset(rdma_buf, 0, buf_total_size);
	if (mr_create(&res, &pdinfo, buf_total_size, rdma_buf, &res.rdma_mr))
		goto main_exit;

	// local data buffers
	loc_mr_list = malloc(sizeof(mrinfo_t) * TEST_NSENDBUF);
	for (i = 0; i < TEST_NSENDBUF; i++) {
		void *loc_buf = calloc(buf_total_size, sizeof(char));
		if (config.server_flg) {
			memset(loc_buf, 's'+ i, config.buf_size);
		} else {
			memset(loc_buf, 'c'+ i, config.buf_size);
		}
		set_written_flg(config, loc_buf, 0); /* magic is 16'h0001 */

		if (mr_create(&res, &pdinfo, buf_total_size, loc_buf, &loc_mr_list[i]))
			goto main_exit;
	}
	dprintf("create RDMA buffer successfully..\n");

	/* Connect qp of each side and init them*/
	if (connect_qp(config, &res, &qpinfo)) {
		goto main_exit;
	}
	dprintf("connect done\n");
	debug_print_qp_conn_info(res, qpinfo, &config);

	/* Register fixed recv buffers */
	mrinfo_recv_list = malloc(sizeof(mrinfo_t) * TEST_NRECVBUF);
	for (i = 0; i < TEST_NRECVBUF; i++) {
		char *buf = calloc(config.buf_size, sizeof(char));
		if(buf == NULL) {
			fprintf(stderr, "cannot malloc %dth buf\n", i);
			goto main_exit;
		}

		if (mr_create(&res, &pdinfo, config.buf_size, buf, &mrinfo_recv_list[i])) {
			goto main_exit;
		}
	}

	/* Modify qp state to RTS */
	if (init_qp(config, &qpinfo)
			|| rtr_qp(config, &qpinfo) || rts_qp(config, &qpinfo)) {
		goto main_exit;
	}
	debug_printf("RTS done\n");

#if 1
    /* barrier */
    for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
        if(sock_sync_data(qpinfo.sock[i], 1, "R", &sync_res)){
            error_perror("sock_sync_data");
        }
    }
#endif

	if (config.server_flg) { /* sender side */
        if(NTRIAL % PPOLLS != 0) { printf("set NTRIAL multiple of PPOLLS\n"); goto fn_fail; }
        if(NTRIAL <= NSKIPS) { printf("set NTRIAL > NSKIP\n"); goto fn_fail; }

		for (i = 0; i < NTRIAL; i++) {
            if(i == NSKIPS) { tscs = rdtsc(); }
            for(j = 0; j < config.nremote; j++) {
                
                entry = j % TEST_NSENDBUF;
                
                post_send_req(&qpinfo, &loc_mr_list[entry], IBV_WR_RDMA_WRITE_WITH_IMM, 0, &qpinfo.remote_conn_info[j], 100+0);
                
                
                int nfound = 0;
                if(i % PPOLLS == PPOLLS - 1) {
                    k = 0;
                    while(1) {
                        int result;
                        struct ibv_wc cqe[PPOLLS];
                        result = ibv_poll_cq(qpinfo.scq, PPOLLS, &cqe[0]);
                        if(result < 0) { printf("ibv_poll_cq"); goto fn_fail; }
                        if(result > 0) {
                            for(j = 0; j < result; j++) { 
                                if(cqe[j].status != IBV_WC_SUCCESS) { printf("cqe status\n"); goto fn_fail; }
                            }
                            //debug_print_mem((addr_t)loc_mr_list[entry].buf, config.buf_size);
                            nfound += result;
                            if(nfound == PPOLLS) { break; }
                        }
                        k++;
                    }
                }
            }
        }
            tsce = rdtsc(); printf("send,%.0f\n", (tsce-tscs)/(double)(NTRIAL-NSKIPS));
    } else { // receiver side
        if(NSKIPR % PPOLLR !=0) { printf("set NSKIP multiple of PPOLL\n"); goto fn_fail; }
		for (i = 0; i < NTRIAL; i++) {
            if(i == NSKIPR) { tscs = rdtsc(); }
			wait_tag = i % TEST_NSENDBUF;

            post_recv_req(&qpinfo, &mrinfo_recv_list[i%TEST_NSENDBUF], i%TEST_NSENDBUF);
            int nfound = 0;
            if(i % PPOLLR == PPOLLR - 1) {
                k = 0;
                while(1) {
                    int result;
                    struct ibv_wc cqe[PPOLLR];
                    result = ibv_poll_cq(qpinfo.rcq, 1, &cqe[0]);
                    if(result < 0) { printf("poll_cq\n"); goto fn_fail; }
                    if(result > 0) {
                        for(j = 0; j < result; j++) { 
                            if(cqe[j].status != IBV_WC_SUCCESS) { printf("cqe.status"); goto fn_fail; }
                        }
                        
                        //debug_print_mem((addr_t)res.rdma_mr.buf, config.buf_size);
                        nfound += result;
                        if(nfound == PPOLLR) { break; }
                    }
                    k++;
                }
            }
		}
        tsce = rdtsc(); printf("recv,%.0f\n", (tsce-tscs)/(double)(NTRIAL-NSKIPR));
	}

 fn_fail:
main_exit:

	if (resource_destroy(&config, &res)) {
		dprintf("resource destroy failed\n");
	}
	if(loc_mr_list) { free(loc_mr_list); }

	return rc;
}

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/mman.h>
#include <unistd.h>
#include "ibcomm.h"
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
#define TEST_RDMA_FLG_SIZE (sizeof(unsigned short))
#define NTRIAL 60
#define PPOLLS 10 /* sweet spot is around 10 */
#define NSKIPS 30
#define PPOLLR 1 /* sweet spot is around 10 */
#define NSKIPR 30

static unsigned long rdtsc() {
    unsigned long x;
    __asm__ __volatile__("xorl %%eax, %%eax; cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx"); /* rdtsc cannot be executed earlier than this */
    __asm__ __volatile__("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(x) : : "memory"); /* rdtsc cannot be executed earlier than here */
    __asm__ __volatile__("xorl %%eax, %%eax; cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx"); /* following instructions cannot be executed earlier than this */
    return x;
}


int debug_counter = 0, debug_counter2 = 0, debug_counter3 = 0, dc = 0;

int main(int argc, char **argv) {
    int ibcom_errno;
	config_t config;
	int i, j, k, tag = 0, rc = 0;
	char sync_res;
    unsigned long tscs, tsce;
	resource_t res;
	pdinfo_t pdinfo;
	qpinfo_t qpinfo;
	mrinfo_t *loc_mr_list = NULL;
	mrinfo_t *mrinfo_recv_list = NULL;

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

	if(config.buf_size == 0) { printf("set buf_size"); goto fn_fail; }

	if (resource_create(config, &res) || pd_create(&res, &pdinfo)
			|| qp_create(&res, &pdinfo, &qpinfo)) {
		goto main_exit;
	}

	// rdma-write-to ring with 2NTRIAL slots 
	void *rdma_buf = mmap(0, IBCOM_INLINE_DATA * NCHAIN * NTRIAL, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    /* unmark magic */
    memset(rdma_buf, 0, IBCOM_INLINE_DATA * NCHAIN * NTRIAL);
    if(!rdma_buf) { printf("mmap failed\n"); goto fn_fail; }
	if(mr_create(&res, &pdinfo, IBCOM_INLINE_DATA * NCHAIN * NTRIAL, rdma_buf, &res.rdma_mr)) { printf("mr_create failed\n"); goto fn_fail; }

#define NSBUF 1
	// rdma-write-from buffers
	loc_mr_list = malloc(sizeof(mrinfo_t) * NSBUF);
	for(i = 0; i < NSBUF; i++) {
		void *loc_buf = mmap(0, IBCOM_INLINE_DATA * NCHAIN, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        if(!loc_buf) { printf("mmap failed\n"); goto fn_fail; }
		if(config.server_flg) {
            for(j = 0; j < IBCOM_INLINE_DATA * NCHAIN; j++) {
                *((char*)(loc_buf + j)) = IBCOM_INLINE_DATA * NCHAIN * i + j;
            }
            *((uint32_t*)(loc_buf + IBCOM_INLINE_DATA * NCHAIN - sizeof(uint32_t))) = IBCOM_MAGIC;
		}
		if(mr_create(&res, &pdinfo, IBCOM_INLINE_DATA * NCHAIN, loc_buf, &loc_mr_list[i])) { printf("mr_create fail\n"); goto fn_fail; }
	}
	dprintf("create RDMA buffer successfully..\n");

	/* Connect qp of each side and init them*/
	if (connect_qp(config, &res, &qpinfo)) {
		goto main_exit;
	}
	dprintf("connect done\n");
	debug_print_qp_conn_info(res, qpinfo, &config);

	/* bring qp up to RTS */
	if(init_qp(config, &qpinfo) || rtr_qp(config, &qpinfo) || rts_qp(config, &qpinfo)) { printf("trs failed\n"); goto fn_fail; }

    /* pre-post receive commands */
	if(!config.server_flg) {
#if 0
        for(i = 0; i < _MAX_RQ_CAPACITY - 16; i++){
            ibcom_errno = ibcom_irecv(&qpinfo, 0);
            if(ibcom_errno) { printf("post_recv_req\n"); goto fn_fail; }
        }
#endif
    }

    /* barrier */
    for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
        if(sock_sync_data(qpinfo.sock[i], 1, "R", &sync_res)){
            perror("sock_sync_data");
        }
    }

	if (config.server_flg) { /* sender side */
        //        usleep(1000000);
        if(NTRIAL % PPOLLS != 0) { printf("set NTRIAL multiple of PPOLLS\n"); goto fn_fail; }
        if(NTRIAL <= NSKIPS) { printf("set NTRIAL > NSKIP\n"); goto fn_fail; }

		for (i = 0; i < NTRIAL; i++) {
            if(i == NSKIPS) { tscs = rdtsc(); }
            
#if 0
            for(j = 0; j < NCHAIN - 1; j++) {
                post_send_req4(&qpinfo, &loc_mr_list[i % NSBUF], IBV_WR_RDMA_WRITE, &qpinfo.remote_conn_info[0], 0, i * NCHAIN + j, IBCOM_INLINE_DATA * j);
            }
            post_send_req4(&qpinfo, &loc_mr_list[i % NSBUF], IBV_WR_RDMA_WRITE_WITH_IMM, &qpinfo.remote_conn_info[0], i, i * NCHAIN + j, IBCOM_INLINE_DATA * j);
#else
            ibcom_isend_chain(&qpinfo, &loc_mr_list[i % NSBUF], IBV_WR_RDMA_WRITE, &qpinfo.remote_conn_info[0], i, i);
#endif
            debug_counter2 += 1;

            //#define POLL_SCQ_PERIODICALLY

#ifdef POLL_SCQ_PERIODICALLY
            if(i % PPOLLS == PPOLLS - 1) { 
                int nfound = 0;
                k = 0;
                while(1) {
                    int result;
                    struct ibv_wc cqe[PPOLLS * NCHAIN];
                    result = ibv_poll_cq(qpinfo.scq, PPOLLS * NCHAIN, &cqe[0]);
                    if(result < 0) { printf("ibv_poll_cq"); goto fn_fail; }
                    if(result > 0) {
                        for(j = 0; j < result; j++) { 
                            if(cqe[j].status != IBV_WC_SUCCESS) { printf("cqe status\n"); goto fn_fail; }
                        }
                        nfound += result;
                        debug_couter3 += result;
                        if(nfound == PPOLLS * NCHAIN) { break; }
                    }
                    k++;
                }
            }
#endif
            //printf("%d ", i);
        }
        tsce = rdtsc(); printf("send,%.0f\n", (tsce-tscs)/(double)(NTRIAL-NSKIPS));
#ifndef POLL_SCQ_PERIODICALLY
        int nfound = 0;
        k = 0;
        while(1) {
            int result;
            struct ibv_wc cqe[NTRIAL * NCHAIN];
            result = ibv_poll_cq(qpinfo.scq, NTRIAL * NCHAIN, &cqe[0]);
            if(result < 0) { printf("ibv_poll_cq"); goto fn_fail; }
            if(result > 0) {
                for(j = 0; j < result; j++) { 
                    if(cqe[j].status != IBV_WC_SUCCESS) { printf("cqe status\n"); goto fn_fail; }
                }
                nfound += result;
                debug_counter3 += result;
                if(nfound == NTRIAL * NCHAIN) { break; }
            }
            k++;
        }
#endif
        dprintf("debug_counter2=%d,%d\n", debug_counter2, debug_counter3);
    } else { // receiver side
        if(NSKIPR % PPOLLR !=0) { printf("set NSKIP multiple of PPOLL\n"); goto fn_fail; }
		for (i = 0; i < NTRIAL; i++) {
            if(i == NSKIPR) { tscs = rdtsc(); }

            if(i % PPOLLR == PPOLLR - 1) {
                int nfound = 0;
                k = 0;
                while(1) {
                    int result;
                    struct ibv_wc cqe[PPOLLR];
#define SKIP_POLL_RCQ
#ifdef SKIP_POLL_RCQ /* if you want to skip poll rcq */
                    result = 1;
#else
                    result = ibv_poll_cq(qpinfo.rcq, PPOLLR, &cqe[0]);
                    if(result < 0) { printf("poll_cq\n"); goto fn_fail; }
#endif
                    if(result > 0) {
                        for(j = 0; j < result; j++) { 
#ifndef SKIP_POLL_RCQ                            
                            if(cqe[j].status != IBV_WC_SUCCESS) { printf("cqe.status"); goto fn_fail; }
#endif
                            volatile uint32_t* magic = (volatile uint32_t*)(res.rdma_mr.buf + IBCOM_INLINE_DATA * NCHAIN * i + IBCOM_INLINE_DATA * NCHAIN - sizeof(uint32_t));
                            while(*magic != IBCOM_MAGIC) { 
                                __asm__ __volatile__
                                    (
                                     "movq %0, %%rsi;"
                                     "prefetchnta -0x40(%%rsi);"
                                     "prefetchnta -0x80(%%rsi);"
                                     "prefetchnta -0xc0(%%rsi);"
                                     :
                                     : "r"(magic)
                                     : "%rsi");

                                //__asm__ __volatile__ ("pause;" : : );
                            }
                            //if(cqe[j].imm_data != i) { printf("%d\n", cqe[j].imm_data); }
                            //print_mem((addr_t)res.rdma_mr.buf + IBCOM_RDMABUF_SZSEG * i * 2, 32);
                            //printf("%d ", i);
                        }
#ifdef SKIP_POLL_RCQ                            
                        break;
#else
                        debug_counter += result;
                        nfound += result;
                        if(nfound == PPOLLR) { break; }
#endif
                    } else {
                        k += 1;
                        if(k % (1ULL<<26) == (1ULL<<26) - 1) {
                            dc += 1;
                            printf("i=%d,dc=%d\n", i, dc); 
                            ibcom_errno = ibcom_irecv(&qpinfo, 0);
                            if(ibcom_errno) { printf("post_recv_req,dc=%d\n", dc); goto fn_fail; }
                        }
                    }
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

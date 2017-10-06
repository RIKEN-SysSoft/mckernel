#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
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
#define NTRIAL 30
#define PPOLLS 10 /* sweet spot is around 10 */
#define NSKIPS 10
#define NSKIPR 10

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
    long int freq = strtol(freq_str, NULL, 10) * 1000;
    if(freq != 2601000000) { printf("freq=%ld\n", freq); goto fn_fail; }
    pclose(fp);

	if(read_config(&config, argc, argv)) { goto fn_fail; }

	config.use_rdma = 1;

	if(config.buf_size == 0) { printf("set buf_size"); goto fn_fail; }

	if (resource_create(config, &res) || pd_create(&res, &pdinfo) || qp_create(&res, &pdinfo, &qpinfo)) { goto main_exit; }

	// rdma-write-to ring with 2NTRIAL slots 
    //#define SHM
#ifdef SHM
#define MAX2(x,y) ((x)>(y)?(x):(y))
    int shmid = shmget(IPC_PRIVATE, MAX2(2*1024*1024, IBCOM_INLINE_DATA * NCHAIN * NTRIAL), SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W);
    if(shmid < 0) { perror("shmget"); goto fn_fail; }
    //printf("shmid: 0x%x\n", shmid);
    void *rdma_buf = shmat(shmid, 0, 0);
    if(rdma_buf == (char *)-1) {
        perror("Shared memory attach failure");
        shmctl(shmid, IPC_RMID, NULL);
        goto fn_fail;
    }
#else
	void *rdma_buf = mmap(0, IBCOM_INLINE_DATA * NCHAIN * NTRIAL, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
#endif
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
#define TLBPREF_AHEAD 20//20
        int tlb_pref_ahd;
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
#if 1
            tlb_pref_ahd = 4096 * TLBPREF_AHEAD;
            __asm__ __volatile__
                ("movq %0, %%rsi;"
                 "movq 0(%%rsi), %%rax;"
                 : : "r"((uint64_t)loc_mr_list[i % NSBUF].buf + tlb_pref_ahd) : "%rsi", "%rax");
#endif
#if 1
            __asm__ __volatile__
                ("movq %0, %%rsi;"
                 "prefetchnta 0x00(%%rsi);"
                 "prefetchnta 0x40(%%rsi);"
                 "prefetchnta 0x80(%%rsi);"
                 "prefetchnta 0xc0(%%rsi);"
                 : : "r"((uint64_t)loc_mr_list[(i+4) % NSBUF].buf) : "%rsi");
#endif

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
        dprintf("debug_counter=%d\n", debug_counter3);
    } else { // receiver side
        int tlb_pref_ahd;
#define TLB_PREF_AMT_AHEAD 20//20
#define PREF_AHEAD 10
#if 0
        for(j = 0; j < PREF_AHEAD; j++) {
            __asm__ __volatile__
                ("movq %0, %%rsi;"
                 "prefetchnta 0x00(%%rsi);"
                 "prefetchnta 0x40(%%rsi);"
                 "prefetchnta 0x80(%%rsi);"
                 "prefetchnta 0xc0(%%rsi);"
                 : : "r"(res.rdma_mr.buf + IBCOM_INLINE_DATA * NCHAIN * (j)) : "%rsi");
        }
#endif

#if 1
        for(tlb_pref_ahd = 0; tlb_pref_ahd < 4096*TLB_PREF_AMT_AHEAD; tlb_pref_ahd += 4096) {
            __asm__ __volatile__
                ("movq %0, %%rsi;"
                 "movq  4096(%%rsi), %%rax;"
                 : : "r"(rdma_buf + tlb_pref_ahd) : "%rsi", "%rax");
        }
#endif
		for(i = 0; i < NTRIAL; i++) {
            if(i == NSKIPR) { tscs = rdtsc(); }
            
            volatile uint32_t* magic = (volatile uint32_t*)(res.rdma_mr.buf + IBCOM_INLINE_DATA * NCHAIN * i + IBCOM_INLINE_DATA * NCHAIN - sizeof(uint32_t));

                k = 4096*5;
                void* tlb_pref_ptr = (void*)magic + 4096*TLB_PREF_AMT_AHEAD;
#if 1
                tlb_pref_ahd = (uint64_t)magic + 4096*TLB_PREF_AMT_AHEAD - (uint64_t)rdma_buf;
#else
                tlb_pref_ahd = 4096*TLB_PREF_AMT_AHEAD;
#endif     
           //tlb_pref_ahd = tlb_pref_ahd % (IBCOM_INLINE_DATA * NCHAIN * NTRIAL);

                while(*magic != IBCOM_MAGIC) { 
#if 1
                __asm__ __volatile__
                    ("movq %0, %%rsi;"
                     "prefetchnta 0x00(%%rsi);"
                     "prefetchnta 0x40(%%rsi);"
                     "prefetchnta 0x80(%%rsi);"
                     "prefetchnta 0xc0(%%rsi);"
                     : : "r"(res.rdma_mr.buf + IBCOM_INLINE_DATA * NCHAIN * (i+1)) : "%rsi");
#endif
#if 1
                __asm__ __volatile__
                    ("movq %0, %%rsi;"
                     "prefetchnta 0x00(%%rsi);"
                     "prefetchnta 0x40(%%rsi);"
                     "prefetchnta 0x80(%%rsi);"
                     "prefetchnta 0xc0(%%rsi);"
                     : : "r"(res.rdma_mr.buf + IBCOM_INLINE_DATA * NCHAIN * (i+2)) : "%rsi");
#endif
#if 0

                __asm__ __volatile__
                    ("movq %0, %%rsi;"
                     "prefetchnta 0x00(%%rsi);"
                     "prefetchnta 0x40(%%rsi);"
                     "prefetchnta 0x80(%%rsi);"
                     "prefetchnta 0xc0(%%rsi);"
                     : : "r"(res.rdma_mr.buf + IBCOM_INLINE_DATA * NCHAIN * (i+PREF_AHEAD)) : "%rsi");
#endif
#if 0
                __asm__ __volatile__
                    ("movq %0, %%rsi;"
                     "prefetchnta 0x00(%%rsi);"
                     "prefetchnta 0x40(%%rsi);"
                     "prefetchnta 0x80(%%rsi);"
                     "prefetchnta 0xc0(%%rsi);"
                     : : "r"(res.rdma_mr.buf + IBCOM_INLINE_DATA * NCHAIN * (i+32)) : "%rsi");
#endif
#if 0
                __asm__ __volatile__
                    ("movq %0, %%rsi;"
                     "movq 0(%%rsi), %%rax;"
                     : : "r"(magic+k) : "%rsi", "%rax");
                //k += 4096;
#endif                
#if 0
                __asm__ __volatile__
                    ("movq %0, %%rsi;"
                     "movq 0(%%rsi), %%rax;"
                     : : "r"(tlb_pref_ptr) : "%rsi", "%rax");
#endif
#if 1
                __asm__ __volatile__
                    ("movq %0, %%rsi;"
                     "movq 0(%%rsi), %%rax;"
                     : : "r"(rdma_buf + tlb_pref_ahd) : "%rsi", "%rax");
                tlb_pref_ahd = (tlb_pref_ahd + 4096*20) % (IBCOM_INLINE_DATA * NCHAIN * NTRIAL);
#endif
            }
            //print_mem((addr_t)res.rdma_mr.buf + IBCOM_RDMABUF_SZSEG * i * 2, 32);
		}
        tsce = rdtsc(); printf("recv,%.0f\n", (tsce-tscs)/(double)(NTRIAL-NSKIPR));
	}

 fn_fail:
main_exit:
#ifdef SHM
    shmctl(shmid, IPC_RMID, NULL);
#endif
#if 0
	if (resource_destroy(&config, &res)) {
		dprintf("resource destroy failed\n");
	}
	if(loc_mr_list) { free(loc_mr_list); }
#endif
	return rc;
}

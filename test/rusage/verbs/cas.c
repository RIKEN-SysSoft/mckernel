#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/mman.h>
#include <unistd.h>
#include "ibcomm.h"
#include "debug.h"
#include "mtype.h"
#include "mcons.h"
#include "mm_ib_test.h"

//#define DEBUG_CAS
#ifdef DEBUG_CAS
#define dprintf printf
#else
#define dprintf(...)
#endif

#define NTRIAL 10
#define NSKIPS 0
#define NSKIPR 0

#define ERR_CHKANDJUMP(cond, errno, stmt) if(cond) { stmt; main_errno = errno; goto fn_fail; }

static unsigned long rdtsc() {
    unsigned long x;
    __asm__ __volatile__("xorl %%eax, %%eax; cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx"); /* rdtsc cannot be executed earlier than this */
    __asm__ __volatile__("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(x) : : "memory"); /* rdtsc cannot be executed earlier than here */
    __asm__ __volatile__("xorl %%eax, %%eax; cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx"); /* following instructions cannot be executed earlier than this */
    return x;
}

volatile int k;
int main(int argc, char **argv) {
	config_t config;
	int i;
    int j;
    int main_errno = 0;
	char sync_res;
    unsigned long tscs, tsce;
	resource_t res;
	pdinfo_t pdinfo;
	qpinfo_t qpinfo;
	mrinfo_t *mr_local = NULL;
	int entry;
    int ib_errno;

	if (read_config(&config, argc, argv)) {
		goto fn_exit;
	}

	config.use_rdma = 1;

	if(config.buf_size != 8) {
        printf("set buf_size to 8\n");
        config.buf_size = 8;
    }

	if(resource_create(config, &res) || pd_create(&res, &pdinfo) || qp_create(&res, &pdinfo, &qpinfo)) { printf("qp_create failed\n"); goto fn_fail; }

	/* rdma-write-to buffer */                                         
	void *buf_rdma = mmap(0, 8/*IBCOM_RDMABUF_SZSEG*/, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    //void *buf_rdma = calloc(8, 1);
    ERR_CHKANDJUMP(!buf_rdma, -1, printf("mmap failed\n"));
    memset(buf_rdma, 0, 8/*IBCOM_RDMABUF_SZSEG*/);

	//ib_errno = mr_create(&res, &pdinfo, 8/*IBCOM_RDMABUF_SZSEG*/, buf_rdma, &res.rdma_mr);
    //ERR_CHKANDJUMP(ib_errno, -1, printf("mr_create failed\n"));

	memset(&res.rdma_mr, 0, sizeof(mrinfo_t));
	res.rdma_mr.buf = buf_rdma;
	res.rdma_mr.buf_size = 8;
	res.rdma_mr.mr = ibv_reg_mr(pdinfo.pd, buf_rdma, 8, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC);
	ERR_CHKANDJUMP(!res.rdma_mr.mr, -1, printf("ibv_reg_mr failed\n"));



	mr_local = calloc(sizeof(mrinfo_t), sizeof(char));
    ERR_CHKANDJUMP(!mr_local, -1, printf("calloc failed\n"));

    void *buf_local = mmap(0, config.buf_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    ERR_CHKANDJUMP(!buf_local, -1, printf("mmap failed\n"));
    memset(buf_local, config.server_flg ? 0x55 : 0xaa, config.buf_size);

    //ib_errno = mr_create(&res, &pdinfo, config.buf_size, buf_local, mr_local);
    //ERR_CHKANDJUMP(ib_errno, -1, printf("mr_create fail\n"));
	memset(mr_local, 0, sizeof(mrinfo_t));
	mr_local->buf = buf_local;
	mr_local->buf_size = 8;
	mr_local->mr = ibv_reg_mr(pdinfo.pd, buf_local, 8, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC);
	ERR_CHKANDJUMP(!mr_local->mr, -1, printf("ibv_reg_mr failed\n"));

	/* exchange gid, lid, qpn, raddr, rkey */
	if(connect_qp(config, &res, &qpinfo)) { printf("connect_qp failed\n"); goto fn_fail; }
	debug_print_qp_conn_info(res, qpinfo, &config);
    printf("connect_qp done\n"); fflush(stdout);

	/* make qp RTS */
	if(init_qp(config, &qpinfo) || rtr_qp(config, &qpinfo) || rts_qp(config, &qpinfo)) { printf("rts failed\n"); goto fn_fail; }
    printf("rts done\n"); fflush(stdout);

    /* barrier */
    for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
        if(sock_sync_data(qpinfo.sock[i], 1, "R", &sync_res)) { perror("sock_sync_data"); }
    }
    printf("barrier done\n"); fflush(stdout);

	if(config.server_flg) { /* sender side */
		for (i = 0; i < NTRIAL; i++) {
            if(i == NSKIPS) { tscs = rdtsc(); }
            
            struct ibv_send_wr sr;
            memset(&sr, 0, sizeof(struct ibv_send_wr));
            struct ibv_send_wr *bad_wr = NULL;

            struct ibv_sge sge[1];
            memset(&sge[0], 0, sizeof(struct ibv_sge));
            
            sr.next = NULL;
            sr.wr_id = 0;
            sr.sg_list = sge;
            //sr.imm_data = imm_data;
            sr.send_flags = IBV_SEND_SIGNALED;
            
            sge[0].addr = (uintptr_t)mr_local->buf;
            printf("local_addr=%08lx\n", sge[0].addr);
            sge[0].length = mr_local->buf_size;
            printf("length=%d\n", sge[0].length);
            sge[0].lkey = mr_local->mr->lkey;
            sr.num_sge = 1;

#if 1
            sr.opcode = IBV_WR_ATOMIC_CMP_AND_SWP;
            //sr.opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
            sr.wr.atomic.compare_add = (uint64_t)i;
            sr.wr.atomic.swap = (uint64_t)i+1;
            sr.wr.atomic.remote_addr = /*255*/qpinfo.remote_conn_info[0].addr;
            printf("remote_addr=%08lx\n", sr.wr.atomic.remote_addr);
            sr.wr.atomic.rkey = /*123*/qpinfo.remote_conn_info[0].rkey;
            printf("rkey=%08lx\n", sr.wr.atomic.rkey);
#else
            sr.opcode = IBV_WR_RDMA_WRITE;
            sr.wr.rdma.remote_addr = qpinfo.remote_conn_info[0].addr;
            sr.wr.rdma.rkey = qpinfo.remote_conn_info[0].rkey;
#endif
            dprintf("ibv_post_send,raddr=%lx\n", sr.wr.rdma.remote_addr);
            
            ib_errno = ibv_post_send(qpinfo.qp, &sr, &bad_wr);
            ERR_CHKANDJUMP(ib_errno, -1, printf("ibv_post_send return %d\n", ib_errno));
            while(1) {
                int result;
                struct ibv_wc cqe[1];
                result = ibv_poll_cq(qpinfo.scq, 1, &cqe[0]);
                ERR_CHKANDJUMP(result < 0, -1, printf("ibv_poll_cq"));
                if(result > 0) {
                    for(j = 0; j < result; j++) { 
                        printf("cqe.imm_data=%08x\n", cqe[j].imm_data);
                        printf("buf_local=%lx\n", *((uint64_t*)buf_local));
                        ERR_CHKANDJUMP(cqe[j].status != IBV_WC_SUCCESS, -1, printf("cqe status,%s\n", ibv_wc_status_str(cqe[j].status)));
                    }
                    break;
                }
            }
            
		}
        tsce = rdtsc(); printf("send,%.0f\n", (tsce-tscs)/(double)(NTRIAL-NSKIPS));
        
	} else { /* receiver side */
        
		for (i = 0; i < NTRIAL; i++) {
            if(i == NSKIPR) { tscs = rdtsc(); }
            
            printf("res.rdma_mr.buf=%lx\n", (unsigned long)res.rdma_mr.buf);
            printf("poll addr=%lx\n", (unsigned long)(buf_rdma));

            volatile uint64_t *ptr = (volatile uint64_t *)buf_rdma;
            while(*ptr == i) {
                __asm__ __volatile__("pause");
            }
            printf("*ptr=%08lx\n", *ptr);
		}
        tsce = rdtsc(); printf("recv,%.0f\n", (tsce-tscs)/(double)(NTRIAL-NSKIPR));
	}

	fn_exit:
	return main_errno;
 fn_fail:
    goto fn_exit;
}

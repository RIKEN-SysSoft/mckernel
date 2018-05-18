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

#include <mpi.h>
#include <qlmpilib.h>

//#define DEBUG_RDMA_WR
#ifdef DEBUG_RDMA_WR
#define dprintf printf
#else
#define dprintf(...)
#endif

#define TEST_SEND_BUF_NUM 3
#define TEST_RDMA_FLG_SIZE (sizeof(unsigned short))
#define NTRIAL 1 /* 120 */
#define PPOLLS 1 /* sweet spot is around 10 */
#define NSKIPS (PPOLLS*0)
#define PPOLLR 1 /* sweet spot is around 10 */
#define NSKIPR (PPOLLR*0)

#define IBCOM_MAGIC 0x55aa55aa

typedef struct tailmagic_t {
    uint32_t magic;
} tailmagic_t;

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

volatile int k;
int main(int argc, char **argv) {
	config_t config;
	unsigned long i, j;
    int ibcom_errno = 0;
	char sync_res;
    unsigned long tscs, tsce;
	resource_t res;
	pdinfo_t pdinfo;
	qpinfo_t qpinfo;
	mrinfo_t *loc_mr_list = NULL;
	int entry;
    int ibv_errno;
	int rc, my_rank, loop_cnt = 0;
	uint32_t send_val = 0;

	if (read_config(&config, argc, argv)) {
		goto fn_exit;
	}

	config.use_rdma = 1;

    unsigned long buf_size;
    char*  str_env = getenv("BUF_SIZE");
    buf_size = str_env ? atol(str_env) : 4096/*48,1073741824ULL * 1 + 4*/;

	if(buf_size == 0) { printf("set buf_size"); goto fn_fail; }

	if(resource_create(config, &res) || pd_create(&res, &pdinfo)) { printf("qp_create failed\n"); goto fn_fail; }
    
    ibv_errno = qp_create(&res, &pdinfo, &qpinfo);
    IBCOM_ERR_CHKANDJUMP(ibv_errno, -1, printf("qp_create failed\n"));

	/* create MR buffers */

	// rdma-write-to buffer
#if 1
	void *rdma_buf = mmap(0, buf_size * NTRIAL, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    memset(rdma_buf, 0, buf_size * NTRIAL);
#else
	void *rdma_buf = calloc(buf_size * NTRIAL, sizeof(char));
#endif
    if(!rdma_buf) { printf("mmap failed\n"); goto fn_fail; }
	if(mr_create(&res, &pdinfo, buf_size * NTRIAL, rdma_buf, &res.rdma_mr)) { printf("mr_create failed\n"); goto fn_fail; }

// for mpi
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);

// switch server/client by rank
	if (my_rank == 0) {
		config.server_name = NULL;
		config.server_flg = 1;
	}

	// local data buffers
	loc_mr_list = calloc(sizeof(mrinfo_t) * NTRIAL, sizeof(char));
	for (i = 0; i < NTRIAL; i++) {
		void *loc_buf = mmap(0, buf_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        if(loc_buf == MAP_FAILED) { printf("mmap failed\n"); goto fn_fail; }
		if(config.server_flg) {
            for(j = 0; j < buf_size; j++) {
                *((unsigned char*)loc_buf + j) = (char)i;
            }
            *((uint32_t *)(loc_buf + buf_size - sizeof(uint32_t))) = 0 + IBCOM_MAGIC;
		}

        dprintf("magic addr=%lx\n", (unsigned long)(loc_buf + buf_size - TEST_RDMA_FLG_SIZE));

		if(mr_create(&res, &pdinfo, buf_size, loc_buf, &loc_mr_list[i])) { printf("mr_create failed\n"); goto fn_fail;	}
    }

    if(!config.server_flg) { dprintf("res->rdma_mr.mr->addr=%lx\n", (unsigned long)res.rdma_mr.mr->addr); }
	/* exchange gid, lid, qpn, raddr, rkey */
	if(connect_qp(config, &res, &qpinfo)) { printf("connect_qp failed\n"); goto fn_fail; }
	debug_print_qp_conn_info(res, qpinfo, &config);
    printf("connect_qp done\n"); fflush(stdout);

    if(config.server_flg) { dprintf("qpinfo->remote_conn_info[0].addr=%lx\n", qpinfo.remote_conn_info[0].addr); }

	/* make qp RTS */
	if(init_qp(config, &qpinfo) || rtr_qp(config, &qpinfo) || rts_qp(config, &qpinfo)) { printf("rts failed\n"); goto fn_fail; }
    printf("rts done\n"); fflush(stdout);

    /* barrier */
    for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
        if(sock_sync_data(qpinfo.sock[i], 1, "R", &sync_res)) { perror("sock_sync_data"); }
    }
    printf("barrier done\n"); fflush(stdout);

ql_loop:
// set send-value
	send_val = loop_cnt + IBCOM_MAGIC;
	//*((uint32_t *)(loc_mr_list[0].buf + buf_size - sizeof(uint32_t))) = send_val;
	*((uint32_t *)(loc_mr_list[0].buf)) = send_val;

// send/recieve
	if(config.server_flg) { /* sender side */
        //usleep(500000);
        if(NTRIAL % PPOLLS != 0) { printf("set NTRIAL multiple of PPOLLS\n"); goto fn_fail; }
        if(NTRIAL <= NSKIPS) { printf("set NTRIAL > NSKIP\n"); goto fn_fail; }

		for (i = 0; i < NTRIAL; i++) {
            if(i == NSKIPS) { tscs = rdtsc(); }

            post_send_req2(&qpinfo, &loc_mr_list[0], IBV_WR_RDMA_WRITE, &qpinfo.remote_conn_info[0], 0, i);

		}
        tsce = rdtsc(); printf("send_time,%.0f\n", (tsce-tscs)/(double)(NTRIAL-NSKIPS));
		printf("send_val: %x\n", send_val);
		fflush(stdout);
#if 1
        int nfound = 0;
        k = 0;
        while(1) {
            int result;
            struct ibv_wc cqe[NTRIAL];
            result = ibv_poll_cq(qpinfo.scq, NTRIAL, &cqe[0]);
            if(result < 0) { printf("ibv_poll_cq"); goto fn_fail; }
            if(result > 0) {
                for(j = 0; j < result; j++) { 
                    if(cqe[j].status != IBV_WC_SUCCESS) { printf("cqe status,%s\n", ibv_wc_status_str(cqe[j].status)); goto fn_fail; }
                }
                //debug_print_mem((addr_t)loc_mr_list[entry].buf, buf_size);
                nfound += result;
                if(nfound >= NTRIAL) { break; }
            }
            k++;
        }
#endif
	} else { /* receiver side */
		//volatile uint32_t *recv_val = NULL;
        if(NSKIPR % PPOLLR !=0) { printf("set NSKIP multiple of PPOLL\n"); goto fn_fail; }
		for (i = 0; i < NTRIAL; i++) {
            if(i == NSKIPR) { tscs = rdtsc(); }

			// poll on magic
            dprintf("res.rdma_mr.buf=%lx\n", (unsigned long)res.rdma_mr.buf);
            dprintf("poll addr=%lx\n", (unsigned long)(rdma_buf + buf_size * i + buf_size - sizeof(uint32_t)));
            //k = 0;
            //volatile uint32_t *ptr = (volatile uint32_t *)(rdma_buf + buf_size * i + buf_size - sizeof(uint32_t));
            volatile uint32_t *ptr = (volatile uint32_t *)(rdma_buf);
            //*recv_val = *(volatile uint32_t *)(rdma_buf + buf_size * i + buf_size - sizeof(uint32_t));
			printf("*** ptr:%d, MAGIC:%x\n", *ptr, loop_cnt + IBCOM_MAGIC);
            while(*ptr != loop_cnt + IBCOM_MAGIC) {
			//printf("++++ send_val:%x, recv_val:%x\n", send_val, *recv_val);
            //while(*recv_val != send_val) {
                //k++; if(i >= NSKIPR && k % 65536 == 65535) { printf("i=%d,poll value=%x\n", i, *((uint32_t *)(rdma_buf + buf_size * i + buf_size - sizeof(uint32_t)))); }
                __asm__ __volatile__("pause");
				// TIMEOUT
				if (rdtsc() - tscs > 10000000) {
					printf("*** recv wait is TIMEOUT\n");
					break;
				}
            }
			if (*ptr == loop_cnt + IBCOM_MAGIC) {
				printf("[OK] recv_val: 0x%x\n", *ptr);
			} else {
				printf("[NG] recv_val is not correct, expected:0x%x  recv:0x%x\n",
				       loop_cnt + IBCOM_MAGIC, *ptr);
			}
				
		}
        tsce = rdtsc(); printf("recv_time,%.0f\n", (tsce-tscs)/(double)(NTRIAL-NSKIPR));
		//printf("recv_valu:%x\n", *recv_val);
	}

	rc = ql_client(&argc, &argv);
	if (rc == QL_CONTINUE) {
		loop_cnt++;
		printf("ql: go back loop\n");
		goto ql_loop;
	}
	else {
		printf("ql_client returns %d, go to exit\n", rc);
	}

#if 0
// 2nd send/recieve
	if(config.server_flg) { /* sender side */
		// other value
		*((uint32_t *)(loc_mr_list[0].buf + buf_size - sizeof(uint32_t))) = 10 + IBCOM_MAGIC;
        //usleep(500000);
        if(NTRIAL % PPOLLS != 0) { printf("set NTRIAL multiple of PPOLLS\n"); goto fn_fail; }
        if(NTRIAL <= NSKIPS) { printf("set NTRIAL > NSKIP\n"); goto fn_fail; }

		for (i = 0; i < NTRIAL; i++) {
            if(i == NSKIPS) { tscs = rdtsc(); }

            post_send_req2(&qpinfo, &loc_mr_list[0], IBV_WR_RDMA_WRITE, &qpinfo.remote_conn_info[0], 0, i);

		}
#if 1
        int nfound = 0;
        k = 0;
        while(1) {
            int result;
            struct ibv_wc cqe[NTRIAL];
            result = ibv_poll_cq(qpinfo.scq, NTRIAL, &cqe[0]);
            if(result < 0) { printf("ibv_poll_cq"); goto fn_fail; }
            if(result > 0) {
                for(j = 0; j < result; j++) { 
                    if(cqe[j].status != IBV_WC_SUCCESS) { printf("cqe status,%s\n", ibv_wc_status_str(cqe[j].status)); goto fn_fail; }
                }
                //debug_print_mem((addr_t)loc_mr_list[entry].buf, buf_size);
                nfound += result;
                if(nfound >= NTRIAL) { break; }
            }
            k++;
        }
		printf("2nd send is OK!!\n");
#endif
	} else { /* receiver side */
        if(NSKIPR % PPOLLR !=0) { printf("set NSKIP multiple of PPOLL\n"); goto fn_fail; }
		for (i = 0; i < NTRIAL; i++) {
            if(i == NSKIPR) { tscs = rdtsc(); }

			// poll on magic
            dprintf("res.rdma_mr.buf=%lx\n", (unsigned long)res.rdma_mr.buf);
            dprintf("poll addr=%lx\n", (unsigned long)(rdma_buf + buf_size * i + buf_size - sizeof(uint32_t)));
            //k = 0;
            volatile uint32_t *ptr = (volatile uint32_t *)(rdma_buf + buf_size * i + buf_size - sizeof(uint32_t));
            while(*ptr != 10 + IBCOM_MAGIC) {
                //k++; if(i >= NSKIPR && k % 65536 == 65535) { printf("i=%d,poll value=%x\n", i, *((uint32_t *)(rdma_buf + buf_size * i + buf_size - sizeof(uint32_t)))); }
                __asm__ __volatile__("pause");
            }
			//debug_print_mem((addr_t)res.rdma_mr.buf, buf_size);
		}
		printf("2nd revieve is OK!!\n");
	}
#endif

	fn_exit:
	/*Can free all resources*/
#if 0
	if (resource_destroy(&config, &res)) {
		fprintf(stderr, "resource destroy failed\n");
	} else {
		dprintf("destroy all successfully..\n");
	}
	if(loc_mr_list) { free(loc_mr_list); }
#endif
	MPI_Finalize();
	return ibcom_errno;
 fn_fail:
    goto fn_exit;
}

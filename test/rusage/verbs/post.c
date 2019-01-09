#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "ibcomm.h"
#include "debug.h"

//#define DEBUG_POST
#ifdef DEBUG_POST
#define dprintf printf
#else
#define dprintf(...)
#endif

static unsigned long rdtsc() {
    unsigned long x;
    __asm__ __volatile__("xorl %%eax, %%eax; cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx"); /* rdtsc cannot be executed earlier than this */
    __asm__ __volatile__("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(x) : : "memory"); /* rdtsc cannot be executed earlier than here */
    __asm__ __volatile__("xorl %%eax, %%eax; cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx"); /* following instructions cannot be executed earlier than this */
    return x;
}

#define MAX_POLL_TIME (1000000ULL * 1000000)
int swr_id_tag_map[1000];
int rwr_id_tag_map[1000];

void put_swr_id_tag(int wr_id, int tag){
	swr_id_tag_map[wr_id] = tag;
}
int get_swr_id_tag(int wr_id){
	int tag = swr_id_tag_map[wr_id];
	return	tag;
}
void put_rwr_id_tag(int wr_id, int tag){
	rwr_id_tag_map[wr_id] = tag;
}
int get_rwr_id_tag(int wr_id){
	int tag = rwr_id_tag_map[wr_id];
	return	tag;
}
int post_send_req(qpinfo_t *qpinfo, mrinfo_t *mrinfo, int opcode, int tag, qp_conn_info_t* remote_conn_info, uint32_t imm_data){
	struct ibv_send_wr sr, *bad_wr = NULL;
	struct ibv_sge sge[1];
	int ret = 0;

	/* Create sge*/
	sge[0].addr = (uintptr_t)mrinfo->buf;
	sge[0].length = mrinfo->buf_size;
	sge[0].lkey = mrinfo->mr->lkey;

	/* Create a SR */
	memset(&sr, 0, sizeof(struct ibv_send_wr));
	sr.next = NULL;
	sr.wr_id = ++qpinfo->sr_num;
	sr.sg_list = sge;
	sr.num_sge = 1;
	sr.opcode = opcode;
    sr.imm_data = imm_data;
    sr.send_flags = IBV_SEND_SIGNALED;

	if(opcode != IBV_WR_RDMA_READ && mrinfo->buf_size <= qpinfo->max_inline_data) { sr.send_flags |= IBV_SEND_INLINE; }
	put_swr_id_tag(sr.wr_id, tag);

	// set addr and key if is RDMA op
	if(opcode != IBV_WR_SEND){
		sr.wr.rdma.remote_addr = remote_conn_info->addr;
		sr.wr.rdma.rkey = remote_conn_info->rkey;
	}

	/* Post SR to SQ */
	ret = ibv_post_send(qpinfo->qp, &sr, &bad_wr);
	if(ret){
		error_perror("ibv_post_send");
		error_printf("ibv_post_send return %d\n", ret);
		return IBCOMM_ERR_CODE;
	}

	return 0;
}

/* write to addr + sz * seq_num */
int post_send_req2(qpinfo_t *qpinfo, mrinfo_t *mrinfo, int opcode, qp_conn_info_t* remote_conn_info, uint32_t imm_data, uint32_t seq_num) {
	struct ibv_send_wr sr, *bad_wr = NULL;
	struct ibv_sge sge[1];
	int ret = 0;

	/* prepare sge*/
	sge[0].addr = (uintptr_t)mrinfo->buf;
	sge[0].length = mrinfo->buf_size;
	sge[0].lkey = mrinfo->mr->lkey;

    dprintf("post_send_req2,sge[0].addr=%lx,sz=%d\n", (unsigned long)sge[0].addr, sge[0].length = mrinfo->buf_size);

	/* prepare send request or work request */
	//memset(&sr, 0, sizeof(struct ibv_send_wr));
	sr.next = NULL;
	sr.wr_id = 0;
	sr.sg_list = sge;
	sr.num_sge = 1;
	sr.opcode = opcode;
    sr.imm_data = imm_data;
    sr.send_flags = IBV_SEND_SIGNALED;

	if(opcode != IBV_WR_RDMA_READ && mrinfo->buf_size <= qpinfo->max_inline_data) {
        sr.send_flags |= IBV_SEND_INLINE; 
    }

	if(opcode == IBV_WR_RDMA_WRITE || opcode == IBV_WR_RDMA_WRITE_WITH_IMM) {
		sr.wr.rdma.remote_addr = remote_conn_info->addr + IBCOM_RDMABUF_SZSEG * seq_num;
		sr.wr.rdma.rkey = remote_conn_info->rkey;
        dprintf("post_send_req2,raddr=%lx\n", sr.wr.rdma.remote_addr);
	}

    //__asm__ __volatile__("" ::: "memory");

	ret = ibv_post_send(qpinfo->qp, &sr, &bad_wr);
	if(ret){
		printf("ibv_post_send return %d\n", ret);
		return IBCOMM_ERR_CODE;
	}

	return 0;
}

int ibcom_isend_chain(qpinfo_t *qpinfo, mrinfo_t *mrinfo, int opcode, qp_conn_info_t* remote_conn_info, uint32_t imm_data, uint32_t seq_num) {
    int ibcom_errno = 0;
    int ib_errno;
    int i;
	struct ibv_send_wr sr[NCHAIN], *bad_wr = NULL;
	struct ibv_sge sge[NCHAIN];

    for(i = 0; i < NCHAIN; i++) {
        sge[i].addr = (uintptr_t)mrinfo->buf + IBCOM_INLINE_DATA * i;
        sge[i].length = IBCOM_INLINE_DATA;
        sge[i].lkey = mrinfo->mr->lkey;
        
        sr[i].next = (i == NCHAIN - 1) ? NULL : &sr[i+1];
        //sr[i].wr_id = 0;
        sr[i].sg_list = &sge[i];
        sr[i].num_sge = 1;
#define SKIP_POLL_RCQ
#ifdef SKIP_POLL_RCQ /* if you want all to be IBV_WR_RDMA_WRITE */
        sr[i].opcode = opcode;
#else
        sr[i].opcode = (i == NCHAIN - 1) ? IBV_WR_RDMA_WRITE_WITH_IMM : IBV_WR_RDMA_WRITE;
#endif
        sr[i].imm_data = imm_data;
        sr[i].send_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE; 

        sr[i].wr.rdma.remote_addr = remote_conn_info->addr + IBCOM_INLINE_DATA * NCHAIN * seq_num + IBCOM_INLINE_DATA * i;
		sr[i].wr.rdma.rkey = remote_conn_info->rkey;
	}

    ib_errno = ibv_post_send(qpinfo->qp, &sr[0], &bad_wr);
    IBCOM_ERR_CHKANDJUMP(ib_errno, -1, printf("ibv_post_send\n"));

 fn_exit:
	return ibcom_errno;
 fn_fail:
    goto fn_exit;
}

/* write to addr + sz * seq_num */
int post_send_req4(qpinfo_t *qpinfo, mrinfo_t *mrinfo, int opcode, qp_conn_info_t* remote_conn_info, uint32_t imm_data, uint32_t seq_num, uint32_t offset) {
	int ibcom_errno = 0;
    int ib_errno;

	struct ibv_send_wr sr, *bad_wr = NULL;
	struct ibv_sge sge[1];

	sge[0].addr = (uintptr_t)mrinfo->buf + offset;
	sge[0].length = IBCOM_INLINE_DATA;
	sge[0].lkey = mrinfo->mr->lkey;

	sr.next = NULL;
	//sr.wr_id = 0;
	sr.sg_list = sge;
	sr.num_sge = 1;
	sr.opcode = opcode;
    sr.imm_data = imm_data;
    sr.send_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE; 

    sr.wr.rdma.remote_addr = remote_conn_info->addr + IBCOM_INLINE_DATA * seq_num;
    sr.wr.rdma.rkey = remote_conn_info->rkey;

	ib_errno = ibv_post_send(qpinfo->qp, &sr, &bad_wr);
	IBCOM_ERR_CHKANDJUMP(ib_errno, -1, printf("ibv_post_send\n"));

 fn_exit:
	return ibcom_errno;
 fn_fail:
    goto fn_exit;
}

int post_send_req_ud(qpinfo_t *qpinfo, mrinfo_t *mrinfo, int opcode, qp_conn_info_ud_t* remote_conn_info, struct ibv_ah *ah) {
	struct ibv_send_wr sr, *bad_wr;
	struct ibv_sge sge[1];
    int ibcom_errno = 0, ib_errno;
    
	/* Create sge*/
    /* addr to addr + length - 1 will be on the payload, but see "post_send_req_ud" part */
    if(mrinfo->buf_size <= 40) { printf("buf_size too short\n"); ibcom_errno = -1; goto fn_fail; } 

	sge[0].addr = (uintptr_t)mrinfo->buf + 40; 
	sge[0].length = mrinfo->buf_size - 40;
	sge[0].lkey = mrinfo->mr->lkey;

	/* Create a SR */
	//memset(&sr, 0, sizeof(struct ibv_send_wr));
	sr.next = NULL;
	sr.wr_id = 0;
	sr.sg_list = sge;
	sr.num_sge = 1;
	sr.opcode = opcode;
    //sr.imm_data = 0;
    sr.send_flags = IBV_SEND_SIGNALED;

#if 0
	if(mrinfo->buf_size <= qpinfo->max_inline_data){
		sr.send_flags |= IBV_SEND_INLINE;
	}
#endif    

    sr.wr.ud.ah = ah;
    sr.wr.ud.remote_qpn = remote_conn_info->qp_num;
    sr.wr.ud.remote_qkey = remote_conn_info->qkey;
    dprintf("ibv_post_send,qpn=%08x,qkey=%08x\n", sr.wr.ud.remote_qpn, sr.wr.ud.remote_qkey);
    //    printf("ibv_post_send,dlid=%02x,is_global=%02x\n", ah->dlid, ah->is_global);

	ib_errno = ibv_post_send(qpinfo->qp, &sr, &bad_wr);
	if(ib_errno) {
        error_perror("ibv_post_send"); 
        printf("ib_errno=%d\n", ib_errno);
        ibcom_errno = IBCOMM_ERR_CODE;
        goto fn_fail;
    }

 fn_exit:
	return ibcom_errno;
 fn_fail:
    goto fn_exit;
}

int post_recv_req(qpinfo_t *qpinfo, mrinfo_t *mrinfo, int tag){
	struct ibv_recv_wr *rr;
	struct ibv_sge *sge;
	struct ibv_recv_wr *bad_wr;
	int ret = 0;

	/* Prepare scatter/gather entry list */
	sge = malloc(sizeof(struct ibv_sge));
	memset(sge, 0, sizeof(struct ibv_sge));
	sge->addr = (uintptr_t)mrinfo->buf;
	sge->length = mrinfo->buf_size;
	sge->lkey = mrinfo->mr->lkey;

	/* Create RR list */
	rr = malloc(sizeof(*rr));
	memset(rr, 0, sizeof(*rr));
	rr->next = NULL;
	rr->wr_id = ++qpinfo->rr_num;
	rr->sg_list = sge;
	rr->num_sge = 1;
	put_rwr_id_tag(rr->wr_id, tag);

	/* Post RR to RQ */
	ret = ibv_post_recv(qpinfo->qp, rr, &bad_wr);
	if(ret){
		dprintf("ibv_post_recv ret=%d\n", ret);
		free(sge);
		free(rr);
		return IBCOMM_ERR_CODE;
	} else {
		dprintf("ibv_post_recv ret=%d\n", ret);
    }

	free(sge);
	free(rr);
	return 0;
}

int ibcom_irecv(qpinfo_t *qpinfo, uint64_t wr_id){
	struct ibv_recv_wr rr;
	struct ibv_recv_wr *bad_wr;
	int ibcom_errno = 0;
    int ib_errno;

	rr.next = NULL;
	rr.sg_list = NULL;
	rr.num_sge = 0;
	rr.wr_id = wr_id;

	/* post rr */
	ib_errno = ibv_post_recv(qpinfo->qp, &rr, &bad_wr);
	IBCOM_ERR_CHKANDJUMP(ib_errno, -1, printf("ibv_post_recv\n"));

 fn_exit:
	return ibcom_errno;
 fn_fail:
    goto fn_exit;
}

int post_recv_req_ud(qpinfo_t *qpinfo, mrinfo_t *mrinfo, uint64_t wr_id){
	struct ibv_recv_wr rr, *bad_wr;
	struct ibv_sge sge[1];
	int ibcom_errno = 0, ib_errno;

	/* Prepare scatter/gather entry list */
	memset(sge, 0, sizeof(struct ibv_sge));
    /* addr to addr + 39 are not filled, addr + 40 to addr + length - 1 are filled with payload */
    if(mrinfo->buf_size <= 40) { printf("buf_size too short\n"); ibcom_errno = -1; goto fn_fail; } 
	sge[0].addr = (uintptr_t)mrinfo->buf;
	sge[0].length = mrinfo->buf_size;
	sge[0].lkey = mrinfo->mr->lkey;

	/* Create RR list */
	memset(&rr, 0, sizeof(struct ibv_recv_wr));
	rr.next = NULL;
	rr.wr_id = wr_id;
	rr.sg_list = sge;
	rr.num_sge = 1;

	/* Post RR to RQ */
	ib_errno = ibv_post_recv(qpinfo->qp, &rr, &bad_wr);
	if(ib_errno){
		printf("ibv_post_recv ib_errno=%d\n", ib_errno);
		ibcom_errno = IBCOMM_ERR_CODE;
        goto fn_fail;
	}
 fn_exit:
	return ibcom_errno;
 fn_fail:
    goto fn_exit;
}

int poll_cq(qpinfo_t *qpinfo, int cq_flg, int *tag) {
	struct ibv_wc wc;
	int wc_num = 0, time=0, rc = IBCOMM_ERR_CODE;
//	wc = malloc(sizeof(struct ibv_wc));
	memset(&wc, 0, sizeof(struct ibv_wc));

	switch(cq_flg){
		case SEND_CQ_FLG:
			do{
				wc_num = ibv_poll_cq(qpinfo->scq, 1, &wc);
			}while(!wc_num && ++time < MAX_POLL_TIME); 
			break;

		case RECV_CQ_FLG:
			do{
				wc_num = ibv_poll_cq(qpinfo->rcq, 1, &wc);
			}while(!wc_num && ++time < MAX_POLL_TIME); 
			break;
	}

	if(wc_num < 0){
		error_perror("ibv_poll_cq");
		goto poll_cq_exit;
	}
	if(wc_num == 0){
		error_printf("no wc is found\n");
		goto poll_cq_exit;
	}
	if (wc.status != IBV_WC_SUCCESS){
		error_printf("wrong wc state: %d, %s\n", wc.status, ibv_wc_status_str(wc.status));
		goto poll_cq_exit;
	}
	switch(cq_flg){
		case SEND_CQ_FLG:
			*tag = get_swr_id_tag(wc.wr_id);
			break;
		case RECV_CQ_FLG:
			*tag = get_rwr_id_tag(wc.wr_id);
			break;
	}
	rc = 0;
	
	poll_cq_exit:

	return rc;
}

int poll_cq2(qpinfo_t *qpinfo, int cq_flg, int *tag, int *result) {
	struct ibv_wc cqe;
    int rc = 0;

	switch(cq_flg){
    case SEND_CQ_FLG:
        *result = ibv_poll_cq(qpinfo->scq, 1, &cqe);
        break;
        
    case RECV_CQ_FLG:
        *result = ibv_poll_cq(qpinfo->rcq, 1, &cqe);
        break;
	}
    
	if(*result < 0){
		error_perror("ibv_poll_cq");
		rc = *result;
        goto fn_fail;
	}
	if(*result > 0 && cqe.status != IBV_WC_SUCCESS){
		error_printf("cqe status=%08x,%s\n", cqe.status, ibv_wc_status_str(cqe.status));
        rc = -1;
		goto fn_fail;
	}
	if(*result > 0) {
        dprintf("cqe.imm_data=%d\n", cqe.imm_data);
        switch(cq_flg){
        case SEND_CQ_FLG:
            *tag = get_swr_id_tag(cqe.wr_id);
            break;
        case RECV_CQ_FLG:
            *tag = get_rwr_id_tag(cqe.wr_id);
            break;
        }
	}
 fn_exit:
	return rc;
 fn_fail:
    goto fn_exit;
}

int poll_cq2_ud(qpinfo_t *qpinfo, int cq_flg, int *result) {
	struct ibv_wc cqe;
    int rc = 0;

	switch(cq_flg){
    case SEND_CQ_FLG: {
        unsigned long tscs = rdtsc();
        *result = ibv_poll_cq(qpinfo->scq, 1, &cqe);
        unsigned long tsce = rdtsc();
        printf("poll_cq,send,%ld\n", tsce-tscs);
        break; }
    case RECV_CQ_FLG:
        *result = ibv_poll_cq(qpinfo->rcq, 1, &cqe);
        break;
	}
    
	if(*result < 0){
		error_perror("ibv_poll_cq");
		rc = *result;
        goto fn_fail;
	}
	if(*result > 0 && cqe.status != IBV_WC_SUCCESS){
		error_printf("cqe status=%08x,%s\n", cqe.status, ibv_wc_status_str(cqe.status));
        rc = -1;
		goto fn_fail;
	}
 fn_exit:
	return rc;
 fn_fail:
    goto fn_exit;
}

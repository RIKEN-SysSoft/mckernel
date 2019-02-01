#include <stdio.h>
#include <stdlib.h>
#include <asm/byteorder.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "ibcomm.h"
#include "sock.h"
#include "debug.h"

//#define DEBUG_QP
#ifdef DEBUG_QP
#define dprintf printf
#else
#define dprintf(...)
#endif

int connect_qp(config_t config, resource_t *res, qpinfo_t *qpinfo){
	union ibv_gid gid;
	qp_conn_info_t local_conn_info;
	int rc = IBCOMM_ERR_CODE;

	// get GID for this connection
	memset(&gid, 0, sizeof(union ibv_gid));
	if(ibv_query_gid(res->ib_ctx, config.ib_port, config.gid_idx, &gid)){
		error_perror("ibv_query_gid");
		goto connect_qp_exit;
	}
    dprintf("port=%08x\n", config.ib_port);

	// set local qp conn info
	memset(&local_conn_info, 0, sizeof(qp_conn_info_t));
	memset(qpinfo->remote_conn_info, 0, sizeof(qpinfo->remote_conn_info));
	local_conn_info.qp_num = htonl(qpinfo->qp->qp_num);
	local_conn_info.lid = htons(res->port_attr->lid);
	memcpy(local_conn_info.gid, &gid, 16);
    dprintf("qp_num=%08x, lid=%08x\n", local_conn_info.qp_num, local_conn_info.lid);
	
	// set rdma address
	if(config.use_rdma == 1){
		local_conn_info.addr = htonll((uint64_t) res->rdma_mr.mr->addr);
		local_conn_info.rkey = htonl((uint32_t) res->rdma_mr.mr->lkey);
        printf("my lkey=%08x\n", res->rdma_mr.mr->lkey);
        printf("my rkey=%08x\n", res->rdma_mr.mr->rkey);
		//local_conn_info.rkey = htonl((uint32_t) res->rdma_mr.mr->rkey);
	}

    if(config.server_flg) { qpinfo->listenfd = -1; } // if listenfd != -1, then listen(listenfd)
    int i;
    for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
        // server accepts connection from NREMOTE clients
        // NREMOTE clients connect to one server

        // sock connect
        qpinfo->sock[i] = sock_connect(config.server_name, config.tcp_port, &(qpinfo->listenfd));
        if(qpinfo->sock[i] < 0) {
            error_perror("sock_connect"); goto connect_qp_exit;
        }
        dprintf("connect_qp, after sock_connect\n");

        // send local_conn_info, receive remote_conn_info
        if(sock_sync_data(qpinfo->sock[i], sizeof(qp_conn_info_t), (char*)&local_conn_info, (char*)&qpinfo->remote_conn_info[i])){
            error_perror("sock_sync_data");
            goto connect_qp_exit;
        }
        dprintf("connect_qp, after sock_sync_data\n");
        qpinfo->remote_conn_info[i].qp_num = ntohl(qpinfo->remote_conn_info[i].qp_num);
        qpinfo->remote_conn_info[i].lid = ntohs(qpinfo->remote_conn_info[i].lid);
        
        // set rdma address
        if(config.use_rdma == 1){
            qpinfo->remote_conn_info[i].addr = ntohll(qpinfo->remote_conn_info[i].addr);
            qpinfo->remote_conn_info[i].rkey = ntohl(qpinfo->remote_conn_info[i].rkey);
            printf("your rkey=%08x\n", qpinfo->remote_conn_info[i].rkey);
        }
    }        
    rc = 0;

connect_qp_exit:
    if(rc) {
        int i;
        for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
            if(qpinfo->sock[i] > 0) { close(qpinfo->sock[i]); }
        }
    }
	return rc;
}

int init_qp(config_t config, qpinfo_t *qpinfo){
	struct ibv_qp_attr attr;
	int flags;
	int rc = 0;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_INIT;
	attr.port_num = config.ib_port;
	attr.pkey_index = 0;
	attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE;
	if(config.use_rdma)
		attr.qp_access_flags |= IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC;
	
	flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
	if(ibv_modify_qp(qpinfo->qp, &attr, flags)){
		error_perror("ibv_modify_qp");
		rc = IBCOMM_ERR_CODE;
	}
	return rc;
}

int init_qp_ud(config_t config, qpinfo_t *qpinfo){
	struct ibv_qp_attr attr;
	int flags;
	int ibcom_errno = 0, ib_errno;
    
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_INIT;
	attr.port_num = config.ib_port;
	attr.pkey_index = 0;
    attr.qkey = 0x11111111;

	flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_QKEY;

	ib_errno = ibv_modify_qp(qpinfo->qp, &attr, flags);
    if(ib_errno) {
        dprintf("ib_errno=%d\n", ib_errno);
		error_perror("ibv_modify_qp");
		ibcom_errno = IBCOMM_ERR_CODE;
        goto fn_fail;
	}
 fn_exit:
	return ibcom_errno;
 fn_fail:
    goto fn_exit;
}

int rtr_qp(config_t config, qpinfo_t *qpinfo){
	struct ibv_qp_attr attr;
	int flags;
	int rc = 0;
	
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTR;
	attr.path_mtu = IBV_MTU_2048/*IBV_MTU_2048*//*IBV_MTU_512*/;
	attr.ah_attr.dlid = qpinfo->remote_conn_info[0].lid;
	attr.ah_attr.port_num = config.ib_port;
	attr.dest_qp_num = qpinfo->remote_conn_info[0].qp_num;
	attr.rq_psn = 0;
	attr.min_rnr_timer = 0x12;
	attr.max_dest_rd_atomic = /*0*/1;

	if(config.use_rdma)
		attr.max_dest_rd_atomic = 1;

	flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
	if(ibv_modify_qp(qpinfo->qp, &attr, flags)){
		error_perror("ibv_modify_qp");
		rc = IBCOMM_ERR_CODE;
	}
	return rc;
}

int rtr_qp_ud(config_t config, qpinfo_t *qpinfo){
	struct ibv_qp_attr attr;
	int flags;
	int ibcom_errno = 0, ib_errno;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTR;

	flags = IBV_QP_STATE;
	ib_errno = ibv_modify_qp(qpinfo->qp, &attr, flags);
    if(ib_errno) { error_perror("ibv_modify_qp"); ibcom_errno = IBCOMM_ERR_CODE; goto fn_fail; }

 fn_exit:
	return ibcom_errno;
 fn_fail:
    goto fn_exit;
}

int rts_qp(config_t config, qpinfo_t *qpinfo){
	struct ibv_qp_attr attr;
	int flags;
	int rc = 0;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.timeout = 0x14;
	attr.retry_cnt = 7;
	attr.rnr_retry = 7;
	attr.sq_psn = 0;
	attr.max_rd_atomic = /*0*/1; // num of outstanding RDMA reads and atomic op allowed
	if(config.use_rdma)
		attr.max_rd_atomic = 1;

	flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
	
	if(ibv_modify_qp(qpinfo->qp, &attr, flags)){
		error_perror("ibv_modify_qp");
		rc = IBCOMM_ERR_CODE;
	}
	return rc;
}

int rts_qp_ud(config_t config, qpinfo_t *qpinfo){
	struct ibv_qp_attr attr;
	int flags;
	int ibcom_errno = 0, ib_errno;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.sq_psn = 0;

	flags = IBV_QP_STATE | IBV_QP_SQ_PSN;
	
	ib_errno = ibv_modify_qp(qpinfo->qp, &attr, flags);
    if(ib_errno) { error_perror("ibv_modify_qp"); ibcom_errno = IBCOMM_ERR_CODE; goto fn_fail; }
 fn_exit:
	return ibcom_errno;
 fn_fail:
    goto fn_exit;
}

/* modify address vector and dest qpn and reset sq_psn */
int modify_dest_qp(config_t config, qpinfo_t *qpinfo, qp_conn_info_t* remote_conn_info){
	struct ibv_qp_attr attr;
	int flags;
	int rc = 0;
	
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.ah_attr.dlid = remote_conn_info->lid;
	attr.ah_attr.port_num = config.ib_port;
	attr.dest_qp_num = remote_conn_info->qp_num;
	attr.sq_psn = 0;

	attr.max_rd_atomic = 0;
	attr.retry_cnt = 7;
	attr.rnr_retry = 7;
	attr.timeout = 0x14;

#if 0
	flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_DEST_QPN | IBV_QP_SQ_PSN |
        IBV_QP_MAX_QP_RD_ATOMIC |
        IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_TIMEOUT;
#else
	flags = IBV_QP_STATE | IBV_QP_AV;
#endif

	if(ibv_modify_qp(qpinfo->qp, &attr, flags)){
		error_perror("ibv_modify_qp");
		rc = IBCOMM_ERR_CODE;
	}
	return rc;
}

void print_qp_status(qpinfo_t *qpinfo){
	struct ibv_qp_attr *attr;
	struct ibv_qp_init_attr *init_attr;
	int	flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
	int rc;
	
	attr = malloc(sizeof(struct ibv_qp_attr));
	init_attr = malloc(sizeof(struct ibv_qp_init_attr));

	rc = ibv_query_qp(qpinfo->qp, attr, flags, init_attr);
	if(rc){
		fprintf(stderr, "query qp error\n");	
	}
	else{
		switch(attr->cur_qp_state){
			case IBV_QPS_RESET:
				dprintf("attr=IBV_QPS_RESET\n");
				break;
			case IBV_QPS_INIT:
				dprintf("attr=IBV_QPS_INIT\n");
				break;
			case IBV_QPS_RTR:
				dprintf("attr=IBV_QPS_RTR\n");
				break;
			case IBV_QPS_RTS:
				dprintf("attr=IBV_QPS_RTS\n");
				break;
			case IBV_QPS_SQD:
				dprintf("attr=IBV_QPS_SQD\n");
				break;
			case IBV_QPS_SQE:
				dprintf("attr=IBV_QPS_SQE\n");
				break;
			case IBV_QPS_ERR:
				dprintf("attr=IBV_QPS_ERR\n");
				break;
		}
	}
	free(attr);
	free(init_attr);
}


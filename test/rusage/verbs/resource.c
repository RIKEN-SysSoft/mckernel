#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ibcomm.h"
#include "debug.h"
#include "list.h"
#include <infiniband/verbs.h>

//#define DEBUG_RESOURCE
#ifdef DEBUG_RESOURCE
#define dprintf printf
#else
#define dprintf(...)
#endif

int resource_create(config_t config, resource_t *res){
	struct ibv_device **dev_list = NULL, *ib_dev = NULL;
	int dev_num;
	int i, rc = IBCOMM_ERR_CODE;

	/*Init*/
	memset(res, 0, sizeof(resource_t));
	res->pdinfo_list = malloc(sizeof(list_t));
	res->qpinfo_list = malloc(sizeof(list_t));
	res->mrinfo_list = malloc(sizeof(list_t));

	res->ib_ctx = NULL;
	res->port_attr = NULL;

	/*Get IB device list*/
	dev_list = ibv_get_device_list(&dev_num);
    printf("resource_create,dev_num=%d\n", dev_num);
	ERR_CHKANDJUMP(!dev_list, -1, error_perror("ibv_get_device_list"));
	if(!dev_num){
		error_printf("no devices are found\n");
		goto resource_create_exit;
	}
	/*Find requested HCA*/
	if(!config.dev_name) {
		config.dev_name = strdup(ibv_get_device_name(dev_list[0]));
    }
    printf("Trying to open device %s\n", config.dev_name);
	for(i=0; i< dev_num; i++){
		if(!strcmp(ibv_get_device_name(dev_list[i]), config.dev_name)){
			ib_dev = dev_list[i];
			break;
		}
	}
	if(ib_dev == NULL){
		error_printf("no devices are found\n");
		goto resource_create_exit;
	}
	/*Open HCA*/
	res->ib_ctx = ibv_open_device(ib_dev);
	if(!res->ib_ctx){
		error_perror("resource_create,ibv_open_device");
		goto resource_create_exit;
	}

    struct ibv_device_attr device_attr;
    int ib_errno;
    ib_errno = ibv_query_device(res->ib_ctx, &device_attr);
    if(ib_errno) { printf("ibv_query_device failed\n"); goto resource_create_exit; }
    printf("atomic_cap=%08x\n", device_attr.atomic_cap);
    printf("max_qp_rd_atom=%08x\n", device_attr.max_qp_rd_atom);
    printf("max_ee_rd_atom=%08x\n", device_attr.max_ee_rd_atom);
    printf("max_res_rd_atom=%08x\n", device_attr.max_res_rd_atom);
    printf("max_qp_init_rd_atom=%08x\n", device_attr.max_qp_init_rd_atom);
    printf("max_ee_init_rd_atom=%08x\n", device_attr.max_ee_init_rd_atom);

	/*Query Port Attr*/
	res->port_attr = malloc(sizeof(struct ibv_port_attr));
	memset(res->port_attr, 0 , sizeof(struct ibv_port_attr));
	if(ibv_query_port(res->ib_ctx, config.ib_port, res->port_attr)){
		error_perror("ibv_query_port");
		goto resource_create_exit;
	}
    printf("res->port_attr.max_msg_sz=%d\n", res->port_attr->max_msg_sz);
	rc = 0;

 fn_exit:
	return rc;
 fn_fail:
 resource_create_exit:
		/*if error, destroy HCA handle*/
		if(rc){
			if(res->ib_ctx){
				ibv_close_device(res->ib_ctx);
				res->ib_ctx = NULL;
			}
			if(res->port_attr){
				free(res->port_attr);
			}
			res = NULL;
		}
		// free other
		ib_dev = NULL;
		if(dev_list){
			ibv_free_device_list(dev_list);
			dev_list = NULL;
		}
        goto fn_exit;
}

int pd_create(resource_t *res, pdinfo_t *pdinfo){
	int rc = IBCOMM_ERR_CODE;

	/*Init*/
	memset(pdinfo, 0, sizeof(pdinfo_t));
	pdinfo->pd = NULL;

	/*Alloc on HCA handle*/
	pdinfo->pd = ibv_alloc_pd(res->ib_ctx);
	if(pdinfo->pd == NULL){
		error_perror("ibv_alloc_pd");
		goto pd_create_exit;
	}

	/*Register to res*/
	list_add(res->pdinfo_list, pdinfo);
	rc = 0;

	pd_create_exit:
		if(rc)
			pdinfo = NULL;

	return rc;
}

int qp_create(resource_t *res, pdinfo_t *pdinfo, qpinfo_t *qpinfo){
	struct ibv_qp_init_attr qp_init_attr;
	int rc = IBCOMM_ERR_CODE;
    int ibv_errno;

	/*Init*/
	memset(qpinfo, 0, sizeof(qpinfo_t));
    int i;
    for(i = 0; i < NREMOTE; i++) {
        qpinfo->sock[i] = -1; // not connected
    }
	qpinfo->sr_num = 0;
	qpinfo->rr_num = 0;

	/*Create cq*/
	qpinfo->scq = ibv_create_cq(res->ib_ctx, _MAX_CQ_CAPACITY, NULL, NULL, 0);
	qpinfo->rcq = ibv_create_cq(res->ib_ctx, _MAX_CQ_CAPACITY, NULL, NULL, 0);
	if(!qpinfo->scq || !qpinfo->rcq){
		error_perror("qp_create,ibv_create_cq");
		goto qp_create_exit;
	}

	/*Create qp*/
	memset(&qp_init_attr, 0, sizeof(struct ibv_qp_init_attr));
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.sq_sig_all = 1;
	qp_init_attr.send_cq = qpinfo->scq;
	qp_init_attr.recv_cq = qpinfo->rcq;
	// max SR/RR num in SQ/RQ
	qp_init_attr.cap.max_send_wr = _MAX_SQ_CAPACITY;
	qp_init_attr.cap.max_recv_wr = _MAX_RQ_CAPACITY;
	// max SGE num
	qp_init_attr.cap.max_send_sge = _MAX_SGE_CAPACITY;
	qp_init_attr.cap.max_recv_sge = _MAX_SGE_CAPACITY;
    qp_init_attr.cap.max_inline_data = IBCOM_INLINE_DATA;
#if 0
    ibv_errno = show_resident(0);
#endif
	qpinfo->qp = ibv_create_qp(pdinfo->pd, &qp_init_attr);
	if(qpinfo->qp == NULL){
		error_perror("ibv_create_qp");
		goto qp_create_exit;
	}
#if 0
    ibv_errno = show_resident(1);
	qpinfo->qp = ibv_create_qp(pdinfo->pd, &qp_init_attr);
    ibv_errno = show_resident(2);
	qpinfo->qp = ibv_create_qp(pdinfo->pd, &qp_init_attr);
    ibv_errno = show_resident(3);
	qpinfo->qp = ibv_create_qp(pdinfo->pd, &qp_init_attr);
    ibv_errno = show_resident(4);
	qpinfo->qp = ibv_create_qp(pdinfo->pd, &qp_init_attr);
    ibv_errno = show_resident(5);
	qpinfo->qp = ibv_create_qp(pdinfo->pd, &qp_init_attr);
    ibv_errno = show_resident(6);
#endif

	qpinfo->max_inline_data = qp_init_attr.cap.max_inline_data;
    printf("max_send_wr=%d,max_recv_wr=%d,inline_data=%d,max_send_sge=%d,max_recv_sge=%d\n", qp_init_attr.cap.max_send_wr, qp_init_attr.cap.max_recv_wr, qp_init_attr.cap.max_inline_data, qp_init_attr.cap.max_send_sge, qp_init_attr.cap.max_recv_sge);

	/*Register to res*/
	list_add(res->qpinfo_list, qpinfo);
	rc = 0;

	qp_create_exit:
		if(rc){
			if(qpinfo->scq){
				ibv_destroy_cq(qpinfo->scq);
				qpinfo->scq = NULL;
			}
			if(qpinfo->rcq){
				ibv_destroy_cq(qpinfo->rcq);
				qpinfo->rcq = NULL;
			}
			if(qpinfo->qp){
				ibv_destroy_qp(qpinfo->qp);
				qpinfo->qp = NULL;
			}
			qpinfo = NULL;
		}
 fn_exit:
	return rc;
 fn_fail:
    goto fn_exit;
}

int qp_create_ud(resource_t *res, pdinfo_t *pdinfo, qpinfo_t *qpinfo){
	struct ibv_qp_init_attr qp_init_attr;
	int rc = IBCOMM_ERR_CODE;
    int ibv_errno;

	/*Init*/
	memset(qpinfo, 0, sizeof(qpinfo_t));
    int i;
    for(i = 0; i < NREMOTE; i++) {
        qpinfo->sock[i] = -1; // not connected
    }
	qpinfo->sr_num = 0;
	qpinfo->rr_num = 0;

	/*Create cq*/
	qpinfo->scq = ibv_create_cq(res->ib_ctx, _MAX_CQ_CAPACITY, NULL, NULL, 0);
	qpinfo->rcq = ibv_create_cq(res->ib_ctx, _MAX_CQ_CAPACITY, NULL, NULL, 0);
	if(!qpinfo->scq || !qpinfo->rcq){
		error_perror("ibv_create_cq");
		goto qp_create_exit;
	}

	/*Create qp*/
	memset(&qp_init_attr, 0, sizeof(struct ibv_qp_init_attr));
	qp_init_attr.qp_type = IBV_QPT_UD;
	//qp_init_attr.sq_sig_all = 1;
	qp_init_attr.send_cq = qpinfo->scq;
	qp_init_attr.recv_cq = qpinfo->rcq;
	// max SR/RR num in SQ/RQ
	qp_init_attr.cap.max_send_wr = _MAX_SQ_CAPACITY;
	qp_init_attr.cap.max_recv_wr = _MAX_RQ_CAPACITY;
	// max SGE num
	qp_init_attr.cap.max_send_sge = _MAX_SGE_CAPACITY;
	qp_init_attr.cap.max_recv_sge = _MAX_SGE_CAPACITY;

	qpinfo->qp = ibv_create_qp(pdinfo->pd, &qp_init_attr);
	if(qpinfo->qp == NULL){
		error_perror("ibv_create_qp");
		goto qp_create_exit;
	}
	qpinfo->max_inline_data = qp_init_attr.cap.max_inline_data;
    printf("max_send_wr=%d,max_recv_wr=%d,max_send_sge=%d,max_recv_sge=%d,\n", qp_init_attr.cap.max_send_wr, qp_init_attr.cap.max_recv_wr, qp_init_attr.cap.max_send_sge, qp_init_attr.cap.max_recv_sge);

	/*Register to res*/
	list_add(res->qpinfo_list, qpinfo);
	rc = 0;

	qp_create_exit:
		if(rc){
			if(qpinfo->scq){
				ibv_destroy_cq(qpinfo->scq);
				qpinfo->scq = NULL;
			}
			if(qpinfo->rcq){
				ibv_destroy_cq(qpinfo->rcq);
				qpinfo->rcq = NULL;
			}
			if(qpinfo->qp){
				ibv_destroy_qp(qpinfo->qp);
				qpinfo->qp = NULL;
			}
			qpinfo = NULL;
		}
	return rc;
}

int mr_create(resource_t *res, pdinfo_t *pdinfo, int buf_size, char *buf, mrinfo_t *mrinfo) {
	int mr_flags;
	int rc = IBCOMM_ERR_CODE;

	/*Init*/
	memset(mrinfo, 0, sizeof(mrinfo_t));
	mrinfo->buf = buf;
	mrinfo->buf_size = buf_size;
    dprintf("mr_create,mrinfo->buf=%lx\n", (unsigned long)mrinfo->buf);

	/*Create mr*/
	mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC;
	mrinfo->mr = ibv_reg_mr(pdinfo->pd, buf, buf_size, mr_flags);
	if(mrinfo->mr == NULL){
		perror("ibv_reg_mr");
		goto mr_create_exit;
	}

	/*Register to res*/
	list_add(res->mrinfo_list, mrinfo);
	rc = 0;

 mr_create_exit:
    if(rc) {
        if(mrinfo->mr) { ibv_dereg_mr(mrinfo->mr); }
        if(mrinfo) { mrinfo = NULL; }
    }
	return rc;
}

int resource_destroy(config_t *config, resource_t *res){
	int rc = 0;

	//config.dev_name
	if(config->dev_name){
		free(config->dev_name);
	}
	// qp
	qpinfo_t *qpinfo = NULL;
	while((qpinfo = (qpinfo_t *)list_pop(res->qpinfo_list)) != NULL){
		// qp
		if(qpinfo->qp && ibv_destroy_qp(qpinfo->qp)){
			error_perror("ibv_destroy_qp");
			rc = IBCOMM_ERR_CODE;
		}
		qpinfo->qp = NULL;
		// scq
		if(qpinfo->scq && ibv_destroy_cq(qpinfo->scq)){
			error_perror("ibv_destroy_cq");
			rc = IBCOMM_ERR_CODE;
		}
		qpinfo->scq = NULL;
		// rcq
		if(qpinfo->rcq && ibv_destroy_cq(qpinfo->rcq)){
			error_perror("ibv_destroy_cq");
			rc = IBCOMM_ERR_CODE;
		}
		qpinfo->rcq = NULL;
		// sock
        int i;
        for(i = 0; i < (config->server_flg ? config->nremote : 1); i++) {
            if(qpinfo->sock[i] >= 0 && close(qpinfo->sock[i])){
                error_perror("close");
                rc = IBCOMM_ERR_CODE;
            }
        }
		qpinfo = NULL;
	}

	// mr
	mrinfo_t *mrinfo = NULL;
	while ((mrinfo = (mrinfo_t *) list_pop(res->mrinfo_list)) != NULL) {
		if (mrinfo->mr && ibv_dereg_mr(mrinfo->mr)) {
			error_perror("ibv_dereg_mr");
			rc = IBCOMM_ERR_CODE;
		}
		mrinfo->mr = NULL;
		if (mrinfo->buf) {
			if (config->pci_buf_flg) {
				//aal_host_mem_free(mrinfo->buf);
			} else {
				munmap(mrinfo->buf, mrinfo->buf_size);
			}
		}
		mrinfo = NULL;
	}
	// pd
	pdinfo_t *pdinfo = NULL;
	while((pdinfo = (pdinfo_t *)list_pop(res->pdinfo_list)) != NULL){
		if(pdinfo->pd && ibv_dealloc_pd(pdinfo->pd)){
			error_perror("ibv_dealloc_pd");
			rc = IBCOMM_ERR_CODE;
		}
		pdinfo = NULL;
	}

	if (res->ib_ctx && ibv_close_device(res->ib_ctx)) {
		error_perror("ibv_close_device");
		rc = IBCOMM_ERR_CODE;
	}
	if(res->port_attr){
		free(res->port_attr);
	}
	res = NULL;

	return rc;
}


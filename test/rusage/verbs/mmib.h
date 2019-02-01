/*
 * mmib.h
 *
 *  Created on: 2011/10/19
 *      Author: simin
 */

#ifndef MMIB_H_
#define MMIB_H_

#include "mtype.h"
#include "ibcomm.h"

enum mmib_buf_type{
	MMIB_MR_BUF,
	MMIB_CQ_BUF,
	MMIB_QP_BUF,
};
enum mmib_buf_pool_state{
	MMIB_BUF_POOL_RESET,
	MMIB_BUF_POOL_ACTIVE
};

struct mmib_buf_pool{
	addr_t offset;
	int page_no; // start page_no
	int size;
	addr_t cur_start; // offset in page
	enum mmib_buf_pool_state state;
};

typedef struct mmib_mrinfo{
	struct ibv_mr *mr;
	buf_t *buf; /*Registered buf*/
}mmib_mrinfo_t;

extern int mmib_pool_init();
extern buf_t *mmib_new_buf(int size, enum mmib_buf_type buf_type);
extern void mmib_destroy_buf(buf_t *buf);
extern void mmib_pool_destroy();

extern void* mmib_qp_buf_alloc(int size);
extern void* mmib_cq_buf_alloc(int size);
extern void mmib_buf_free(void* buf);

extern int mmib_resource_create(config_t config, resource_t *res);
extern int mmib_pd_create(resource_t *res, pdinfo_t *pdinfo);
extern int mmib_qp_create(resource_t *res, pdinfo_t *pdinfo, qpinfo_t *qpinfo);
extern int mmib_mr_create(resource_t *res, pdinfo_t *pdinfo, buf_t *buf, mmib_mrinfo_t *mrinfo);
extern int mmib_post_send_req(qpinfo_t *qpinfo, mmib_mrinfo_t *mrinfo_list, int opcode, int tag);
extern int mmib_post_recv_req(qpinfo_t *qpinfo, mmib_mrinfo_t *mrinfo_list, int tag);
extern int mmib_poll_cq(qpinfo_t *qpinfo, int cq_flg, int *tag);
extern int mmib_resource_destroy(config_t *config, resource_t *res);
#endif /* MMIB_H_ */

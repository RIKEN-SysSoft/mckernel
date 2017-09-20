#ifndef IBCOMM_H
#define IBCOMM_H
#include <byteswap.h>
#include "infiniband/verbs.h"
#include "sock.h"
#include "list.h"

#define _MAX_FIX_BUF_SIZE 64
#define _MAX_SQ_CAPACITY /*512*/256/*12*/
#define _MAX_RQ_CAPACITY /*512*/256/*1*/
#define _MAX_SGE_CAPACITY /*20*/3
#define _MAX_CQ_CAPACITY /*512*/256/*1*/

#define IBCOM_INLINE_DATA /*(128*4-64)*//*(512-64)*//*884*/512
#define IBCOM_RDMABUF_SZSEG (16384+4096)
#define IBCOM_MAGIC 0x55aa55aa
#define NCHAIN 2

#define SEND_CQ_FLG 1
#define RECV_CQ_FLG 2
#define IBCOMM_ERR_CODE -1

#define ibcomm_return_code_num 30

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

/* ERROR definition*/
enum ibcomm_return_code{
	_IBCOMM_RETCODE_SUCCESS ,
	_IBCOMM_ERRCODE_DEVICE_FOUND,
	_IBCOMM_ERRCODE_NO_DEVICE,
	_IBCOMM_ERRCODE_DEVICE_OPEN,
	_IBCOMM_ERRCODE_CREATE_RES,
	_IBCOMM_ERRCODE_DEVICE_QUERY_PORT,

	_IBCOMM_ERRCODE_PD_ALLOC,
	_IBCOMM_ERRCODE_CQ_CREATE,
	_IBCOMM_ERRCODE_QP_CREATE,
	_IBCOMM_ERRCODE_MR_CREATE,

	_IBCOMM_ERRCODE_QP_DESTROY,
	_IBCOMM_ERRCODE_CQ_DESTROY,
	_IBCOMM_ERRCODE_MR_DESTROY,
	_IBCOMM_ERRCODE_PD_DEALLOC,
	_IBCOMM_ERRCODE_DEVICE_CLOSE,

	_IBCOMM_ERRCODE_SOCK_CONN,
	_IBCOMM_ERRCODE_SOCK_SYNC,
	_IBCOMM_ERRCODE_SOCK_CLOSE,

	_IBCOMM_ERRCODE_QP_QUERY_GID,
	_IBCOMM_ERRCODE_INIT_QP,
	_IBCOMM_ERRCODE_RTR_QP,
	_IBCOMM_ERRCODE_RTS_QP,

	_IBCOMM_ERRCODE_POLL_CQ_ERR,
	_IBCOMM_ERRCODE_POLL_CQ_ZERO_RESULT
};
typedef struct config{
	char *dev_name; /*IB device name*/
	char *server_name; /*server host name*/
	u_int32_t tcp_port; /*server TCP port*/
	int ib_port; /*local IB port*/
	int gid_idx; /*gid index*/
	int use_rdma; /*rdma flag*/
	int buf_size;
	int server_flg;
	int pci_buf_flg;
	int pci_cq_flg;
    int nremote; /* number of remote nodes */
}config_t;

typedef struct qp_conn_info{
	uint64_t addr; /*Buffer address*/
	uint32_t rkey; /*Remote key*/
	uint32_t qp_num; /*QP number*/
	uint16_t lid; /*LID of the IB port*/
	uint8_t gid[16];/*GID of the IB port*/
}qp_conn_info_t;

typedef struct qp_conn_info_ud{
	uint16_t lid;
	union ibv_gid gid;
	uint32_t qp_num;
	uint32_t qkey;
} qp_conn_info_ud_t;

typedef struct mrinfo{
	struct ibv_mr *mr;
	char *buf; /*Registered buf*/
	int buf_size;
}mrinfo_t;

#define NREMOTE 4
typedef struct qpinfo{
	struct ibv_qp *qp;
	struct ibv_cq *scq; /*Send cq*/
	struct ibv_cq *rcq; /*Receive cq*/
	qp_conn_info_t remote_conn_info[NREMOTE]; /*Remote info*/
	int sock[NREMOTE]; /* exchange remote_conn_info using TCP */
    int listenfd; /* exchange remote_conn_info using TCP */
	int sr_num;
	int rr_num;
	int max_inline_data; /*if data smaller than it, use inline send*/
}qpinfo_t;

typedef struct pdinfo{
	struct ibv_pd *pd;
}pdinfo_t;

typedef struct resource{
	struct ibv_context *ib_ctx;/*HCA handle*/
	struct ibv_port_attr *port_attr; /*IB port attributes*/

	list_t *pdinfo_list;
	list_t *mrinfo_list;
	list_t *qpinfo_list;

	/* RDMA buffers */
	mrinfo_t rdma_mr;
}resource_t;

/**
 * create resource 
 * connect TCP socket
 */
extern int resource_create(config_t config, resource_t *res);

/**
 * create a pd and register it to resource
 */
extern int pd_create(resource_t *res, pdinfo_t *pdinfo);

/**
 * creete a qp and register it to pd
 *	-create send cq
 *	-create recv cq
 *	-assign send cq to sq
 *	-assign recv cq to rq
 */
extern int qp_create(resource_t *res, pdinfo_t *pdinfo, qpinfo_t *qpinfo);
extern int qp_create_ud(resource_t *res, pdinfo_t *pdinfo, qpinfo_t *qpinfo);

/**
 * 1.create a mr and register it to pd
 * 2.register buf to this mr
 */
extern int mr_create(resource_t *res, pdinfo_t *pdinfo, int buf_size, char *buf, mrinfo_t *mrinfo);
/**
 * destroy all resources
 */
extern int resource_destroy(config_t *config, resource_t *res);


/**
 * connect to remote qp by exchanging addr info 
 */
extern int connect_qp(config_t config, resource_t *res, qpinfo_t *qpinfo);

/**
 * change qp status
 */
extern int init_qp(config_t config, qpinfo_t *qpinfo);
extern int init_qp_ud(config_t config, qpinfo_t *qpinfo);

extern int rtr_qp(config_t config, qpinfo_t *qpinfo);
extern int rtr_qp_ud(config_t config, qpinfo_t *qpinfo);

extern int rts_qp(config_t config, qpinfo_t *qpinfo);
extern int rts_qp_ud(config_t config, qpinfo_t *qpinfo);

extern int modify_dest_qp(config_t config, qpinfo_t *qpinfo, qp_conn_info_t* remote_conn_info);

extern int post_send_req(qpinfo_t *qpinfo, mrinfo_t *mrinfo, int opcode, int tag, qp_conn_info_t* remote_conn_info, uint32_t imm_data);
int post_send_req2(qpinfo_t *qpinfo, mrinfo_t *mrinfo, int opcode, qp_conn_info_t* remote_conn_info, uint32_t imm_data, uint32_t seq_num);
extern int post_send_req_ud(qpinfo_t *qpinfo, mrinfo_t *mrinfo, int opcode, qp_conn_info_ud_t* remote_conn_info, struct ibv_ah *ah);

extern int post_recv_req(qpinfo_t *qpinfo, mrinfo_t *mrinfo_list, int tag);
extern int post_recv_req_ud(qpinfo_t *qpinfo, mrinfo_t *mrinfo, uint64_t wr_id);

extern int poll_cq(qpinfo_t *qpinfo, int cq_flg, int *tag);
extern int poll_cq2(qpinfo_t *qpinfo, int cq_flg, int *tag, int *result);
extern int poll_cq2_ud(qpinfo_t *qpinfo, int cq_flg, int *result);

extern void print_qp_status(qpinfo_t *qpinfo);

extern void debug_print_qp_conn_info(resource_t res, qpinfo_t qpinfo, config_t *config);
extern int read_config(config_t *config, int argc, char **argv);
#endif

#define ERR_CHKANDJUMP(cond, errno, stmt) if(cond) { stmt; rc = errno; goto fn_fail; }
#define IBCOM_ERR_CHKANDJUMP(cond, errno, stmt) if(cond) { stmt; ibcom_errno = errno; goto fn_fail; }
#define VERBS_ERR_CHKANDJUMP(cond, errno, stmt) if(cond) { stmt; verbs_errno = errno; goto fn_fail; }

static inline int show_resident(int step) {
    unsigned long size, resident, share, text, lib, data, dirty;
    FILE* fp = fopen("/proc/self/statm", "r");
    fscanf(fp, "%ld %ld %ld %ld %ld %ld %ld", &size, &resident, &share, &text, &lib, &data, &dirty);
    printf("step=%d,resident=%ldKB\n", step, resident * 4);
    return 0;
}

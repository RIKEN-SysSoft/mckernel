#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "ibcomm.h"
#include "debug.h"

//#define DEBUG_DEBUG
#ifdef DEBUG_DEBUG
#define dprintf printf
#else
#define dprintf(...)
#endif

void debug_print_qp_conn_info(resource_t res, qpinfo_t qpinfo, config_t *config) {
	uint8_t *p;
	dprintf("local.qp_num=0x%x\n", qpinfo.qp->qp_num);
	dprintf("local.lid=0x%x\n", res.port_attr->lid);
	dprintf("local.sock[0]=%d\n", qpinfo.sock[0]);
	if (res.rdma_mr.mr != NULL) {
		dprintf("local.addr=0x%lx\n", (uint64_t)res.rdma_mr.buf);
		dprintf("local.rkey=0x%x\n\n", res.rdma_mr.mr->rkey);
	}

    int i;
    for(i = 0; i < (qpinfo.listenfd == -1 ? 1 : config->nremote); i++) {
        dprintf("remote.qp_num=0x%x\n", qpinfo.remote_conn_info[i].qp_num);
        dprintf("remote.lid=0x%x\n", qpinfo.remote_conn_info[i].lid);
        p = qpinfo.remote_conn_info[i].gid;
        dprintf(
                     "remote.gid = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                     p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
        if (qpinfo.remote_conn_info[i].addr) {
            dprintf("remote.addr=0x%lx\n", qpinfo.remote_conn_info[i].addr);
            dprintf("remote.rkey=0x%x\n", qpinfo.remote_conn_info[i].rkey);
        }
    }
}


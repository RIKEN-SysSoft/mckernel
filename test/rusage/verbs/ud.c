#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include "ibcomm.h"
#include "debug.h"
#include "mtype.h"
#include "mm_ib_test.h"

//#define DEBUG_UD
#ifdef DEBUG_UD
#define dprintf printf
#else
#define dprintf(...)
#endif

#define MAX2(x,y) ((x) > (y) ? (x) : (y))
#define SERVER_BUF_NUM TEST_SERVER_BUF_NUM
#define NTRIAL 120
#define PPOLLS 10 /* sweet spot is around 10 */
#define NSKIPS (PPOLLS*1)
#define PPOLLR 10 /* sweet spot is around 10 */
#define NSKIPR (PPOLLR*1)

static unsigned long rdtsc() {
    unsigned long x;
    __asm__ __volatile__("xorl %%eax, %%eax; cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx"); /* rdtsc cannot be executed earlier than this */
    __asm__ __volatile__("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(x) : : "memory"); /* rdtsc cannot be executed earlier than here */
    __asm__ __volatile__("xorl %%eax, %%eax; cpuid;" : : : "%rax", "%rbx", "%rcx", "%rdx"); /* following instructions cannot be executed earlier than this */
    return x;
}

int main(int argc, char **argv) {
	config_t config;
	int i, j, k;
	char sync_res;
	resource_t res;
	pdinfo_t pdinfo;
	qpinfo_t qpinfo;
	mrinfo_t *mrinfo_send_list = NULL, *mrinfo_recv_list = NULL;
    int ibv_errno, ibcom_errno, verbs_errno = 0;
    unsigned long tscs, tsce, tscs2, tsce2;

    FILE* fp;
    fp = popen("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if(!fp) { printf("popen failed\n"); goto fn_fail; }
    char freq_str[256];
    int nread = fread(freq_str, sizeof(char), 256, fp);
    if(!nread) { printf("popen failed"); goto fn_fail; }
    freq_str[nread] = 0;
    long int freq = strtol(freq_str, NULL, 10) * 1000;
    printf("freq=%ld\n", freq);
    pclose(fp);

	ibcom_errno = read_config(&config, argc, argv);
    if(ibcom_errno) { printf("read_config\n"); goto fn_fail; }
    
    ibcom_errno = resource_create(config, &res);
    if(ibcom_errno) { printf("resource_create\n"); goto fn_fail; }

	ibcom_errno = pd_create(&res, &pdinfo);
    if(ibcom_errno) { printf("pd_create\n"); goto fn_fail; }
    
    ibcom_errno = qp_create_ud(&res, &pdinfo, &qpinfo);
    if(ibcom_errno) { printf("qp_create_ud\n"); goto fn_fail; }

	ibcom_errno = init_qp_ud(config, &qpinfo);
    if(ibcom_errno) { printf("init_qp_ud\n"); goto fn_fail; }

    /* prepare local lid, gid, qpn, qkey */
    qp_conn_info_ud_t local_conn_info, remote_conn_info;

    struct ibv_port_attr port_attr; /* IB port attributes */
    ibv_errno = ibv_query_port(res.ib_ctx, config.ib_port, &port_attr);
    VERBS_ERR_CHKANDJUMP(ibv_errno, -1, printf("ibv_query_port on port %u failed\n", config.ib_port));
    local_conn_info.lid = port_attr.lid;

    ibv_errno = ibv_query_gid(res.ib_ctx, config.ib_port, 0, (union ibv_gid*)&local_conn_info.gid);
    VERBS_ERR_CHKANDJUMP(ibv_errno, -1, printf("could not get gid for port %d, index 0\n", config.ib_port));

    local_conn_info.qp_num = qpinfo.qp->qp_num;
    local_conn_info.qkey = 0x11111111;

    /* send local connection info and obtain remote one */
    int listenfd = config.server_flg ? -1 : 0;
    int fd = sock_connect(config.server_name, config.tcp_port, &listenfd);
    if(fd < 0) { error_perror("sock_connect"); goto fn_fail; }
    if(config.server_flg) {
        dprintf("server,fd=%d\n", fd);
    } else {
        dprintf("client,fd=%d\n", fd);
    }
    ibcom_errno = sock_sync_data(fd, sizeof(qp_conn_info_ud_t), (char*)&local_conn_info, (char*)&remote_conn_info);
    if(ibcom_errno) { error_perror("sock_sync_data"); goto fn_fail; }

    /* print local and remote connection info */
    dprintf("local lid=%08x,qpn=%08x,qkey=%08x\n", local_conn_info.lid, local_conn_info.qp_num, local_conn_info.qkey);
    dprintf("local gid=");
    for(i = 0; i < 16; i++) { dprintf("%02x", local_conn_info.gid.raw[i]); }
    dprintf("\n");

    dprintf("remote lid=%08x,qpn=%08x,qkey=%08x\n", remote_conn_info.lid, remote_conn_info.qp_num, remote_conn_info.qkey);
    dprintf("remote gid=");
    for(i = 0; i < 16; i++) { dprintf("%02x", remote_conn_info.gid.raw[i]); }
    dprintf("\n");

	/* ibv_reg_mr */
	mrinfo_recv_list = malloc(sizeof(mrinfo_t) * SERVER_BUF_NUM);
	for (i = 0; i < SERVER_BUF_NUM; i++) {
		char *buf = malloc(config.buf_size * sizeof(char));
		if(!buf) { fprintf(stderr, "cannot malloc %dth buf\n", i); goto fn_fail; }
		for(j = 0; j < config.buf_size; j++) {
            buf[j] = -j & 0xff;
        }
		ibcom_errno = mr_create(&res, &pdinfo, config.buf_size, buf, &mrinfo_recv_list[i]);
        VERBS_ERR_CHKANDJUMP(ibcom_errno, -1, printf("mr_create\n"));
	}

	mrinfo_send_list = malloc(sizeof(mrinfo_t) * NTRIAL);
	for (i = 0; i < NTRIAL; i++) {
		char *buf = malloc(config.buf_size * sizeof(char));
		if (!buf) { printf("cannot malloc %dth buf\n", i); goto fn_fail; }
		for(j = 0; j < config.buf_size; j++) {
            buf[j] = j & 0xff;
        }
        ibcom_errno = mr_create(&res, &pdinfo, config.buf_size, buf, &mrinfo_send_list[i]);
        if(ibcom_errno) { printf("mr_create\n");  goto fn_fail; }
	}

	/* ibv_modify_qp */
	ibcom_errno = rtr_qp_ud(config, &qpinfo);
    if(ibcom_errno) { printf("rtr\n"); goto fn_fail; }
    ibcom_errno = rts_qp_ud(config, &qpinfo);
    if(ibcom_errno) { printf("rts\n"); goto fn_fail; }
    print_qp_status(&qpinfo);

    /* prepare address header (1/2, ibv_ah_attr) */
    struct ibv_ah_attr ah_attr;
    memset(&ah_attr, 0, sizeof(struct ibv_ah_attr));
    ah_attr.dlid = remote_conn_info.lid;
    ah_attr.sl = 0;
    ah_attr.src_path_bits = 0;
    ah_attr.static_rate = 0; /* not limit on static rate (100% port speed) */
    ah_attr.is_global = 0;
    ah_attr.port_num = config.ib_port;
    
#if 0
    ah_attr.is_global = 1;
    ah_attr.grh.dgid = remote_conn_info.gid;
    ah_attr.grh.flow_label = 0;
    ah_attr.grh.sgid_index = 0; /* what is this? */
    ah_attr.grh.hop_limit = 1;
    ah_attr.grh.traffic_class = 0;
#endif
    
    /* prepare address header (2/2, ibv_ah) */
    struct ibv_ah *ah;
    ah = ibv_create_ah(pdinfo.pd, &ah_attr);
    if(!ah) { printf("ibv_crate_ah\n"); goto fn_fail; }

    /* pre-post receive commands */
    VERBS_ERR_CHKANDJUMP(_MAX_RQ_CAPACITY < NTRIAL, -1, printf("Increase _MAX_RQ_CAPACITY,_MAX_RQ_CAPACITY=%d,NTRIAL=%d\n", _MAX_RQ_CAPACITY, NTRIAL));
	if(!config.server_flg) {
        for(i = 0; i < NTRIAL; i++){
            ibcom_errno = post_recv_req_ud(&qpinfo, &mrinfo_recv_list[0], 0x1234ULL);
            if(ibcom_errno) { printf("post_recv_req_ud\n"); goto fn_fail; }
        }
    }

    /* barrier */
    for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
        sock_sync_data(qpinfo.sock[i], 1, "R", &sync_res);
    }

    /* barrier */
    for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
        sock_sync_data(qpinfo.sock[i], 1, "R", &sync_res);
    }

	if(config.server_flg) { // sender side
        usleep(1000000);
        if(NTRIAL % PPOLLS != 0) { printf("set NTRIAL multiple of PPOLLS\n"); goto fn_fail; }
        if(NTRIAL <= NSKIPS) { printf("set NTRIAL > NSKIP\n"); goto fn_fail; }
		for(i = 0; i < NTRIAL; i++) {
            if(i == NSKIPS) { tscs = rdtsc(); }

            ibcom_errno = post_send_req_ud(&qpinfo, &mrinfo_send_list[0], IBV_WR_SEND, &remote_conn_info, ah);
            if(ibcom_errno) { printf("post_send_req_ud\n"); goto fn_fail; }
            

#if 1
            int nfound = 0;
            if(i % PPOLLS == PPOLLS - 1) {
                k = 0;
                while(1) {
                    int result;
                    struct ibv_wc cqe[PPOLLS];
                    result = ibv_poll_cq(qpinfo.scq, PPOLLS, &cqe[0]);
                    if(result < 0) { printf("ibv_poll_cq"); goto fn_fail; }
                    if(result > 0) {
                        for(j = 0; j < result; j++) { 
                            if(cqe[j].status != IBV_WC_SUCCESS) { printf("cqe status\n"); goto fn_fail; }
                        }
                        //debug_print_mem((unsigned long long)mrinfo_send_list[i].buf, config.buf_size);
                        nfound += result;
                        if(nfound == PPOLLS) { break; }
                    }
                    k++;
                }
            }
#endif
        }
        tsce = rdtsc(); printf("send,%.0f\n", (tsce-tscs)/(double)(NTRIAL-NSKIPS));

	} else { // receiver side
        if(NSKIPR % PPOLLR !=0) { printf("set NSKIP multiple of PPOLL\n"); goto fn_fail; }
		for(i = 0; i< NTRIAL; i++){
            if(i == NSKIPR) { tscs = rdtsc(); }
            //tscs2 = rdtsc();
#if 0
            ibv_errno = ibv_query_port(res.ib_ctx, config.ib_port, &port_attr);
            VERBS_ERR_CHKANDJUMP(ibv_errno, -1, printf("ibv_query_port on port %u failed\n", config.ib_port));
            printf("bad_pkey_cntr=%d,%d\n", port_attr.bad_pkey_cntr, port_attr.qkey_viol_cntr);
#endif

            /* poll CQ */
            int nfound = 0;
            if(i % PPOLLR == PPOLLR - 1) {
                k = 0;
                while(1) {
                    int ib_errno, result;
                    struct ibv_wc cqe[PPOLLR];
                    result = ibv_poll_cq(qpinfo.rcq, 1, &cqe[0]);
                    if(result < 0) { printf("poll_cq\n"); goto fn_fail; }
                    if(result > 0) {
                        for(j = 0; j < result; j++) { 
                            if(cqe[j].status != IBV_WC_SUCCESS) { printf("cqe.status"); goto fn_fail; }
                        }
                        printf("wr_id=%lx\n", cqe[0].wr_id);
                        //tsce2 = rdtsc(); printf("received,%ld\n", tsce2 - tscs2);
                        nfound += result;
                        if(nfound == PPOLLR) { break; }
                    }
                    k++;
                }
            }
		}
        tsce = rdtsc(); printf("recv,%.0f\n", (tsce-tscs)/(double)(NTRIAL-NSKIPR));
	}

 fn_exit:
	return verbs_errno;
 fn_fail:
    goto fn_exit;
}

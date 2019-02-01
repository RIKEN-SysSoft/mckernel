#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include "ibcomm.h"
#include "debug.h"
#include "mtype.h"
#include "mm_ib_test.h"

#define SERVER_BUF_NUM TEST_SERVER_BUF_NUM
#define REPEAT_TIME 1


/**
 * Alloc all buffers from host memory
 *
 */
int main(int argc, char **argv){
	config_t config;
	int i, mr_idx = 0, rc = 0;
	char sync_res;
	double t0, t1, t;
	resource_t res;
	pdinfo_t pdinfo;
	qpinfo_t qpinfo;
	mrinfo_t *mrinfo_send_list = NULL, *mrinfo_recv_list = NULL;

	debug_printf("enter\n");

	if(read_config(&config, argc, argv)){
		return rc;
	}

	debug_printf("after read_config..\n");

	if(resource_create(config, &res) ||
			pd_create(&res, &pdinfo) ||
				qp_create(&res, &pdinfo, &qpinfo)){
		goto main_exit;
	}
	debug_printf("create all successfully..\n");
	
	/* Connect qp of each side and init them*/
	if(connect_qp(config, &res, &qpinfo)){
		goto main_exit;
	}
	debug_print_qp_conn_info(res, qpinfo, &config);

	if(init_qp(config, &qpinfo)){
		goto main_exit;
	}

    debug_printf("buf_size=%d\n", config.buf_size);

	/* Register fixed recv buffers */
	mrinfo_recv_list = malloc(sizeof(mrinfo_t) * SERVER_BUF_NUM);
	for (i = 0; i < SERVER_BUF_NUM; i++) {
		char *buf = calloc(config.buf_size, sizeof(char));
		if (buf == NULL) {
			fprintf(stderr, "cannot malloc %dth buf\n", i);
			goto main_exit;
		}

		if (mr_create(&res, &pdinfo, config.buf_size, buf, &mrinfo_recv_list[i])) {
			goto main_exit;
		}

        //		post_recv_req(&qpinfo, &mrinfo_recv_list[i], i);
	}

	mrinfo_send_list = malloc(sizeof(mrinfo_t) * REPEAT_TIME);
	for (i = 0; i < REPEAT_TIME; i++) {
		char *buf = malloc(sizeof(char) * config.buf_size);
		if (buf == NULL) {
			fprintf(stderr, "cannot malloc %dth buf\n", i);
			goto main_exit;
		}debug_printf("alloc buf=0x%lx\n", (unsigned long)buf);
		memset(buf, '1', config.buf_size);
		buf[config.buf_size - 4] = i;

		if (mr_create(&res, &pdinfo, config.buf_size, buf, &mrinfo_send_list[i])) {
			goto main_exit;
		}
	}


	/* Modify qp state to RTS */
	if(rtr_qp(config, &qpinfo) ||
			rts_qp(config, &qpinfo)){
		goto main_exit;
	}
    for(i = 0; i < (config.server_flg ? config.nremote : 1); i++) {
        sock_sync_data(qpinfo.sock[i], 1, "R", &sync_res);
    }

	/*Receive first at server side*/
	if(config.server_flg){
		t0 = cur_time();
		for(i=0; i<REPEAT_TIME; i++){
			// send
            sleep(1);
			post_send_req(&qpinfo, &mrinfo_send_list[i], IBV_WR_SEND, i, &qpinfo.remote_conn_info[0], 0); /* 0 means only one receiver */
			if(!poll_cq(&qpinfo, SEND_CQ_FLG, &mr_idx)){
				debug_printf("send data to client by %dth buf[0x%lx]\n", i, (addr_t)mrinfo_send_list[i].buf);
				debug_print_mem((unsigned long long)mrinfo_send_list[i].buf, config.buf_size);
			}
		}
		t1 = cur_time();
	}
	/*Send first at client side*/
	else{
		t0 = cur_time();
		for(i=0; i<REPEAT_TIME; i++){
			// receive
            sleep(0);
            post_recv_req(&qpinfo, &mrinfo_recv_list[i], i);
			if(!poll_cq(&qpinfo, RECV_CQ_FLG, &mr_idx)){
				debug_printf("recv data from client by %dth buf[0x%lx]\n",  mr_idx, (addr_t)mrinfo_recv_list[mr_idx].buf);
				debug_print_mem((unsigned long long)mrinfo_recv_list[mr_idx].buf, config.buf_size);
			}
		}
		t1 = cur_time();
	}

	t = (t1 - t0) * 1000;
	debug_printf("use %lf msec, %lf msec\n", t, t / REPEAT_TIME);
//#ifdef PF_OUTPUT
		FILE *fp = fopen("/tmp/log_sr_host.txt", "a+");
		if(fp != NULL){
			fprintf(fp, "%d\t%lf\t%lf\n", config.buf_size, t, t / REPEAT_TIME);
			fclose(fp);
		}
//#endif

	main_exit:
		/*Can free all resources*/
		if(resource_destroy(&config, &res)){
			fprintf(stderr, "resource destroy failed\n");
		}else{
			debug_printf("destroy all successfully..\n");
		}
		if(mrinfo_send_list != NULL)
			free(mrinfo_send_list);
		if(mrinfo_recv_list != NULL)
			free(mrinfo_recv_list);

	return rc;
}

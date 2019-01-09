#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include "ibcomm.h"
/*
 int read_config(config_t *config, int argc, char **argv){
 memset(config, 0, sizeof(config_t));
 config->server_name = NULL;
 config->ib_port = 1;
 config->dev_name = NULL;

 // client mode
 if(argc == 4){
 config->server_name = argv[1];
 config->tcp_port = strtoul(argv[2], NULL, 0);
 config->buf_size = strtoul(argv[3], NULL, 0);
 }
 // server mode
 else if(argc == 3){
 config->tcp_port = strtoul(argv[1], NULL, 0);
 config->buf_size = strtoul(argv[2], NULL, 0);
 config->server_flg = 1;
 }
 else{
 printf("usage: ./main <server_name> <port> <size>\n");
 return IBCOMM_ERR_CODE;
 }

 if(config->tcp_port <=0 )
 return IBCOMM_ERR_CODE;

 return 0;
 }

 */

int read_config(config_t *config, int argc, char **argv) {
	memset(config, 0, sizeof(config_t));
	config->server_name = NULL;
	config->ib_port = 1;
	config->dev_name = NULL;
	config->server_flg = 1;
    config->nremote = 1;
    config->buf_size = 40 + 8; /* UD requires more than 40 byte */
    config->tcp_port = 5256;

	while (1) {
		int oc = getopt(argc, argv, "s:p:m:n:h");
		if (oc == -1)
			break;
		switch (oc) {
		case 's': /* name for IP for exchanging LID and QPN */
			config->server_name = optarg;
			config->server_flg = 0;
			break;
		case 'p': /* TCP port for exchange LID and  QPN */
			config->tcp_port = atoi(optarg);
			break;
		case 'm':
			config->buf_size = atoi(optarg);
			break;
        case 'n': /* number of remote nodes */
            config->nremote = atoi(optarg);
            break;
		case 'h':
		default:
			printf("usage: ./main [-s <server_name>] [-p <tcp_port>] [-m <size>]\n"
				   "Example: ssh cn01 ./main -p 10000 & ./main -s cn01 -p 10000\n");
            exit(-1);
			break;
		}
	}

    //	if (config->tcp_port <= 0) { return IBCOMM_ERR_CODE; }
    // no need to set tcp_port for IB

	return 0;
}

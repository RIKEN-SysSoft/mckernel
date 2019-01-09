#ifndef SOCK_H
#define SOCK_H
enum sock_return_code{
	_SOCK_SUCCESS,
	_SOCK_CONN_ERR,	
	_SOCK_WRITE_ERR,	
	_SOCK_READ_ERR
};
extern int sock_connect(char *server_name, int port, int *listenfd);
extern int sock_sync_data(int sock, int data_size, char *local_data, char *remote_data);
#endif

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "../include/qlmpi.h"

int	fd = -1;

#define BUF_MAX 256

void terminate(int rc)
{
	if(fd >= 0){
		shutdown(fd, 2);
		close(fd);
	}
	exit(rc);
}

int main(int argc, char* argv[])
{
	int	rc=-1, len;
	struct sockaddr_un	unix_addr;
	char	buf[BUF_MAX];

	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);

	if (argc < 5) {
#ifdef QL_DEBUG
		printf("too few arguments\n");
#endif
		return rc;
	}
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
#ifdef QL_DEBUG
		printf("client:socket error.\n");
#endif
		terminate(rc);
	}
#ifdef QL_DEBUG
	printf("client:socket.\n");
#endif
	unix_addr.sun_family = AF_UNIX;
	strcpy(unix_addr.sun_path, argv[4]);
#ifdef QL_DEBUG
	printf("socket_path %s\n",argv[4]);
#endif
	len = sizeof(unix_addr.sun_family)+strlen(unix_addr.sun_path) + 1;
	rc = connect(fd, (struct sockaddr*)&unix_addr, len);
	if (rc < 0) {
#ifdef QL_DEBUG
		printf("client:connect error.\n");
		printf("%s %s\n", unix_addr.sun_path, strerror(errno));
#endif
		terminate(rc);
	}

	if (argv[1][0]) {
		sprintf(buf,"%s %04x %s",argv[1],
					(unsigned int)strlen(argv[3]),argv[3]);
		rc = send(fd, buf, strlen(buf) + 1, 0);
		if (rc < 0) {
#ifdef QL_DEBUG
			printf("send error.\n");
#endif
			terminate(rc);
		}
	}
	if (strcmp(argv[2],"-n")) {
#ifdef QL_DEBUG
		printf("waiting reply message from ql_server ...\n");
#endif
		rc = recv(fd, buf, 256, 0);
#ifdef QL_DEBUG
		printf("%s\n",buf);
#endif
		if (rc < 0) {
#ifdef QL_DEBUG
			printf("recv error\n");
#endif
			terminate(rc);
		}
		if (buf[0] == argv[2][0]){
			terminate(0);
		}
		if (buf[0] == QL_AB_END){
			/* abnormal end */
			terminate(-2);
		}
	}

	terminate(0);
	return rc; /*not reached */
}

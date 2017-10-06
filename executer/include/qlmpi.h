
#ifndef __HEADER_QLMPI_H
#define __HEADER_QLMPI_H

/* UerProgram executed */
#define QL_EXEC_END 'E'
/* qlmpiexec_finalize */
#define QL_RET_FINAL 'F'
/* UserProgram resume */
#define QL_RET_RESUME 'R'
/* Connect from ql_mpiexec_start/Finalize*/
#define QL_COM_CONN 'N'
/* Abnormal end */
#define QL_AB_END 'A'

/* Client kind */
/* mpiexec moniter Program */
#define QL_MONITOR 1
/* mcexec */
#define QL_MCEXEC_PRO 2
/* ql_mcexec_start ql_mpiexec_finalize */
#define QL_MPEXEC 3


#define QL_SOCK "ql_sock"

#define QL_MAX_PATH 4096
#define QL_PARAM_PATH "./"
#define QL_PARAM_EXTE ".param"
#define QL_SWAP_PATH "/tmp"
#define QL_SOCKT_PATH "/run/user"

#define QL_NAME "QL_NAME"
#define QL_SWAP_ENV "QL_SWAP_PATH"
#define QL_PARAM_ENV "QL_PARAM_PATH"
#define QL_SOCK_ENV "QL_SOCKET_PATH"

#define QL_BUF_MAX 256


struct client_fd {
	int fd;		//FD
	int client;	//Client Kind
	char *name;	//QL_NAME
	int status;	//execute status
};

int ql_recv(int fd,char ** buf);

int ql_send(int fd,int command,char *buf);


#define QL_COMMAND '0'
#define QL_ARG '1'
#define QL_ENV '2'

//#define QL_DEBUG
#endif

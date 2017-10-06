#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <alloca.h>
#include <unistd.h>
#include <fcntl.h>

#include "../include/qlmpi.h"

#define	NALLOC	10
#define NOLOG

#ifndef NOLOG
#define LOGFILE "ql_server.log"
int log_open(char *f_name);
int log_close();
void log_printf(const char *format, ...);
void log_dump(struct client_fd *fd_list,int fd_size);

FILE * log_fp;
#endif

int listen_fd = -1;
char file_path[1024];

int check_ql_server( char * path,char * file ,char *filep){
	struct stat st;
	int rc;

	sprintf(filep,"%s/%s",path,file);

	rc = stat(filep,&st);
	if (rc == 0) {
		fprintf(stderr,"socket file exests. %s\n",filep);
		return rc;
	}
	else {
		rc = stat(path,&st);
		if ( rc == 0) {
			fprintf(stderr,"dir(file) exests. %s %d\n",path,rc);
			return 1;
		}
		else {
			mode_t m = st.st_mode;
			if (S_ISDIR(m)) {
				fprintf(stderr,"dir exests. %s %d\n",path,rc);
				return rc; /* dir exist */
			}
			else {
				if (mkdir(path, (S_IRUSR | S_IWUSR | S_IRWXU |
						S_IRGRP | S_IWGRP | S_IRWXG |
						S_IROTH | S_IWOTH | S_IRWXO)) == 0) {
					fprintf(stderr,"dir create. %s %d\n",path,rc);
					return 1;
				}
				fprintf(stderr,"mkdir error. %s %d\n",path,rc);
				return 0; /* mkdir error */
			}
		}
	}
}

void terminate(int rc){

	if (listen_fd >= 0) {
		shutdown(listen_fd, 2);
		close(listen_fd);
		unlink(file_path);
	}
#ifndef NOLOG
	log_close();
#endif
	exit(rc);
}

int s_fd_list(char * p_name,int client_type ,
		struct client_fd *fd_list,int fd_size){
	int i;
	for (i = 0; fd_size > i; i++) {
		if ((fd_list[i].client == client_type) && 
			(!strcmp(fd_list[i].name,p_name)) && 
			(fd_list[i].fd != -1)) {
			break;
		}
	}
	return i;
}

int main( int argc, char *argv[]){
	int i,j, fd, rc = 0, len, maxfd;
	int fd_size ;
	struct client_fd *fd_list;
	fd_set rset, allset;
	struct sockaddr_un	unix_addr;
	char	*buf;
	int s_indx;
#ifndef NOLOG
	int e_no; /*errno copy*/
#endif
	char * null_buff = "";
	
	if (argc < 3 ) {
		fprintf(stderr," few args \n");
		exit(-1);
	}

	for (i = 0; i < 4096; i++)
		close(i);
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);

	if (!check_ql_server(argv[1], argv[2] ,file_path)) {
		fprintf(stderr,"ql_server already exists.\n");
		exit(-1);
	}
	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);

	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		fprintf(stderr,"listen error.\n");
		terminate(rc);
	}

#ifndef NOLOG
	log_open(argv[1]);
#endif
	unix_addr.sun_family = AF_UNIX;
	strcpy(unix_addr.sun_path, file_path);
#ifndef NOLOG
	log_printf("file_path =%s \n",file_path);
#endif
	len = sizeof(unix_addr.sun_family) + strlen(unix_addr.sun_path) + 1;
	rc = bind(listen_fd, (struct sockaddr *)&unix_addr, len);

	if (rc < 0) {
#ifndef NOLOG
		log_printf("bind error \n",file_path);
#endif
		terminate(rc);
	}

	// become a daemon
	if (fork())
		exit(0);
	if (fork())
		exit(0);
	setsid();

	rc = listen(listen_fd, 5);
	if (rc < 0) {
#ifndef NOLOG
		log_printf("listen error \n");
#endif
		terminate(rc);
	}

	FD_ZERO(&allset);
	FD_SET(listen_fd, &allset);
	maxfd = listen_fd;
	fd_size = NALLOC;
	fd_list = malloc(sizeof(struct client_fd)*fd_size);
	for (i = 0; i < fd_size; i++) {
		fd_list[i].fd = -1;
	}

#ifndef NOLOG
	log_printf("loop_start \n");
#endif
	for (;;) {
		memcpy(&rset, &allset, sizeof(rset));
		rc = select(maxfd + 1, &rset, NULL, NULL, NULL);
		if (rc == -1) {
#ifndef NOLOG
			e_no = errno;
			log_printf("server:select error.\n");
			log_printf("select error string by strerror: %s\n", 
				strerror(e_no));
			log_printf("select error code: %d\n", e_no);
#endif
			terminate(rc);
		}
#ifndef NOLOG
		log_printf("server:select.\n");
#endif

		if (FD_ISSET(listen_fd, &rset)) {
			len = sizeof(unix_addr);
			fd = accept(listen_fd, (struct sockaddr *)&unix_addr, 
				(socklen_t*)&len);
			if (fd < 0) {
#ifndef NOLOG
				log_printf("server:accept error.\n");
#endif
				terminate(fd);
			}
#ifndef NOLOG
			log_printf("server:accept (%d).\n", fd);
#endif
			for (i = 0; fd_size > i; i++) {
				if (fd_list[i].fd == -1) {
					fd_list[i].fd = fd;
					break;
				}
			}
			if (i >= fd_size) {
				fd_list = realloc(fd_list, 
					sizeof(int)*(fd_size+NALLOC));
				for (i = fd_size; i < (fd_size + NALLOC); i++) {
					fd_list[i].fd = -1;
				}
				fd_list[fd_size].fd = fd;
				fd_size += NALLOC;
			}
			FD_SET(fd, &allset);
			if (fd > maxfd) {
				maxfd = fd;
			}
		}

		for (i = 0; i < fd_size; i++) {
			if (fd_list[i].fd == -1)
				continue;
			fd = fd_list[i].fd;
			if (!FD_ISSET(fd, &rset))
				continue;
			rc = ql_recv(fd, &buf);
#ifndef NOLOG
			log_printf("ql_recv (%d) index = %d fd = %d \n", rc,i,fd);
#endif
			if(rc < 0){
#ifndef NOLOG
				log_printf("server:recv (%d) error.\n", fd);
#endif
				terminate(rc);
			}
			if (rc == 0) {
#ifndef NOLOG
				log_printf("server:closed (%d).\n", fd);
#endif
				fd_list[i].fd = -1;
				if (strcmp(fd_list[i].name,null_buff)) {
					free(fd_list[i].name);
					fd_list[i].name = null_buff;
				}
				FD_CLR(fd, &allset);
				maxfd = -1;
				for (j = 0; fd_size > j ; j++) {
					if (fd > maxfd) {
						maxfd = fd;
					}
				}
				close(fd);
#ifndef NOLOG
				log_printf("index = %d\n",i);
				log_dump(fd_list,fd_size);
#endif
				if (maxfd == -1) {
					terminate(rc);
				}
				continue;
			}

			if (rc == QL_EXEC_END){ /* swapout from mcexec */
				fd_list[i].client = QL_MCEXEC_PRO;
				fd_list[i].name = buf;
				fd_list[i].status = QL_EXEC_END;
#ifndef NOLOG
				log_printf("index = %d\n",i);
				log_dump(fd_list,fd_size);
#endif
/* send E command to ql_talker */
				if ((s_indx = s_fd_list(fd_list[i].name,
					QL_MPEXEC,fd_list,
					fd_size)) <  fd_size) {
#ifndef NOLOG
					log_printf("E command to talker %d \n",s_indx); 
#endif
					rc = ql_send(fd_list[s_indx].fd,
						QL_EXEC_END,NULL);
/*  fd close for ql_talker */
					FD_CLR(fd_list[s_indx].fd, &allset);
					maxfd = -1;
					close(fd_list[s_indx].fd);
					free(fd_list[s_indx].name);
					fd_list[s_indx].fd = -1;
					fd_list[s_indx].name = null_buff;
					for (j = 0; fd_size > j ; j++) {
						if (fd_list[j].fd > maxfd) {
							maxfd = fd_list[j].fd;
						}
					}
					if (maxfd == -1) terminate(0);
				}
				else{
					/* ql_talker not found */
#ifndef NOLOG
					log_printf("ql_talker not found\n",i);
#endif
				/* send I command to mcexec and param_file put A command*/
				}
#ifndef NOLOG
				log_printf("index = %d\n",i);
				log_dump(fd_list,fd_size);
#endif
			}
			else if (rc == QL_RET_RESUME) {
				/* recv R command from ql_talker */
				fd_list[i].client = QL_MPEXEC;
				fd_list[i].name = buf;
				fd_list[i].status = QL_RET_RESUME;
#ifndef NOLOG
				log_printf("index = %d,fd_size=%d\n",
					i,fd_size);
				log_dump(fd_list,fd_size);
#endif
				/* send R command to mcexec */
				if (((s_indx = s_fd_list(fd_list[i].name,
					QL_MCEXEC_PRO ,
					fd_list,fd_size)) <  fd_size) && 
					fd_list[s_indx].status == QL_EXEC_END) {
#ifndef NOLOG
					log_printf("R command to mcexec %d \n",s_indx);
					log_dump(fd_list,fd_size);
#endif
					rc = ql_send(fd_list[s_indx].fd,
						QL_RET_RESUME,NULL);
					fd_list[s_indx].status = QL_RET_RESUME;
					FD_CLR(fd_list[s_indx].fd, &allset);
					close(fd_list[s_indx].fd);
					free(fd_list[s_indx].name);
					fd_list[s_indx].fd = -1;
					fd_list[s_indx].name = null_buff;
					maxfd = -1;
					for (j = 0; fd_size > j ; j++) {
						if (fd_list[j].fd > maxfd) {
							maxfd = fd_list[j].fd;
						}
					}
					if (maxfd == -1) terminate(0);
				}
				else{
/* mcexec not found */
/* send A command to ql_talker */
#ifndef NOLOG
					log_printf("send A command index = %d,fd_size=%d\n",
						i,fd_size);
					log_dump(fd_list,fd_size);
#endif
					rc = ql_send(fd_list[i].fd,
						QL_AB_END,NULL);
/*  fd close for ql_talker */
					FD_CLR(fd_list[i].fd, &allset);
					close(fd_list[i].fd);
					free(fd_list[i].name);
					fd_list[i].fd = -1;
//					fd_list[i].name = NULL;
					fd_list[i].name = null_buff;
					maxfd = -1;
					for (j = 0; fd_size > j ; j++) {
						if (fd_list[j].fd > maxfd) {
							maxfd = fd_list[j].fd;
						}
					}
					if (maxfd == -1) terminate(0);
				}
#ifndef NOLOG
				log_printf("index = %d,s_indx=%d\n",
					i,s_indx);
				log_dump(fd_list,fd_size);
#endif
			}
			else if (rc == QL_COM_CONN) {
				/* connect from ql_mpiexec_* */
				fd_list[i].client = QL_MPEXEC;
				fd_list[i].name = buf;
				fd_list[i].status = QL_COM_CONN;
#ifndef NOLOG
				log_printf("N command index = %d,fd_size=%d\n",
					i,fd_size);
				log_dump(fd_list,fd_size);
#endif
				if ((s_indx = s_fd_list(fd_list[i].name,
					QL_MCEXEC_PRO,fd_list,
					fd_size)) <  fd_size) {
					rc = ql_send(fd_list[i].fd,
						QL_EXEC_END,NULL);
/*  fd close for ql_talker */
					FD_CLR(fd_list[i].fd, &allset);
					maxfd = -1;
					close(fd_list[i].fd);
					free(fd_list[i].name);
					fd_list[i].fd = -1;
					fd_list[i].name = null_buff;
					for (j = 0; fd_size > j ; j++) {
						if (fd_list[j].fd > maxfd) {
							maxfd = fd_list[j].fd;
						}
					}
				//	if (maxfd == -1) terminate(0);
				}
#ifndef NOLOG
				log_dump(fd_list,fd_size);
#endif
			}
			else if(rc == QL_RET_FINAL) {
				/*  F command from Monitor Process */
				fd_list[i].client = QL_MONITOR;
				fd_list[i].name = buf;
				fd_list[i].status = QL_RET_FINAL;
#ifndef NOLOG
				log_printf("F command index = %d,fd_size=%d\n",
					i,fd_size);
				log_dump(fd_list,fd_size);
#endif
				/* search ql_mpiexec_start process */
				if ((s_indx = s_fd_list(fd_list[i].name,
					QL_MPEXEC,fd_list,
					fd_size)) <  fd_size) {
				/* send A command */
					rc = ql_send(fd_list[s_indx].fd,
						QL_AB_END,NULL);
				/* table clear */
					FD_CLR(fd_list[s_indx].fd, &allset);
					maxfd = -1;
					close(fd_list[s_indx].fd);
					free(fd_list[s_indx].name);
					fd_list[s_indx].fd = -1;
					fd_list[s_indx].name = null_buff;
					for (j = 0; fd_size > j ; j++) {
						if (fd_list[j].fd > maxfd) {
							maxfd = fd_list[j].fd;
						}
					}
				}
				/* search mcexec process */
				if ((s_indx = s_fd_list(fd_list[i].name,
					QL_MCEXEC_PRO,fd_list,
					fd_size)) <  fd_size) {
				/* table clear */
					FD_CLR(fd_list[s_indx].fd, &allset);
					maxfd = -1;
					close(fd_list[s_indx].fd);
					free(fd_list[s_indx].name);
					fd_list[s_indx].fd = -1;
					fd_list[s_indx].name = null_buff;
					for (j = 0; fd_size > j ; j++) {
						if (fd_list[j].fd > maxfd) {
							maxfd = fd_list[j].fd;
						}
					}
				}
				FD_CLR(fd_list[i].fd, &allset);
				close(fd_list[i].fd);
				free(fd_list[i].name);
				fd_list[i].fd = -1;
				fd_list[i].name = null_buff;
				maxfd = -1;
				for (j = 0; fd_size > j ; j++) {
					if (fd_list[j].fd > maxfd) {
						maxfd = fd_list[j].fd;
					}
				}
#ifndef NOLOG
				log_printf("F command end index = %d,fd_size=%d\n",
					i,fd_size);
				log_dump(fd_list,fd_size);
#endif
				if (maxfd == -1)
					terminate(0);
			}
			else {
#ifndef NOLOG
				log_printf("server:unknwon commond %d (%d).\n",
				           rc, fd);
#endif
			}
#ifndef NOLOG
			log_printf("server:recv (%d) .\n", fd);
#endif
		}
	}
	terminate(0);
}

#ifndef NOLOG
int log_open(char *f_path){
	char f_name[1024];
	sprintf(f_name,"%s/%s",f_path,LOGFILE);
	if ((log_fp = fopen(f_name,"w")) == NULL) {
		log_fp = stderr;
	}
	return 0;
}

int log_close(){
	if (log_fp != stdout) {
		fclose(log_fp);
	}
	return 0;
}

void log_printf(const char *format, ...){
	va_list arglist;
	char log[1024];

	va_start(arglist, format);
	vsprintf(log, format, arglist);
	fprintf(log_fp, "%s\n", log);
	va_end(arglist);
	fflush(log_fp);
}

void log_dump(struct client_fd *fd_list,int fd_size){
	int i;
	for (i = 0; fd_size > i; i++) {
		if (fd_list[i].fd != -1) {
			log_printf("|%4d|%4d|%c|%s|\n",fd_list[i].fd,
				fd_list[i].client,(char)fd_list[i].status,
				fd_list[i].name);
		}
		else{
			log_printf("|%4d|0000| |    |\n",fd_list[i].fd);
		}
	}
	log_printf("-----------------------\n");
}
#endif

int ql_recv(int fd,char ** buf){
	char l_buf[QL_BUF_MAX];
	char comm;
	int size = 0;
	int rc;
	int ret;

	rc = recv(fd, l_buf, QL_BUF_MAX, 0);
#ifndef NOLOG
	log_printf("rc = %d,l_buf=%s\n",rc,l_buf);
#endif
	if (rc <= 0) {
		return rc;
	}
	
	sscanf(l_buf, "%c %x", &comm, &size);
	ret = (int)(comm);
#ifndef NOLOG
	log_printf("COMM=%c size = %x rc= %d\n", ret, size, rc);
#endif
	if (size > 0) {
		*buf = malloc(size+1);
		memcpy(*buf, &l_buf[7], size);
		buf[size] = 0x00;
#ifndef NOLOG
		log_printf("COMM=%c size = %x *buf= %s\n",ret,size,*buf);
#endif
	}
#ifndef NOLOG
	log_printf("ret = %d\n", ret);
#endif
	return ret;
}

int ql_send(int fd,int command,char *buf){
	char *lbuf;
	int size;
	int rc;

	if (buf != NULL) {
		size = strlen(buf);
		lbuf = alloca(size+7+1);
		sprintf(lbuf,"%c %04x %s",command,size,buf);
	}
	else{
		size = 0;
		lbuf = alloca(6+1);
		sprintf(lbuf,"%c 0000",command);
	}
#ifndef NOLOG
	log_printf("send lbuf=%s",lbuf);
#endif
	rc=send(fd,lbuf,strlen(lbuf),0);
	return rc;
}


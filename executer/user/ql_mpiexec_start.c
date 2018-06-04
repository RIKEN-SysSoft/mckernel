#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include "config.h"

#include "../include/qlmpi.h"
#include "../include/md5.h"

#define MCEXEC "mcexec"
#define QL_PIPE_PATH "/tmp/"
#define QL_PIPE_IN_EXTENTION ".in"
#define QL_PIPE_OUT_EXTENTION ".out"
#define QL_SERVER_EXECUTION SBINDIR "/ql_server"
#define QL_TALKER_EXECUTION SBINDIR "/ql_talker"

extern char **environ;

struct mpi_opt {
	const char *opt;
	int n;
	int flags;
#define HOSTFILE_OPT  1
#define HOSTLIST_OPT  2
#define NODE_OPT      4
#define UNSUPP_OPT    8
#define ENVLIST_OPT  16
#define ENVNONE_OPT  32
#define ENVALL_OPT   64
#define ENV_OPT     128
};

const struct mpi_opt opts[] = {
	{"help", 0, 0},
	{"h", 0, 0},
	{"genv", -1, ENV_OPT},
	{"genvlist", 1, ENVLIST_OPT},
	{"genvnone", 0, ENVNONE_OPT},
	{"genvall", 0, ENVALL_OPT},
	{"f", 1, HOSTFILE_OPT},
	{"hostfile", 1, HOSTFILE_OPT},
	{"machinefile", 1, HOSTFILE_OPT},
	{"machine", 1, HOSTLIST_OPT},
	{"machines", 1, HOSTLIST_OPT},
	{"machinelist", 1, HOSTLIST_OPT},
	{"host", 1, HOSTLIST_OPT},
	{"hosts", 1, HOSTLIST_OPT},
	{"hostlist", 1, HOSTLIST_OPT},
	{"ppn", 1, 0},
	{"profile", 0, 0},
	{"prepend-rank", 0, 0},
	{"l", 0, 0},
	{"prepend-pattern", 1, 0},
	{"outfile-pattern", 1, 0},
	{"outfile", 1, 0},
	{"errfile-pattern", 1, 0},
	{"errfile", 1, 0},
	{"wdir", 1, 0},
	{"configfile", 1, 0},
	{"env", -1, ENV_OPT},
	{"envlist", 1, ENVLIST_OPT},
	{"envnone", 0, ENVNONE_OPT},
	{"envall", 0, ENVALL_OPT},
	{"n", 1, NODE_OPT},
	{"np", 1, NODE_OPT},
	{"launcher", 1, 0},
	{"launcher-exec", 1, 0},
	{"bootstrap", 1, 0},
	{"bootstrap-exec", 1, 0},
	{"enable-x", 0, 0},
	{"disable-x", 0, 0},
	{"rmk", 1, 0},
	{"bind-to", 1, 0},
	{"binding", 1, 0},
	{"map-by", 1, 0},
	{"membind", 1, 0},
	{"topolib", 1, 0},
	{"ckpoint-interval", 1, 0},
	{"ckpoint-prefix", 1, 0},
	{"ckpoint-num", 1, 0},
	{"ckpointlib", 1, 0},
	{"demux", 1, 0},
	{"verbose", 0, 0},
	{"v", 0, 0},
	{"debug", 0, 0},
	{"info", 0, 0},
	{"version", 0, 0},
	{"print-all-exitcodes", 0, 0},
	{"iface", 1, 0},
	{"nameserver", 1, 0},
	{"disable-auto-cleanup", 0, 0},
	{"dac", 0, 0},
	{"enable-auto-cleanup", 0, 0},
	{"disable-hostname-propagation", 0, 0},
	{"enable-hostname-propagation", 0, 0},
	{"order-nodes", 1, 0},
	{"localhost", 1, 0},
	{"usize", 1, 0},
	{NULL, 0, 0}
};

char **mpi_opt_top;
char **usr_opt_top;

int fdstdin = -1;
int fdstdout = -1;
int fdstderr = -1;
char ql_name[33] = "";
char ql_sock_file[1024] = "";
char target_host[256] = "";
struct sockaddr_un wsock;

char *
trim(char *buf)
{
	char *p;
	char *q;

	for(p = buf; *p && (isspace(*p)); p++);
	if(!*p)
		return p;
	for(q = strchr(p, '\0') - 1; isspace(*q); q--)
		*q = '\0';
	return p;
}

void
esc_put(FILE *fp, char type, const char *buf)
{
	const char *t;

	fprintf(fp, "%c %ld ", type, strlen(buf));
	for (t = buf; *t; t++) {
		if (*t == '%' || *t < ' ')
			fprintf(fp, "%%%02x", *t);
		else
			fputc(*t, fp);
	}
	fputc('\n', fp);
}

static void
ql_setenv(char **env, char *k, char *v)
{
	char **e;
	char *w;
	char *t;
	int l;

	if (!*k || *k == '=')
		return;

	l = strlen(k);
	if (v)
		l += strlen(v) + 1;
	else if (!strchr(k, '='))
		l++;
	w = malloc(l + 1);
	strcpy(w, k);
	if (!(t = strchr(w, '=')))
		strcat(w, "=");
	else
		t[1] = '\0';
	l = strlen(w);
	for (e = env; *e; e++)
		if (!strncmp(w, *e, l))
			break;
	if (v)
		strcat(w, v);
	else if (t)
		strcpy(w, k);
	if (!*e)
		e[1] = NULL;
	*e = w;
}

static void
ql_envlist(char **env, char *list)
{
	char *w = strdup(list);
	char *p = w;

	for (;;) {
		char *q = strchr(p, ',');

		if (q) {
			*q = '\0';
			ql_setenv(env, p, NULL);
			p = q + 1;
		}
		else {
			ql_setenv(env, p, NULL);
			break;
		}
	}

	free(w);
}

static int
sendfd(int sock, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg = (struct cmsghdr*)cmsgbuf;
	char c;

	iov.iov_base = &c;
	iov.iov_len = 1;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*((int *)CMSG_DATA(cmsg)) = fd;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;
	if (sendmsg(sock, &msg, 0) == -1) {
		return -1;
	}

	return 0;
}

#ifndef QL_MPIEXEC_FINALIZE
static int
recvfd(int sock)
{
	struct msghdr msg;
	struct iovec iov;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg = (struct cmsghdr *)cmsgbuf;
	char c;

	iov.iov_base = &c;
	iov.iov_len = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = MSG_WAITALL;
	if (recvmsg(sock, &msg, 0) == -1) {
		return -1;
	}

	return *(int *)CMSG_DATA(cmsg);
}

int eventfds[2];

static void
chld(int s)
{
	write(eventfds[1], "Q", 1);
}

static void
term_server()
{
	char buf[1024];

	sprintf(buf,"ssh %s %s %c %s %s %s", target_host, QL_TALKER_EXECUTION,
	        QL_RET_FINAL, "-n", ql_name ,ql_sock_file);
	system(buf);
}

#define RBUFSIZE 65536
struct rbuf {
	int rpos;
	int wpos;
	char buf[RBUFSIZE];
};

struct rbuf *
buf_new()
{
	struct rbuf *rbuf = malloc(sizeof(struct rbuf));

	rbuf->rpos = 0;
	rbuf->wpos = 0;
	return rbuf;
}

int
buf_empty(struct rbuf *bp)
{
	return bp->rpos == bp->wpos;
}

int
buf_full(struct rbuf *bp)
{
	if (bp->wpos)
		return bp->rpos == bp->wpos - 1;
	return bp->rpos == RBUFSIZE - 1;
}

int
buf_read(int fd, struct rbuf *bp)
{
	struct iovec iov[2];
	int iovlen = 1;
	int rc;

	iov[0].iov_base = bp->buf + bp->rpos;
	if (bp->rpos >= bp->wpos) {
		if (bp->wpos == 0)
			iov[0].iov_len = RBUFSIZE - bp->rpos - 1;
		else {
			iovlen = 2;
			iov[0].iov_len = RBUFSIZE - bp->rpos;
			iov[1].iov_base = bp->buf;
			iov[1].iov_len = bp->wpos - 1;
		}
	}
	else
		iov[0].iov_len = bp->wpos - bp->rpos - 1;
	rc = readv(fd, iov, iovlen);
	if (rc <= 0)
		return rc;
	bp->rpos += rc;
	if (bp->rpos >= RBUFSIZE)
		bp->rpos -= RBUFSIZE;
	return rc;
}

int
buf_write(int fd, struct rbuf *bp)
{
	struct iovec iov[2];
	int iovlen = 1;
	int rc;

	iov[0].iov_base = bp->buf + bp->wpos;
	if (bp->wpos > bp->rpos) {
		iov[0].iov_len = sizeof(bp->buf) - bp->wpos;
		iov[1].iov_base = bp->buf;
		if ((iov[1].iov_len = bp->rpos))
			iovlen = 2;
	}
	else
		iov[0].iov_len = bp->rpos - bp->wpos;
	rc = writev(fd, iov, iovlen);
	if (rc <= 0)
		return rc;
	bp->wpos += rc;
	if (bp->wpos >= RBUFSIZE)
		bp->wpos -= RBUFSIZE;
	return rc;
}

struct fds {
	struct fds *next;
	int in_fd;
	int out_fd;
	struct rbuf *buf;
};

struct fds *
fds_new(int in_fd, int out_fd)
{
	struct fds *fdp;

	fdp = malloc(sizeof(struct fds));

	fdp->next = NULL;
	fdp->buf = buf_new();
	fdp->in_fd = in_fd;
	fdp->out_fd = out_fd;
	return fdp;
}

static void
ql_wrapper(char **args, int afd)
{
	pid_t pid;
	char c;
	int pfds0[2];
	int pfds1[2];
	int pfds2[2];
	int pfds3[2];
	int rc;
	int maxfd = afd;
	fd_set readfds;
	fd_set writefds;
	int first = 1;
	int cfd = -1;
	int nflg = 0;
	struct fds *fds0;
	struct fds *fds1;
	struct fds *fds2;
	struct fds *fdtop;
	struct fds *fdp;
	int exitcode = 1;

	pipe(eventfds);
	if (eventfds[0] > maxfd)
		maxfd = eventfds[0];

	pipe(pfds0);
	pipe(pfds1);
	pipe(pfds2);

	fds0 = fds_new(-1, pfds0[1]);
	fds1 = fds_new(pfds1[0], -1);
	fds2 = fds_new(pfds2[0], -1);
	fdtop = fds0;
	fds0->next = fds1;
	fds1->next = fds2;

	socketpair(AF_UNIX, SOCK_STREAM, 0, pfds3);
	fcntl(pfds3[1], F_SETFD, FD_CLOEXEC);
	pid = fork();
	if (pid == 0) {
		close(afd);
		close(pfds0[1]);
		if (pfds0[0] != 0) {
			dup2(pfds0[0], 0);
			close(pfds0[0]);
		}
		close(pfds1[0]);
		if (pfds1[1] != 1) {
			dup2(pfds1[1], 1);
			close(pfds1[1]);
		}
		close(pfds2[0]);
		if (pfds2[1] != 1) {
			dup2(pfds2[1], 2);
			close(pfds2[1]);
		}
		close(pfds3[0]);

		// wait for client
		while ((rc = read(pfds3[1], &c, 1)) == -1 && errno == EINTR);
		if (rc != 1) //client is already terminated
			exit(0);
		execvp("mpiexec", args);

		// exec fail
		rc = errno;
		write(pfds3[1], &rc, sizeof rc);
		exit(1);
	}
	close(pfds0[0]);
	close(pfds1[1]);
	close(pfds2[1]);
	close(pfds3[1]);
	if (pfds0[1] > maxfd)
		maxfd = pfds0[1];
	if (pfds1[0] > maxfd)
		maxfd = pfds1[0];
	if (pfds2[0] > maxfd)
		maxfd = pfds2[0];

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, chld);

	for (;;) {
		if (afd == -1 &&
		    (fds1->out_fd == -1 || buf_empty(fds1->buf)) &&
		    (fds2->out_fd == -1 || buf_empty(fds2->buf)))
			break;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_SET(eventfds[0], &readfds);
		if (cfd == -1)
			FD_SET(afd, &readfds);
		else
			FD_SET(cfd, &readfds);

		for (fdp = fdtop; fdp; fdp = fdp->next) {
			if (fdp->out_fd != -1 && !buf_empty(fdp->buf))
				FD_SET(fdp->out_fd, &writefds);
			if (fdp->in_fd != -1 && !buf_full(fdp->buf))
				FD_SET(fdp->in_fd, &readfds);
		}

		rc = select(maxfd + 1, &readfds, &writefds, NULL, NULL);
		if (rc == -1 && errno == EINTR)
			continue;
		if (rc == 0)
			continue;

		if (FD_ISSET(eventfds[0], &readfds)) { // child die
			int c;
			int st;

			read(eventfds[0], &c, 1);
			while (waitpid(pid, &st, 0) == -1 && errno == EINTR);
			term_server();
			if (cfd != -1) {
				write(cfd, "X", 1);
				write(cfd, &st, 4);
			}
			exitcode = 0;
			close(afd);
			afd = -1;
		}

		if (FD_ISSET(afd, &readfds)) {
			struct sockaddr_un sock;
			socklen_t len;

			len = sizeof sock;
			cfd = accept(afd, (struct sockaddr *)&sock, &len);
			if (cfd == -1) {
				goto end;
			}
			if (cfd > maxfd)
				maxfd = cfd;
		}
		if (FD_ISSET(cfd, &readfds)) {
			int fd;

			rc = read(cfd, &c, 1);
			if (rc == 0) {
				close(cfd);
				cfd = -1;
				if (!nflg) { // abormally terminated
					kill(pid, SIGINT);
					term_server();
					close(afd);
					afd = -1;
				}
			}
			else if (c == 'C') {
				nflg = 0;
			}
			else if (c == '0') {
				fd = recvfd(cfd);
				if (fd > maxfd)
					maxfd = fd;
				fds0->out_fd = fd;
			}
			else if (c == '1') {
				fd = recvfd(cfd);
				if (fd > maxfd)
					maxfd = fd;
				fds1->out_fd = fd;
			}
			else if (c == '2') {
				fd = recvfd(cfd);
				if (fd > maxfd)
					maxfd = fd;
				fds2->out_fd = fd;
				if (first) {
					char buf[256];
					int e = 0;

					first = 0;
					write(pfds3[0], " ", 1);
					rc = read(pfds3[0], &e, sizeof e);
					if (rc == sizeof e) { // failed to exec
						sprintf(buf, "mpiexec: exec(%s)"
						        "\n", strerror(e));
						write(fd, buf, strlen(buf));
						goto end;
					}
					else if (rc == -1) {
						sprintf(buf, "mpiexec: read(%s)"
						        "\n", strerror(errno));
						write(fd, buf, strlen(buf));
					}
					close(pfds3[0]);
				}
			}
			else if (c == 'E') {
				nflg = 1;
			}
			else if (c == 'F') {
				nflg = 1;
			}
			if (c != 'F')
				write(cfd, " ", 1);
		}
		for (fdp = fdtop; fdp; fdp = fdp->next) {
			if (fdp->out_fd != -1 &&
			    FD_ISSET(fdp->out_fd, &writefds)) {
				rc = buf_write(fdp->out_fd, fdp->buf);
				if (fdp->in_fd == -1 &&
				    buf_empty(fdp->buf)) {
					close(fdp->out_fd);
					fdp->out_fd = -1;
				}
			}
			if (fdp->in_fd != -1 &&
			    FD_ISSET(fdp->in_fd, &readfds)) {
				rc = buf_read(fdp->in_fd, fdp->buf);
				if (rc == 0) {
					close(fdp->in_fd);
					fdp->in_fd = -1;
					if (buf_empty(fdp->buf)) {
						close(fdp->out_fd);
						fdp->out_fd = -1;
					}
				}
			}
		}
	}
end:
	unlink(wsock.sun_path);
	exit(exitcode);
}
#endif

int ql_check_directory( char * path,char * file ,char *filep){
	struct stat st;
	int rc;

	sprintf(filep,"%s/%s",path,file);

	rc = stat(filep,&st);
	if (rc == 0) {
	/* file exist */
		return 1;
	}
	else {
		rc = stat(path,&st);
		/* file or directory exist */
		if ( rc == 0) {
			mode_t m = st.st_mode;
			if (S_ISDIR(m)) {
			/* directory exist */
				return 1; 
			}
			return 0;
		}
		else {
			mode_t m = st.st_mode;
			if (S_ISDIR(m)) {
			/* directory exist */
				return rc; 
			}
			else {
				if (mkdir(path, (S_IRUSR | S_IWUSR | S_IRWXU |
						S_IRGRP | S_IWGRP | S_IRWXG |
						S_IROTH | S_IWOTH | S_IRWXO)) == 0) {
					return 1;
				}
				return 0; /* mkdir error */
			}
		}
	}
}





/* ex: ql_mpiexec_start -machinefile file_name -n 4 mcexec a.out arg1 arg2 */
// stdin, stdout, stderr
#define PIPE_HANDLE_NUM 3
int main(int argc, char *argv[])
{
	char *machinefile = NULL;
	char ql_param_file[1024] = ""; /* */
	char ql_sock_path[1024] = "";
	char ql_file[1024] = "";
	char *exe_name =NULL;
	char  tmp[4096];
	struct stat st; /* for file check */
	int fd;
	int i;
	md5_state_t state;
	md5_byte_t digest[16];
	FILE *fp;
	char base[1024]; 
	char *ptr;
	char **a;
	char **b;
	int rc;
	char **env;
	int n;
	int uid;
	char *pt;
	int wfd;
	socklen_t wlen;
	int exitcode = 0;
	char c;

#ifndef QL_MPIEXEC_FINALIZE
	int f_flg = 0;
#endif

	for (a = environ, n = 0; *a; a++, n++);
	for (a = argv; *a; a++) {
		if (!strcmp(*a, "-genv") ||
		    !strcmp(*a, "-env")) {
			n++;
		}
		else if ((!strcmp(*a, "-genvlist") ||
		          !strcmp(*a, "-envlist")) &&
		         a[1]) {
			char *t;

			n++;
			for (t = a[1]; *a; t++)
				if (*t == ',')
					n++;
		}
	}
	env = malloc(sizeof(char *) * (n + 2));
	for (a = environ, b = env; (*b = *a); a++, b++);

	md5_init(&state);
	mpi_opt_top = argv + 1;
	for (a = mpi_opt_top; *a; a++) {
		char *opt;
		const struct mpi_opt *o;
		int i;

		if ((*a)[0] != '-')
			break;
		opt = (*a) + 1;
		for (o = opts; o->opt; o++) {
			if (!strcmp(opt, o->opt))
				break;
		}
		if (!o->opt) {
			fprintf(stderr, "unknown option: %s\n", *a);
			exit(1);
		}
		if (o->n < 0) { // -genv, -env
			a++;
			if (!*a) {
				fprintf(stderr, "bad option: -%s\n", o->opt);
				exit(1);
			}
			if (!strchr(*a, '=')) {
				char *k = *a;
				a++;
				if (!*a) {
					fprintf(stderr, "bad option: -%s\n",
					        o->opt);
					exit(1);
				}
				if (o->flags & ENV_OPT)
					ql_setenv(env, k, *a);
			}
			else {
				if (o->flags & ENV_OPT)
					ql_setenv(env, *a, NULL);
			}
		}
		else {
			for (i = 0; i < o->n; i++) {
				a++;
				if (!*a) {
					fprintf(stderr, "bad option: -%s\n",
					        o->opt);
					exit(1);
				}
			}
			if (o->flags & UNSUPP_OPT) {
					fprintf(stderr, "unsupported option: "
					        "-%s\n", o->opt);
					exit(1);
			}
			if (o->flags & HOSTFILE_OPT)
				machinefile = *a;
			if (o->flags & NODE_OPT) {
				md5_append(&state, (const md5_byte_t *)*a,
				           strlen(*a));
			}
			if (o->flags & ENVNONE_OPT) {
				env[0] = NULL;
			}
			if (o->flags & ENVALL_OPT) {
				for (a = environ, b = env; (*b = *a); a++, b++);
			}
			if (o->flags & ENVLIST_OPT) {
				ql_envlist(env, *a);
			}
		}
	}
	usr_opt_top = a;
	if (!*a) {
		fprintf(stderr, "no user program\n");
		exit(1);
	}
	exe_name = *a;
	md5_append(&state, (const md5_byte_t *)exe_name, strlen(exe_name));

	for (; *a; a++)
		if (!strcmp(*a, ":")) {
			fprintf(stderr, "':' is unsupported\n");
			exit(1);
		}

	if (machinefile) { 
		/* get target_host from -machinefile */
		if (!stat(machinefile, &st)) { /* file exist*/
			char *b;
			size_t siz;
			FILE *f;
			char line[65536];

			siz = st.st_size;
			fd = open(machinefile, O_RDONLY);
			b = mmap(NULL, siz, PROT_READ, MAP_PRIVATE, fd, 0);
			close(fd);
			if (b == (void *)-1) {
				fprintf(stderr, "unable to read hostfile(%s): %s\n", machinefile, strerror(errno));
				exit(1);
			}
			md5_append(&state, (const md5_byte_t *)b, siz);
			munmap(b, siz);

			if (!(f = fopen(machinefile, "r"))) {
				fprintf(stderr, "could not open hostfile(%s): %s\n", machinefile, strerror(errno));
				exit(1);
			}
			while (fgets(line, sizeof line, f)) {
				char *w;
				char *t;
				if ((w = strchr(line, '#')))
					*w = '\0';
				if ((w = strchr(line, ':')))
					*w = '\0';
				if ((w = strchr(line, ',')))
					*w = '\0';
				t = trim(line);
				if ((w = strchr(line, ' ')))
					*w = '\0';
				if ((w = strchr(line, '\t')))
					*w = '\0';
				if (t[0] == '\0')
					continue;
				strcpy(target_host, t);
				break;
			}
			fclose(f);
#ifdef QL_DEBUG
			printf(" target_host %s\n", target_host);
#endif
		}
		else {
			fprintf(stderr, "-machinefile not exist\n");
			exit(1);
		}
	}
	else {
		fprintf(stderr, "specify -machinefile option\n");
		exit(1);
	}

	md5_finish(&state, digest);
	for (i = 0; i < 16; i++) {
		sprintf(ql_name + i * 2, "%02x", digest[i]);
	}
	if ((ptr = getenv(QL_PARAM_ENV)) == NULL) {
		sprintf(base, "%s", getenv("HOME"));
	}
	else{
		sprintf(base, "%s", ptr);
	}

	setenv("QL_NAME", ql_name, 1);
	ql_setenv(env, "QL_NAME", ql_name);

	uid  = (int)getuid();
	if ((pt = getenv(QL_SOCK_ENV)) != NULL) {
		sprintf(ql_sock_path,"%s/%s",pt,QL_SOCK);
	}
	else {
		sprintf(ql_sock_path,"%s/%d/%s",QL_SOCKT_PATH,uid,QL_SOCK); 
	} 
	sprintf(ql_file,"%s.%d", QL_SOCK, uid);

    if(!ql_check_directory(ql_sock_path,ql_file,ql_sock_file)) {
		fprintf(stderr, "socket directory not exist\n");
		exit(1);
	}

	setenv("QL_SOCKET_FILE", ql_sock_file, 1);
#ifdef QL_DEBUG
	printf(" socket path  %s\n", ql_sock_file);
#endif

#ifndef QL_MPIEXEC_FINALIZE
	sprintf(tmp, "ssh %s ""%s %s %s""", target_host, QL_SERVER_EXECUTION ,ql_sock_path ,ql_file);

#ifdef QL_DEBUG
	printf(" system   %s\n", tmp);
#endif
	if((rc = system(tmp)) == -1){
		fprintf(stderr, "ql_server not execution %s", strerror(errno));
		exit(-1);
	}
#endif

	memset(&wsock, '\0', sizeof wsock);
	wsock.sun_family = AF_UNIX;
	sprintf(wsock.sun_path, "%s/%s.s", ql_sock_path, ql_name);
	wlen = sizeof wsock.sun_family + strlen(wsock.sun_path) + 1;

	if(stat(wsock.sun_path, &st)){ /* socket file not exist */
#ifdef QL_MPIEXEC_FINALIZE
		fprintf(stderr,"not found mpi process\n");
		exit(1);
#else
		pid_t pid;
		int wst;

		f_flg = 1;

		if ((wfd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			fprintf(stderr, "ql_mpiexec_start: socket(%s)\n",
			        strerror(errno));
			exit(1);
		}
		if (bind(wfd, (struct sockaddr *)&wsock, wlen) == -1) {
			fprintf(stderr, "ql_mpiexec_start: bind(%s)\n",
			        strerror(errno));
			exit(1);
		}
		if (listen(wfd, 5) == -1) {
			fprintf(stderr, "ql_mpiexec_start: listen(%s)\n",
			        strerror(errno));
			exit(1);
		}

		if ((pid = fork()) == 0) { 
			int i;
			char **args;
			char **b;

			if (fork())
				exit(0);

			setsid();
			if (wfd < 3) {
				dup2(wfd, 3);
				wfd = 3;
			}
			for (i = 0; i < 4096; i++)
				if (i != wfd)
					close(i);
			open("/dev/null", O_RDONLY);
			open("/dev/null", O_WRONLY);
			open("/dev/null", O_WRONLY);

			args = (char **)malloc(sizeof(char *) * (argc + 2));
			*args = "mpiexec";
			for (a = mpi_opt_top, b = args + 1; a != usr_opt_top;
			     a++)
				*(b++) = *a;
			*(b++) = BINDIR "/mcexec";
			for (; *a; a++)
				*(b++) = *a;
			*b = NULL;
			ql_wrapper(args, wfd);
			exit(-1); /*not reach */
		}
		close(wfd);
		while(waitpid(pid, &wst, 0) == -1 && errno == EINTR);
#endif
	}
	else{
		int env_n;
		int arg_n;

		for (arg_n = 0, a = usr_opt_top; *a; a++, arg_n++);
		for (env_n = 0, a = env; *a; a++, env_n++);

		/* param file output */
		sprintf(ql_param_file, "%s/%s%s", base, ql_name, QL_PARAM_EXTE);
		fp = fopen(ql_param_file, "w");
#ifdef QL_MPIEXEC_FINALIZE
		fprintf(fp, "%c COM=%c\n", QL_COMMAND, QL_RET_FINAL);
#else
		fprintf(fp, "%c COM=%c %d %d\n", QL_COMMAND, QL_RET_RESUME,
		        arg_n, env_n);

		for (a = usr_opt_top; *a; a++)
			esc_put(fp, QL_ARG, *a);
		for (a = env; *a; a++)
			esc_put(fp, QL_ENV, *a);
#endif

		fclose(fp);
	}

	if ((wfd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "ql_mpiexec_start: socket(%s)\n",
		        strerror(errno));
		exit(1);
	}
	rc = connect(wfd, (struct sockaddr *)&wsock, wlen);
	if (rc == -1) {
		fprintf(stderr, "ql_mpiexec_start: connect(%s)\n",
		        strerror(errno));
		exit(1);
	}
	write(wfd, "C", 1);
	if ((rc = read(wfd, &c, 1)) <= 0)
		exit(1);
	write(wfd, "0", 1);
	sendfd(wfd, 0);
	if ((rc = read(wfd, &c, 1)) <= 0)
		exit(1);
	write(wfd, "1", 1);
	sendfd(wfd, 1);
	if ((rc = read(wfd, &c, 1)) <= 0)
		exit(1);
	write(wfd, "2", 1);
	sendfd(wfd, 2);
	if ((rc = read(wfd, &c, 1)) <= 0)
		exit(1);

#ifdef QL_MPIEXEC_FINALIZE
	sprintf(tmp,"ssh %s %s %c %s %s %s",
	        target_host, QL_TALKER_EXECUTION, QL_RET_RESUME, "-n", ql_name , ql_sock_file);
	rc = system(tmp);
	write(wfd, "F", 1);
#else
	if (f_flg == 1) {
		sprintf(tmp,"ssh %s %s %c %c %s %s",
		        target_host, QL_TALKER_EXECUTION, QL_COM_CONN,
		        QL_EXEC_END, ql_name ,ql_sock_file);
		rc = system(tmp);
		/* send N and recv E */
	}
	else{
		sprintf(tmp,"ssh %s %s %c %c %s %s",
		        target_host, QL_TALKER_EXECUTION, QL_RET_RESUME,
		        QL_EXEC_END, ql_name , ql_sock_file);
		rc = system(tmp);
		/* send R and recv E */
	}
	write(wfd, "E", 1);
#endif

	if ((rc = read(wfd, &c, 1)) <= 0)
		goto end;
	if (c == 'X') {
		int wst;

		read(wfd, &wst, sizeof st);
		if (WIFSIGNALED(wst)) {
			int sig = WTERMSIG(wst);
			signal(sig, SIG_DFL);
			kill(getpid(), sig);
			pause();
		}
		exitcode = WEXITSTATUS(wst);
	}
	close(wfd);

end:
	unlink(ql_param_file);
	exit(exitcode);
}

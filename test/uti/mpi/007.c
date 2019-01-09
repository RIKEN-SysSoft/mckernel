#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <mpi.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sched.h>
#include <errno.h>
#include <psm2.h>     /* required for core PSM2 functions */
#include <psm2_mq.h>  /* required for PSM2 MQ functions (send, recv, etc) */
#include "util.h"
#include "fwq.h"

//#define DEBUG
#ifdef DEBUG
#define dprintf printf
#else
#define dprintf {}
#endif

#define BUFFER_LENGTH 8000000
#define CONNECT_ARRAY_SIZE 8
void die(char *msg, int rc)
{
	fprintf(stderr, "%s: %d\n", msg, rc);
	exit(1);
}

static inline int on_same_node(int ppn, int me, int you)
{
	return (me / ppn == you / ppn);
}

/* isend-calc-wait */
void my_send(int nproc, int ppn, int rank, double *sbuf, double *rbuf,
	     int ndoubles, MPI_Request *reqs, long calc_nsec)
{
	int i;
	int r = 0, s = 0;
	int req = 0;

	for (i = 0; i < nproc; i++) {
		if (!on_same_node(ppn, rank, i)) {
			MPI_Irecv(rbuf + r * ndoubles, ndoubles, MPI_DOUBLE,
				  i, 0, MPI_COMM_WORLD, &reqs[req]);
			r++;
			req++;
			MPI_Isend(sbuf + s * ndoubles, ndoubles, MPI_DOUBLE,
				  i, 0, MPI_COMM_WORLD, &reqs[req]);
			s++;
			req++;
		}
	}
	fwq(calc_nsec);
	MPI_Waitall(req, reqs, MPI_STATUSES_IGNORE);
}


/* Helper functions to find the server's PSM2 endpoint identifier (epid). */
psm2_epid_t find_server(int rank)
{
	FILE *fp = NULL;
	psm2_epid_t server_epid = 0;
	char fn[256];

	sprintf(fn, "psm2-demo-server-epid-%d", rank);
	printf("PSM2 client waiting for epid mapping file to appear...\n");
	while (!fp) {
		sleep(1);
		fp = fopen(fn, "r");
	}
	fscanf(fp, "%lx", &server_epid);
	fclose(fp);
	printf("PSM2 client found server epid = 0x%lx\n", server_epid);
	return server_epid;
}

void write_epid_to_file(int rank, psm2_epid_t myepid)
{
	FILE *fp;
	char fn[256];

	sprintf(fn, "psm2-demo-server-epid-%d", rank);
	fp = fopen(fn, "w");
	if (!fp) {
		fprintf(stderr,
			"Exiting, couldn't write server's epid mapping file: ");
		die(strerror(errno), errno);
	}
	fprintf(fp, "0x%lx", myepid);
	fclose(fp);
	printf("PSM2 server wrote epid = 0x%lx to file.\n", myepid);
}

int psm2_sendrecv(int rank, int sender, int receiver)
{
	struct psm2_ep_open_opts o;
	psm2_uuid_t uuid;
	psm2_ep_t myep;
	psm2_epid_t myepid;
	psm2_epid_t server_epid;
	psm2_epid_t epid_array[CONNECT_ARRAY_SIZE];
	int epid_array_mask[CONNECT_ARRAY_SIZE];
	psm2_error_t epid_connect_errors[CONNECT_ARRAY_SIZE];
	psm2_epaddr_t epaddr_array[CONNECT_ARRAY_SIZE];
	int rc;
	int ver_major = PSM2_VERNO_MAJOR;
	int ver_minor = PSM2_VERNO_MINOR;
	char msgbuf[BUFFER_LENGTH];
	psm2_mq_t q;
	psm2_mq_req_t req_mq;

	memset(uuid, 0, sizeof(psm2_uuid_t)); /* Use a UUID of zero */
	/* Try to initialize PSM2 with the requested library version.
	 * In this example, given the use of the PSM2_VERNO_MAJOR and MINOR
	 * as defined in the PSM2 headers, ensure that we are linking with
	 * the same version of PSM2 as we compiled against.
	 */

	if ((rc = psm2_init(&ver_major, &ver_minor)) != PSM2_OK) {
		die("couldn't init", rc);
	}
	printf("PSM2 init done.\n");
	/* Setup the endpoint options struct */
	if ((rc = psm2_ep_open_opts_get_defaults(&o)) != PSM2_OK) {
		die("couldn't set default opts", rc);
	}
	printf("PSM2 opts_get_defaults done.\n");
	/* Attempt to open a PSM2 endpoint. This allocates hardware resources.
	 */
	if ((rc = psm2_ep_open(uuid, &o, &myep, &myepid)) != PSM2_OK) {
		die("couldn't psm2_ep_open()", rc);
	}
	printf("PSM2 endpoint open done.\n");
	int is_server = (rank == receiver) ? 1 : 0;

	if (is_server) {
		write_epid_to_file(rank, myepid);
	} else {
		server_epid = find_server(receiver);
	}
	if (is_server) {
		/* Server does nothing here. A connection does not have to be
		 * established to receive messages.
		 */
		printf("PSM2 server up.\n");
	} else {
		/* Setup connection request info.
		 * PSM2 can connect to a single epid per request,
		 * or an arbitrary number of epids in a single connect call.
		 * For this example, use part of an array of
		 * connection requests.
		 */
		memset(epid_array_mask, 0, sizeof(int) * CONNECT_ARRAY_SIZE);
		epid_array[0] = server_epid;
		epid_array_mask[0] = 1;
		/* Begin the connection process.
		 * note that if a requested epid is not responding,
		 * the connect call will still return OK.
		 * The errors array will contain the state of individual
		 * connection requests.
		 */
		if ((rc = psm2_ep_connect(myep,
					  CONNECT_ARRAY_SIZE,
					  epid_array,
					  epid_array_mask,
					  epid_connect_errors,
					  epaddr_array,
					  0 /* no timeout */
					  )) != PSM2_OK) {
			die("couldn't ep_connect", rc);
		}
		printf("PSM2 connect request processed.\n");
		/* Now check if our connection to the server is ready */
		if (epid_connect_errors[0] != PSM2_OK) {
			die("couldn't connect to server",
			    epid_connect_errors[0]);
		}
		printf("PSM2 client-server connection established.\n");
	}
	/* Setup our PSM2 message queue */
	if ((rc = psm2_mq_init(myep, PSM2_MQ_ORDERMASK_NONE, NULL, 0, &q))
	    != PSM2_OK) {
		die("couldn't initialize PSM2 MQ", rc);
	}
	printf("PSM2 MQ init done.\n");
	if (is_server) {
		psm2_mq_tag_t t = {0xABCD};
		psm2_mq_tag_t tm = {-1};
		/* Post the receive request */
		if ((rc = psm2_mq_irecv2(q, PSM2_MQ_ANY_ADDR,
					 &t, /* message tag */
					 &tm, /* message tag mask */
					 0, /* no flags */
					 msgbuf, BUFFER_LENGTH,
					 NULL, /* no context to add */
					 &req_mq /* track irecv status */
					 )) != PSM2_OK) {
			die("couldn't post psm2_mq_irecv()", rc);
		}
		printf("PSM2 MQ irecv() posted\n");
		/* Wait until the message arrives */
		if ((rc = psm2_mq_wait(&req_mq, NULL)) != PSM2_OK) {
			die("couldn't wait for the irecv", rc);
		}
		printf("PSM2 MQ wait() done.\n");
		printf("Message from client:\n");
		printf("%s", msgbuf);
		unlink("psm2-demo-server-epid");
	} else {
		/* Say hello */
		snprintf(msgbuf, BUFFER_LENGTH,
			 "Hello world from epid=0x%lx, pid=%d.\n",
			 myepid, getpid());
		psm2_mq_tag_t t = {0xABCD};

		if ((rc = psm2_mq_send2(q,
					epaddr_array[0], /* destination epaddr */
					PSM2_MQ_FLAG_SENDSYNC, /* no flags */
					&t, /* tag */
					msgbuf, BUFFER_LENGTH
					)) != PSM2_OK) {
			die("couldn't post psm2_mq_isend", rc);
		}
		printf("PSM2 MQ send() done.\n");
	}
	/* Close down the MQ */
	if ((rc = psm2_mq_finalize(q)) != PSM2_OK) {
		die("couldn't psm2_mq_finalize()", rc);
	}
	printf("PSM2 MQ finalized.\n");
	/* Close our ep, releasing all hardware resources.
	 * Try to close all connections properly
	 */
	if ((rc = psm2_ep_close(myep, PSM2_EP_CLOSE_GRACEFUL,
				0 /* no timeout */)) != PSM2_OK) {
		die("couldn't psm2_ep_close()", rc);
	}
	printf("PSM2 ep closed.\n");
	/* Release all local PSM2 resources */
	if ((rc = psm2_finalize()) != PSM2_OK) {
		die("couldn't psm2_finalize()", rc);
	}
	printf("PSM2 shut down, exiting.\n");
	return 0;
}

static struct option options[] = {
	{
		.name =		"ppn",
		.has_arg =	required_argument,
		.flag =		NULL,
		.val =		'P',
	},
	/* end */
	{ NULL, 0, NULL, 0, },
};

struct thr_arg {
	volatile int bar_count; /* Barrier before entering loop */
	pthread_mutex_t bar_lock;
	pthread_cond_t bar_cond;
	pthread_t pthread;
	int rank;
	int ppn;
	int nproc;
};

struct thr_arg thr_arg;

void *progress_fn(void *arg)
{
	struct thr_arg *thr_arg = (struct thr_arg *)arg;
	int rc;
	int i;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stdout, "CT09100 %s running on Linux OK\n",
			__func__);
	else {
		fprintf(stdout,
			"CT09100 %s running on McKernel NG (%d)\n",
			__func__, rc);
	}

	printf("progress,enter\n");

	/* barrier */
	pthread_mutex_lock(&thr_arg->bar_lock);
	thr_arg->bar_count++;
	if (thr_arg->bar_count == 2) {
		if ((rc = pthread_cond_broadcast(&thr_arg->bar_cond))) {
			printf("pthread_cond_broadcast failed,rc=%d\n", rc);
		}
	}
	while (thr_arg->bar_count != 2) {
		if ((rc = pthread_cond_wait(&thr_arg->bar_cond,
					    &thr_arg->bar_lock))) {
			printf("pthread_cond_wait failed,rc=%d\n", rc);
		}
	}
	pthread_mutex_unlock(&thr_arg->bar_lock);

	printf("progress,after barrier\n");
#if 1
	for (i = 0; i < thr_arg->nproc; i++) {
		if (!on_same_node(thr_arg->ppn, thr_arg->rank, i)) {
			if (thr_arg->rank < i) {
				psm2_sendrecv(thr_arg->rank, thr_arg->rank, i);
			} else {
				psm2_sendrecv(thr_arg->rank, i, thr_arg->rank);
			}
		}
	}
#endif

	/* barrier */
	pthread_mutex_lock(&thr_arg->bar_lock);
	thr_arg->bar_count--;
	if (thr_arg->bar_count == 0) {
		if ((rc = pthread_cond_broadcast(&thr_arg->bar_cond))) {
			printf("pthread_cond_broadcast failed,rc=%d\n", rc);
		}
	}
	while (thr_arg->bar_count != 0) {
		if ((rc = pthread_cond_wait(&thr_arg->bar_cond,
					    &thr_arg->bar_lock))) {
			printf("pthread_cond_wait failed,rc=%d\n", rc);
		}
	}
	pthread_mutex_unlock(&thr_arg->bar_lock);


	printf("progress,exit\n");
	return NULL;
}

int main(int argc, char **argv)
{
	int rc;
	int actual;
	int nproc;
	int ppn = -1;
	int ndoubles = -1;
	int my_rank = -1, size = -1;
	int i, j;
	double *sbuf, *rbuf;
	MPI_Request *reqs;
	struct timespec start, end;
	long t_pure_l, t_overall_l;
	long t_pure, t_overall;
	int opt;
	pthread_condattr_t condattr;
	pthread_mutexattr_t mutexattr;

	fwq_init();

	while ((opt = getopt_long(argc, argv, "+d:P:", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			ndoubles = (1ULL << atoi(optarg));
			break;
		case 'P':
			ppn = atoi(optarg);
			break;
		default: /* '?' */
			printf("unknown option %c\n", optopt);
			exit(1);
		}
	}

	if (ndoubles == -1 || ppn == -1) {
		printf("specify ndoubles with -d and ppn with --ppn");
		exit(1);
	}

	char *rank_str = getenv("PMI_RANK");

	if (!rank_str) {
		printf("getenv failed\n");
		exit(1);
	}
	my_rank = atoi(rank_str);
	nproc = 2;

	if (my_rank == 0) {
		printf("tid=%d,pid=%d,ndoubles=%d,nproc=%d\n",
		       syscall(__NR_gettid), getpid(), ndoubles, nproc);
		printf("nsec=%ld, nspw=%f\n", nsec, nspw);
	}

	/* Spawn a thread */
	thr_arg.rank = my_rank;
	thr_arg.ppn = ppn;
	thr_arg.nproc = nproc;
	thr_arg.bar_count = 0;

	pthread_condattr_init(&condattr);
	pthread_cond_init(&thr_arg.bar_cond, &condattr);

	pthread_mutexattr_init(&mutexattr);
	pthread_mutex_init(&thr_arg.bar_lock, &mutexattr);

	char *uti_str = getenv("DISABLE_UTI");
	int uti_val = uti_str ? atoi(uti_str) : 0;

	if (!uti_val) {
		rc = syscall(731, 1, NULL);
		if (rc) {
			fprintf(stdout,
				"CT09003 INFO: uti not available (rc=%d)\n",
				rc);
		} else {
			fprintf(stdout, "CT09003 INFO: uti available\n");
		}
	} else {
		fprintf(stdout, "CT09003 INFO: uti disabled\n");
	}

	rc = pthread_create(&thr_arg.pthread, NULL, progress_fn, &thr_arg);
	if (rc) {
		fprintf(stdout, "pthread_create: %d\n", rc);
		exit(1);
	}

	/* barrier */
	pthread_mutex_lock(&thr_arg.bar_lock);
	thr_arg.bar_count++;
	if (thr_arg.bar_count == 2) {
		if ((rc = pthread_cond_broadcast(&thr_arg.bar_cond))) {
			printf("pthread_cond_broadcast failed,rc=%d\n", rc);
		}
	}
	while (thr_arg.bar_count != 2) {
		if ((rc = pthread_cond_wait(&thr_arg.bar_cond,
					    &thr_arg.bar_lock))) {
			printf("pthread_cond_wait failed,rc=%d\n", rc);
		}
	}
	pthread_mutex_unlock(&thr_arg.bar_lock);

	printf("parent,after barrier\n");


	print_cpu_last_executed_on("main");

	/* barrier */
	pthread_mutex_lock(&thr_arg.bar_lock);
	thr_arg.bar_count--;
	if (thr_arg.bar_count == 0) {
		if ((rc = pthread_cond_broadcast(&thr_arg.bar_cond))) {
			printf("pthread_cond_broadcast failed,rc=%d\n", rc);
		}
	}
	while (thr_arg.bar_count != 0) {
		if ((rc = pthread_cond_wait(&thr_arg.bar_cond,
					    &thr_arg.bar_lock))) {
			printf("pthread_cond_wait failed,rc=%d\n", rc);
		}
	}
	pthread_mutex_unlock(&thr_arg.bar_lock);


	pthread_join(thr_arg.pthread, NULL);

 fn_exit:
	return 0;
 fn_fail:
	goto fn_exit;
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sched.h>
#include <errno.h>
#include <pthread.h>
#include <psm2.h>     /* required for core PSM2 functions */
#include <psm2_mq.h>  /* required for PSM2 MQ functions (send, recv, etc) */

#define BUFFER_LENGTH /*8000000*/(1ULL<<12)
#define CONNECT_ARRAY_SIZE 8

void die(char *msg, int rc)
{
	fprintf(stderr, "%s: %d\n", msg, rc);
	fflush(stderr);
}

static inline int on_same_node(int ppn, int me, int you)
{
	return (me / ppn == you / ppn);
}

/* Helper functions to find the server's PSM2 endpoint identifier (epid). */
psm2_epid_t find_server(int rank)
{
	FILE *fp = NULL;
	psm2_epid_t server_epid = 0;
	char fn[256];

	sprintf(fn, "%s/tmp/psm2-demo-server-epid-%d", getenv("HOME"), rank);
	printf("client: waiting for epid file to appear...\n");
	while (!fp) {
		usleep(250*1000);
		fp = fopen(fn, "r");
	}
	fscanf(fp, "%lx", &server_epid);
	fclose(fp);
	printf("client: found server epid = 0x%lx.\n", server_epid);
	return server_epid;
}

void write_epid_to_file(int rank, psm2_epid_t myepid)
{
	FILE *fp;
	char fn[256];

	sprintf(fn, "%s/tmp/psm2-demo-server-epid-%d", getenv("HOME"), rank);
	fp = fopen(fn, "w");
	if (!fp) {
		fprintf(stderr,
			"Exiting, couldn't write server's epid mapping file: ");
		die(strerror(errno), errno);
	}
	fprintf(fp, "0x%lx", myepid);
	fclose(fp);
	printf("server: wrote epid = 0x%lx to file.\n", myepid);
}

psm2_uuid_t uuid;
psm2_ep_t myep;
psm2_epid_t myepid;
psm2_epid_t server_epid;
psm2_epid_t epid_array[CONNECT_ARRAY_SIZE];
int epid_array_mask[CONNECT_ARRAY_SIZE];
psm2_error_t epid_connect_errors[CONNECT_ARRAY_SIZE];
psm2_epaddr_t epaddr_array[CONNECT_ARRAY_SIZE];

int my_psm2_init(int my_rank, int server_rank)
{
	struct psm2_ep_open_opts o;
	int rc;
	int ver_major = PSM2_VERNO_MAJOR;
	int ver_minor = PSM2_VERNO_MINOR;

	memset(uuid, 0, sizeof(psm2_uuid_t)); /* Use a UUID of zero */

	/* Try to initialize PSM2 with the requested library version.
	 * In this example, given the use of the PSM2_VERNO_MAJOR and MINOR
	 * as defined in the PSM2 headers, ensure that we are linking with
	 * the same version of PSM2 as we compiled against.
	 */

	if ((rc = psm2_init(&ver_major, &ver_minor)) != PSM2_OK) {
		die("couldn't init", rc);
	}
	printf("%s: PSM2 init done.\n",
	       my_rank == server_rank ? "server" : "client");

	/* Setup the endpoint options struct */
	if ((rc = psm2_ep_open_opts_get_defaults(&o)) != PSM2_OK) {
		die("couldn't set default opts", rc);
	}
	printf("%s: PSM2 opts_get_defaults done.\n",
	       my_rank == server_rank ? "server" : "client");

	/* Attempt to open a PSM2 endpoint.
	 * This allocates hardware resources.
	 */
	if ((rc = psm2_ep_open(uuid, &o, &myep, &myepid)) != PSM2_OK) {
		die("couldn't psm2_ep_open()", rc);
	}
	printf("%s: PSM2 endpoint open done.\n",
	       my_rank == server_rank ? "server" : "client");

	return 0;
}

psm2_mq_t q;

int my_psm2_connect(int my_rank, int server_rank)
{
	int rc;
	int is_server = (my_rank == server_rank) ? 1 : 0;

	if (is_server) {
		write_epid_to_file(my_rank, myepid);
	} else {
		server_epid = find_server(server_rank);
	}

	if (is_server) {
		/* Server does nothing here. A connection does not have to be
		 * established to receive messages.
		 */
		printf("server: waiting for connection...\n");
	} else {
		int count = 0;

		/* Setup connection request info */
		/* PSM2 can connect to a single epid per request,
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
		printf("client: connecting to server...");
		while ((rc = psm2_ep_connect(myep,
					     CONNECT_ARRAY_SIZE,
					     epid_array,
					     epid_array_mask,
					     epid_connect_errors,
					     epaddr_array,
					     1 /* 0.5 sec timeout */
					     )) != PSM2_OK) {
			struct timespec ts = {
				.tv_sec = 0, .tv_nsec = 500*1000*1000 };

			nanosleep(&ts, NULL);
			printf("."); fflush(stdout);
			count++;
			if (count > 30) {
				break;
			}
		}

		if (rc != PSM2_OK) {
			printf("client: psm2_ep_connect timed-out\n");
			return -1;
		}

		/* Now check if our connection to the server is ready */
		if (epid_connect_errors[0] != PSM2_OK) {
			die("couldn't connect to server",
			    epid_connect_errors[0]);
			return -1;
		}
		printf(" success\n");
	}

	/* Setup our PSM2 message queue */
	if ((rc = psm2_mq_init(myep, PSM2_MQ_ORDERMASK_NONE, NULL, 0, &q))
	    != PSM2_OK) {
		die("couldn't initialize PSM2 MQ", rc);
	}
	printf("%s: psm2_mq_init() succeeded\n",
	       is_server ? "server" : "client");

	return 0;
}
char msgbuf[BUFFER_LENGTH];

int my_psm2_sendrecv(int rank, int sender, int receiver)
{
	int is_server = (rank == receiver) ? 1 : 0;
	int rc;
	psm2_mq_req_t req_mq;
	//char msgbuf[BUFFER_LENGTH];

	memset(msgbuf, 0, BUFFER_LENGTH);

	if (is_server) {
		psm2_mq_tag_t t = { .tag0 = 0xABCD};
		psm2_mq_tag_t tm = { .tag0 = -1, .tag1 = 0, .tag2 = 0 };



		/* Post the receive request */
		printf("server: calling psm2_mq_irecv()...");
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
		printf(" success\n");

#if 1
		/* Wait until the message arrives */
		if ((rc = psm2_mq_wait(&req_mq, NULL)) != PSM2_OK) {
			die("couldn't wait for the irecv", rc);
		}

		printf("server: message received: %s", msgbuf);

		if (is_server) {
			char fn[256];

			sprintf(fn, "%s/tmp/psm2-demo-server-epid-%d",
				getenv("HOME"), rank);
			unlink(fn);
		}
#else
		int count = 0;

		while ((rc = psm2_mq_ipeek(q, &req_mq, NULL)) != PSM2_OK) {
			struct timespec ts = {
				.tv_sec = 0, .tv_nsec = 500*1000*1000 };
			nanosleep(&ts, NULL);
			printf("."); fflush(stdout);
			count++;
			if (count > 2) {
				break;
			}
		}
		if (rc == PSM2_OK) {
			char fn[256];

			if ((rc = psm2_mq_test(&req_mq, NULL)) != PSM2_OK) {
				printf("psm2_mq_test failed\n");
			} else  {
				printf("PSM2 MQ test() done.\n");
				printf("Message from client:\n");
				printf("%s", msgbuf);
			}
			sprintf(fn, "psm2-demo-server-epid-%d", rank);
			unlink(fn);
		} else {
			printf("PSM2 MQ test() timed-out.\n");
		}
#endif
	} else {
		/* Say hello */
		snprintf(msgbuf, BUFFER_LENGTH,
			 "Hello world from epid=0x%lx, pid=%d.\n",
			 myepid, getpid());
		psm2_mq_tag_t t = { .tag0 = 0xABCD };
#if 1
		if ((rc = psm2_mq_send2(q,
					epaddr_array[0], /* dest epaddr */
					PSM2_MQ_FLAG_SENDSYNC, /* no flags */
					&t, /* tag */
					msgbuf, BUFFER_LENGTH
					)) != PSM2_OK) {
			die("couldn't post psm2_mq_isend", rc);
		}
		printf("client: psm2_mq_send2() succeeded\n");
#else
		if ((rc = psm2_mq_isend2(q,
					 epaddr_array[0], /* dest epaddr */
					 PSM2_MQ_FLAG_SENDSYNC, /* no flags */
					 &t, /* tag */
					 msgbuf, BUFFER_LENGTH,
					 NULL, /* no context to add */
					 &req_mq /* track irecv status */
					 )) != PSM2_OK) {
			die("couldn't post psm2_mq_isend", rc);
		}
		printf("PSM2 MQ isend() posted\n");

		int count = 0;

		while ((rc = psm2_mq_ipeek2(q, &req_mq, NULL)) != PSM2_OK) {
			struct timespec ts = {
				.tv_sec = 0, .tv_nsec = 500*1000*1000 };

			nanosleep(&ts, NULL);
			printf("."); fflush(stdout);
			count++;
			if (count > 30) {
				break;
			}
		}
		if (rc == PSM2_OK) {
			if ((rc = psm2_mq_test2(&req_mq, NULL)) != PSM2_OK) {
				printf("PSM2 MQ test() failed.\n");
			} else {
				printf("PSM2 MQ test() done.\n");
			}
		} else {
			printf("PSM2 MQ test() timeout.\n");
		}
#endif
	}
	/* Close down the MQ */
	if ((rc = psm2_mq_finalize(q)) != PSM2_OK) {
		die("couldn't psm2_mq_finalize()", rc);
	}
	printf("%s: psm2_mq_finalize() succeeded\n",
	       is_server ? "server" : "client");

	/* Close our ep, releasing all hardware resources.
	 * Try to close all connections properly
	 */
	if ((rc = psm2_ep_close(myep, PSM2_EP_CLOSE_GRACEFUL,
				0 /* no timeout */)) != PSM2_OK) {
		die("couldn't psm2_ep_close()", rc);
	}
	printf("%s: psm2_ep_close() succeeded\n",
	       is_server ? "server" : "client");

	/* Release all local PSM2 resources */
	if ((rc = psm2_finalize()) != PSM2_OK) {
		die("couldn't psm2_finalize()", rc);
	}
	printf("%s: psm2_finalize() succeeded\n",
	       is_server ? "server" : "client");
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
	pthread_barrier_t bar;
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
		fprintf(stdout, "%s: Progress thread is running on Linux\n",
			thr_arg->rank != 0 ? "server" : "client");
	else {
		fprintf(stdout, "%s: progress thread is running on McKernel\n",
			thr_arg->rank != 0 ? "server" : "client");
	}

	pthread_barrier_wait(&thr_arg->bar);

	for (i = 0; i < thr_arg->nproc; i++) {
		if (!on_same_node(thr_arg->ppn, thr_arg->rank, i)) {
			if (thr_arg->rank < i) {
				my_psm2_sendrecv(thr_arg->rank, thr_arg->rank,
						 i);
			} else {
				my_psm2_sendrecv(thr_arg->rank, i,
						 thr_arg->rank);
			}
		}
	}

	pthread_barrier_wait(&thr_arg->bar);

	return NULL;
}

int main(int argc, char **argv)
{
	int rc;
	int nproc;
	int ppn = -1;
	int my_rank = -1;
	int opt;
	pthread_barrierattr_t barrierattr;

	while ((opt = getopt_long(argc, argv, "+P:", options, NULL)) != -1) {
		switch (opt) {
		case 'P':
			ppn = atoi(optarg);
			break;
		default: /* '?' */
			printf("unknown option %c\n", optopt);
			exit(1);
		}
	}

	if (ppn == -1) {
		printf("specify ppn with --ppn");
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
		printf("tid=%ld,pid=%d,nproc=%d\n",
		       syscall(__NR_gettid), getpid(), nproc);
	}

	int server_rank = ppn + (my_rank % ppn);

	my_psm2_init(my_rank, server_rank);
	my_psm2_connect(my_rank, server_rank);

	/* Spawn a thread */
	thr_arg.rank = my_rank;
	thr_arg.ppn = ppn;
	thr_arg.nproc = nproc;

	pthread_barrierattr_init(&barrierattr);
	pthread_barrier_init(&thr_arg.bar, &barrierattr, nproc);

	char *uti_str = getenv("DISABLE_UTI");
	int uti_val = uti_str ? atoi(uti_str) : 0;

	if (!uti_val) {
		rc = syscall(731, 1, NULL);
		if (rc) {
			printf("%s: uti not available (rc=%d)\n",
				my_rank != 0 ? "server" : "client", rc);
		} else {
			printf("%s: uti available\n",
				my_rank != 0 ? "server" : "client");
		}
	} else {
		printf("%s: uti disabled\n",
			my_rank != 0 ? "server" : "client");
	}

	rc = pthread_create(&thr_arg.pthread, NULL, progress_fn, &thr_arg);
	if (rc) {
		printf("pthread_create: %d\n", rc);
		exit(1);
	}

	pthread_barrier_wait(&thr_arg.bar);

	pthread_barrier_wait(&thr_arg.bar);

	pthread_join(thr_arg.pthread, NULL);

	return 0;
}

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <signal.h>

#define DEBUG

#ifdef DEBUG
#define	dprintf(...)											\
	do {														\
		char msg[1024];											\
		sprintf(msg, __VA_ARGS__);								\
		fprintf(stdout, "%s,%s", __FUNCTION__, msg);			\
	} while (0);
#define	eprintf(...)											\
	do {														\
		char msg[1024];											\
		sprintf(msg, __VA_ARGS__);								\
		fprintf(stdout, "%s,%s", __FUNCTION__, msg);			\
	} while (0);
#else
#define dprintf(...) do {  } while (0)
#define eprintf(...) do {  } while (0)
#endif

#define NPROC 1
#define MAX_NOPS 10
int NOPS=1;/* RDMA:1, accumulate:10 */
#define TS2NS(sec, nsec) ((unsigned long)(sec) * 1000000000ULL + (unsigned long)(nsec))
#define CALC_CPU  (100000)  /* 100,000 nsec, CPU time for calculation */
#define I2R_OCC     ( 200)  /*  200 nsec, occupation time for for sending AM packet */
#define I2R_NET     (1000)  /*  1,000   nsec, Network time for packet to arrive at responder  */
int R2I_OCC=    (10200/*400*/);  /*  RDMA:10,200 nsec, accumulate:400ns, occupation time for perforing accumulate or RDMA-RD and sending ACK packet . Note that 10GB/s means 100KB/10,000 ns */
#define R2I_NET     (1000)  /*  1000   nsec, Network time for packet to arrive at initiator */
#define POLL_CPU       ( 200) /*  200 nsec, CPU time for checking DRAM event queue */
#define REQ_UPDATE_CPU ( 200) /*  200 nsec, CPU time for updates MPI_Request */
#define NSPIN 1
static inline void fixed_size_work() {
	asm volatile(
	    "movq $0, %%rcx\n\t"
		"1:\t"
		"addq $1, %%rcx\n\t"
		"cmpq $99, %%rcx\n\t"
		"jle 1b\n\t"
		:
		: 
		: "rcx", "cc");
}

static inline void bulk_fsw(unsigned long n) {
	int j;
	for (j = 0; j < (n); j++) {
		fixed_size_work(); 
	} 
}

struct thr_arg {
	int rank;
	volatile int bar_count; /* Barrier before entering loop */
	pthread_mutex_t bar_lock;
	pthread_cond_t bar_cond;
	pthread_t pthread;

	pthread_mutex_t ep_lock; /* mutex for endpoint manipulation */
	volatile long ini_ev[MAX_NOPS]; /* events on the responder */
	volatile long res_ev[MAX_NOPS]; /* events on the initiator */
	volatile int terminate;
	long ini_busy; /* Initiator is busy sending AM packet or RTS packet etc. */
	long res_busy; /* Responder is busy doing accumulate or RDMA-RD etc. */
};

struct per_proc {
	int rank;
	struct thr_arg thr_arg;
	long nsec;

};

struct proc_glb {
	struct per_proc per_procs[NPROC];
	volatile int bar_count;
	pthread_mutex_t bar_lock;
	pthread_cond_t bar_cond;
};

struct proc_glb *proc_glb;

unsigned long mem; /* Per-thread storage */
int wps = 1; /* work per sec */
double nspw; /* nsec per work */

#define N_INIT 10000000

int progress_responder(struct thr_arg *thr_arg) {
	int ret = 0;
	int j;
	struct timespec now_ts;
	long now_long;
	clock_gettime(CLOCK_REALTIME, &now_ts);
	now_long = TS2NS(now_ts.tv_sec, now_ts.tv_nsec);

	pthread_mutex_lock(&thr_arg->ep_lock); /* This lock is for consistency */
	for (j = 0; j < NOPS; j++) {
		if (thr_arg->res_busy <= now_long && thr_arg->res_ev[j] && thr_arg->res_ev[j] <= now_long) {
			//if(thr_arg->rank == 0) { printf("res_ev=%ld,busy=%ld,now=%ld\n", thr_arg->res_ev[j] % 1000000000UL, thr_arg->res_busy % 1000000000UL, now_long  % 1000000000UL); }
			thr_arg->ini_ev[j] = now_long + R2I_OCC + R2I_NET;
			thr_arg->res_ev[j] = 0;
			thr_arg->res_busy = now_long + R2I_OCC; /* responder is busy for AM or RDMA-RD etc. */
			ret = 1;
		}
	}
	pthread_mutex_unlock(&thr_arg->ep_lock);
	return ret;
}

int progress_initiator(struct thr_arg* thr_arg) {
	int ret = 0;
	int j;
	struct timespec now_ts;
	long now_long;
	clock_gettime(CLOCK_REALTIME, &now_ts);
	now_long = TS2NS(now_ts.tv_sec, now_ts.tv_nsec);

	pthread_mutex_lock(&thr_arg->ep_lock);
	for (j = 0; j < NOPS; j++) {
		//if(thr_arg->rank == 0) { printf("ini_ev=%ld,now=%ld\n", thr_arg->ini_ev[j], now_long); }
		if (thr_arg->ini_busy <= now_long && thr_arg->ini_ev[j] && thr_arg->ini_ev[j] <= now_long) {
			fwq(POLL_CPU); /* Account for cache miss */
			fwq(REQ_UPDATE_CPU);
			now_long += POLL_CPU + REQ_UPDATE_CPU;
			thr_arg->ini_ev[j] = 0; /* Event is consumed */
			thr_arg->ini_busy = now_long;
			ret = 1;
		}
	}
	pthread_mutex_unlock(&thr_arg->ep_lock);
	return ret;
}

void *progress_fn(void *arg) {
	struct thr_arg *thr_arg = (struct thr_arg *)arg;
	int rc;
	int spin_count = 0;
	int i, j;
	struct timespec now_ts;
	long now_long;
	
	rc = syscall(732);
	if (rc == -1)
		fprintf(stdout, "CT09100 progress_fn running on Linux OK\n");
	else {
		fprintf(stdout, "CT09100 progress_fn running on McKernel NG\n", rc);
	}

	printf("progress,enter,rank=%d\n", thr_arg->rank);

	pthread_mutex_lock(&thr_arg->bar_lock);
	thr_arg->bar_count++;
	if (thr_arg->bar_count == 2) {
		if ((rc = pthread_cond_broadcast(&thr_arg->bar_cond))) {
			printf("[%d] pthread_cond_broadcast failed,rc=%d\n", thr_arg->rank, rc);
		}
	}
	while (thr_arg->bar_count != 2) {
		if ((rc = pthread_cond_wait(&thr_arg->bar_cond, &thr_arg->bar_lock))) {
			printf("[%d] pthread_cond_wait failed,rc=%d\n", thr_arg->rank, rc);
		}
    }
	pthread_mutex_unlock(&thr_arg->bar_lock);

	printf("[%d] progress,after barrier\n", thr_arg->rank);
	//#define NO_ASYNC
#ifdef NO_ASYNC
	return NULL;
#endif
	/* Start progress */
	while(1) {
		if (thr_arg->terminate) {
			break;
		}

		if (progress_responder(thr_arg)) {
			//if (thr_arg->rank == 0) { printf("progress_fn, responder progressed\n"); }
		}

		if (progress_initiator(thr_arg)) {
			//if (thr_arg->rank == 0) { printf("progress_fn, initiator progressed\n"); }
		}

		spin_count++;
		if (spin_count >= NSPIN) {
			spin_count = 0;
			sched_yield();
		}
	}
	printf("progress,exit,rank=%d\n", thr_arg->rank);
	return NULL;
}

void parent_fn(struct per_proc *per_proc) {
	int i, j;
	int rc;
	char* uti_str;
	int uti_val;
	struct timespec start, end;
	pthread_condattr_t condattr;
	pthread_mutexattr_t mutexattr;
	struct timespec now_ts;
	long now_long;

	printf("[%d] parent_fn,enter,proc_glb=%p,bar_count=%d\n", per_proc->rank, proc_glb, proc_glb->bar_count);

	pthread_mutex_lock(&proc_glb->bar_lock);
	proc_glb->bar_count++;
	if (proc_glb->bar_count == NPROC) {
		if ((rc = pthread_cond_broadcast(&proc_glb->bar_cond))) {
			printf("[%d] pthread_cond_broadcast failed,rc=%d\n", per_proc->rank, rc);
		}
	}
	while (proc_glb->bar_count != NPROC) {
		if ((rc = pthread_cond_wait(&proc_glb->bar_cond, &proc_glb->bar_lock))) {
			printf("[%d] pthread_cond_wait failed,rc=%d\n", per_proc->rank, rc);
		}
    }
	pthread_mutex_unlock(&proc_glb->bar_lock);

	//printf("[%d] parent,after barrier\n", per_proc->rank);

	pthread_mutexattr_init(&mutexattr);
	//pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&per_proc->thr_arg.ep_lock, &mutexattr);

	per_proc->thr_arg.bar_count = 0;

	pthread_condattr_init(&condattr);
	//pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED);
	pthread_cond_init(&per_proc->thr_arg.bar_cond, &condattr);

	pthread_mutexattr_init(&mutexattr);
	//pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&per_proc->thr_arg.bar_lock, &mutexattr);

	uti_str = getenv("DISABLE_UTI");
	uti_val = uti_str ? atoi(uti_str) : 0;
	if (!uti_val) {
		rc = syscall(731, 1, NULL);
		if (rc) {
			fprintf(stdout, "CT09003 INFO: uti not available (rc=%d)\n", rc);
		} else {
			fprintf(stdout, "CT09003 INFO: uti available\n");
		}
	} else {
		fprintf(stdout, "CT09003 INFO: uti disabled\n", rc);
	}

	per_proc->thr_arg.rank = per_proc->rank;
	rc = pthread_create(&per_proc->thr_arg.pthread, NULL, progress_fn, &per_proc->thr_arg);
	if (rc){
		fprintf(stdout, "pthread_create: %d\n", rc);
		exit(1);
	}
	
	pthread_mutex_lock(&per_proc->thr_arg.bar_lock);
	per_proc->thr_arg.bar_count++;
	if (per_proc->thr_arg.bar_count == 2) {
		if ((rc = pthread_cond_broadcast(&per_proc->thr_arg.bar_cond))) {
			printf("[%d] pthread_cond_broadcast failed,rc=%d\n", per_proc->rank, rc);
		}
	}
	while (per_proc->thr_arg.bar_count != 2) {
		if ((rc = pthread_cond_wait(&per_proc->thr_arg.bar_cond, &per_proc->thr_arg.bar_lock))) {
			printf("[%d] pthread_cond_wait failed,rc=%d\n", per_proc->rank, rc);
		}
    }
	pthread_mutex_unlock(&per_proc->thr_arg.bar_lock);

	printf("[%d] parent,after barrier\n", per_proc->rank);
	//fprintf(stdout, "CT09004 pthread_create OK\n");

	//#define TIMER_KIND CLOCK_THREAD_CPUTIME_ID
#define TIMER_KIND CLOCK_REALTIME
	clock_gettime(TIMER_KIND, &start);
	for (i = 0; i < 10000; i++) { /* It takes 1 sec */

		/* Send request-to-send packet */
		clock_gettime(CLOCK_REALTIME, &now_ts);
		now_long = TS2NS(now_ts.tv_sec, now_ts.tv_nsec);
	
		for (j = 0; j < NOPS; j++) {
			pthread_mutex_lock(&per_proc->thr_arg.ep_lock); /* Lock is taken per MPI_Accumulate() */
			fwq(I2R_OCC);
			now_long += I2R_OCC;
			per_proc->thr_arg.res_ev[j] = now_long + I2R_NET;
			per_proc->thr_arg.ini_busy = now_long;
			//printf("res_ev=%ld,ini_busy=%ld,now=%ld\n", per_proc->thr_arg.res_ev[j] % 1000000000UL, per_proc->thr_arg.ini_busy % 1000000000UL, now_long  % 1000000000UL);
			pthread_mutex_unlock(&per_proc->thr_arg.ep_lock);
		}

		/* Start calculation */
		fwq(CALC_CPU);

		/* Progress responder and initiator */
		int more_reap_needed;
		while (1) {
			if (progress_responder(&per_proc->thr_arg)) {
				//printf("parent_fn, responder progressed\n");
			}

			if (progress_initiator(&per_proc->thr_arg)) {
				//printf("parent_fn, initiator progressed\n");
			}

			more_reap_needed = 0;
			for (j = 0; j < NOPS; j++) {
				if (per_proc->thr_arg.res_ev[j] || per_proc->thr_arg.ini_ev[j]) {
					more_reap_needed = 1;
					break;
				}
			}
			if (!more_reap_needed) {
				break;
			}
		}
	}
	clock_gettime(TIMER_KIND, &end);
	
	per_proc->thr_arg.terminate = 1;
	pthread_join(per_proc->thr_arg.pthread, NULL);

	per_proc->nsec = TS2NS(end.tv_sec, end.tv_nsec) - TS2NS(start.tv_sec, start.tv_nsec);
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

int main(int argc, char **argv) {
	int rc;
	int i;
	char *uti_str;
	int uti_val;
	int st;
	pid_t pid;
	long max;
	pthread_condattr_t condattr;
	pthread_mutexattr_t mutexattr;
	int fd;
	key_t key = ftok(argv[0], 0);
	int shmid;
	int opt;

	while ((opt = getopt_long(argc, argv, "+ar", options, NULL)) != -1) {
		switch (opt) {
		case 'a': /* accumulate */
			NOPS = 10; /* ten accumulates */
			R2I_OCC = 400; /* 200 ns to accumulate, 200 ns to send ACK */
			break;
		case 'r':
			NOPS = 6; /* 3D stencil, RDMA */
			R2I_OCC = 10200; /* 10000 ns to RDMA-RD, 200 ns to send DONE */
				break;
		default: /* '?' */
			printf("usage: [-a] [-r]");
			exit(1);
		}
	}

	fprintf(stdout, "CT09001 MPI progress thread skelton START\n");

	rc = syscall(732);
	if (rc == -1)
		fprintf(stdout, "CT09002 main running on Linux INFO\n");
	else {
		fprintf(stdout, "CT09002 main running on McKernel INFO\n");
	}

	fwq_init();

#define SHMPOSIX 1
#define SHMSYSV 2
#define SHMANON 3
#define SHM_METHOD SHMPOSIX
#if SHM_METHOD==SHMPOSIX
	printf("posix1\n");
	if((fd = shm_open("/CT27", O_RDWR | O_CREAT, 0644)) == -1) {
		fprintf(stdout, "shm_open failed\n");
	}
	if(ftruncate(fd, sizeof(struct proc_glb))) {
		fprintf(stdout, "ftruncate failed\n");
	}
	proc_glb = mmap(0, sizeof(struct proc_glb), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (proc_glb == (void*)-1) {
		fprintf(stdout, "mmap failed\n");
		exit(1);
	}
#elif SHM_METHOD==SHMSYSV
	printf("sysv1\n");
    if ((shmid = shmget(key, sizeof(struct proc_glb), IPC_CREAT | 0660)) == -1) {
		fprintf(stdout, "shmget failed: %s\n", strerror(errno));
	}
	proc_glb = shmat(shmid, NULL, 0);
	if (proc_glb == (void*)-1) {
		fprintf(stdout, "shmat failed\n");
		exit(1);
	}
#elif SHM_METHOD==SHMANON
	printf("anon1\n");
	proc_glb = mmap(0, sizeof(struct proc_glb), PROT_READ | PROT_WRITE, MAP_SHARED/* | MAP_ANONYMOUS*/, /*-1*/fd, 0);
	if (proc_glb == (void*)-1) {
		fprintf(stdout, "mmap failed\n");
		exit(1);
	}
#endif

	memset(proc_glb, 0, sizeof(struct proc_glb));

	proc_glb->bar_count = 0;

	pthread_condattr_init(&condattr);
	pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED);
	pthread_cond_init(&proc_glb->bar_cond, &condattr);

	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&proc_glb->bar_lock, &mutexattr);

	for (i = 0; i < NPROC; i++) {
		proc_glb->per_procs[i].rank = i;
		printf("[0] i=%d,rank=%d\n", i, proc_glb->per_procs[i].rank);
	}
	for (i = 1; i < NPROC; i++) {
		pid = fork();
		if(pid < 0) {
			fprintf(stdout, "fork failed: %s\n", strerror(errno));
			exit(1);
		} else if (pid == 0) {
#if SHM_METHOD==SHMSYSV
	printf("sysv2\n");
			proc_glb = shmat(shmid, NULL, 0);
#endif
			printf("[%d] rank=%d\n", i, proc_glb->per_procs[i].rank);
			parent_fn(&proc_glb->per_procs[i]);
			exit(0);
		}
	}
	parent_fn(&proc_glb->per_procs[0]);
	
	while ((pid = waitpid(-1, &st, __WALL)) > 0);

	max = -1;
	for (i = 0; i < NPROC; i++) {
		if (max < proc_glb->per_procs[i].nsec) {
			max = proc_glb->per_procs[i].nsec;
		}
	}

	fprintf(stderr, "max %ld nsec\n", max);
	fprintf(stdout, "CT09006 END\n");
}


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

#define NPROC 8
#define NINC 10000
#define TS2NS(sec, nsec) ((unsigned long)(sec) * 1000000000ULL + (unsigned long)(nsec))
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
	volatile long count; /* events on the responder */
	volatile int terminate;
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

static int print_cpu_last_executed_on() {
	char fn[256];
	char* result;
	pid_t tid = syscall(SYS_gettid);
	int fd;
	int offset;
    int mpi_errno = 0;

	sprintf(fn, "/proc/%d/task/%d/stat", getpid(), (int)tid);
	//printf("fn=%s\n", fn);
	fd = open(fn, O_RDONLY);
	if(fd == -1) {
		printf("open() failed\n");
		goto fn_fail;
	}

	result = malloc(65536);
	if(result == NULL) {
		printf("malloc() failed");
		goto fn_fail;
	}

	int amount = 0;
	offset = 0;
	while(1) {
		amount = read(fd, result + offset, 65536);
		//		printf("amount=%d\n", amount);
		if(amount == -1) {
			printf("read() failed");
			goto fn_fail;
		}
		if(amount == 0) {
			goto eof;
		}
		offset += amount;
	}
 eof:;
    //printf("result:%s\n", result);

	char* next_delim = result;
	char* field;
	int i;
	for(i = 0; i < 39; i++) {
		field = strsep(&next_delim, " ");
	}

	int cpu = sched_getcpu();
	if(cpu == -1) {
		printf("getpu() failed\n");
		goto fn_fail;
	}

	printf("stat-cpu=%02d,sched_getcpu=%02d,tid=%d\n", atoi(field), cpu, tid); fflush(stdout);
 fn_exit:
    free(result);
    return mpi_errno;
 fn_fail:
	mpi_errno = -1;
    goto fn_exit;
}

void init_bar(struct thr_arg* thr_arg) {
	pthread_mutex_lock(&thr_arg->bar_lock);
	thr_arg->bar_count= 0;
	pthread_mutex_unlock(&thr_arg->bar_lock);
}

void bar(struct thr_arg* thr_arg) {
	int rc;
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

	printf("[%d] progress,enter,", thr_arg->rank);
	print_cpu_last_executed_on();

	bar(thr_arg);

	printf("[%d] progress,after barrier\n", thr_arg->rank);

	for (i = 0; i < NINC; i++) {
		pthread_mutex_lock(&thr_arg->ep_lock);
		thr_arg->count++;
		pthread_mutex_unlock(&thr_arg->ep_lock);
		sched_yield();
	}

	bar(thr_arg);
	printf("progress,exit,rank=%d\n", thr_arg->rank);

	return NULL;
}

#define TIMER_KIND CLOCK_THREAD_CPUTIME_ID
//#define TIMER_KIND CLOCK_REALTIME

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

	printf("[%d] parent_fn,enter,", per_proc->rank);
	print_cpu_last_executed_on();

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


	pthread_mutexattr_init(&mutexattr);
	pthread_mutex_init(&per_proc->thr_arg.ep_lock, &mutexattr);

	per_proc->thr_arg.bar_count = 0;

	pthread_condattr_init(&condattr);
	pthread_cond_init(&per_proc->thr_arg.bar_cond, &condattr);

	pthread_mutexattr_init(&mutexattr);
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
	
	init_bar(&per_proc->thr_arg);
	bar(&per_proc->thr_arg);

	printf("[%d] parent,after barrier\n", per_proc->rank);

	clock_gettime(TIMER_KIND, &start);
	for (i = 0; i < NINC; i++) {
		pthread_mutex_lock(&per_proc->thr_arg.ep_lock); /* Lock is taken per MPI_Accumulate() */
		per_proc->thr_arg.count++;
		pthread_mutex_unlock(&per_proc->thr_arg.ep_lock);
	}
	init_bar(&per_proc->thr_arg);
	bar(&per_proc->thr_arg);
	clock_gettime(TIMER_KIND, &end);
	
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

	while ((opt = getopt_long(argc, argv, "+", options, NULL)) != -1) {
		switch (opt) {
		default: /* '?' */
			printf("unknown option: %c\n", optopt);
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


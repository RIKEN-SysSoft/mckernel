#define _GNU_SOURCE 1
#include <stdio.h>
#include <sched.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef OPENMP
#include <omp.h>
#include <sys/syscall.h>
#endif
#ifdef MPI
#include <mpi.h>
#endif

#define BUFFER_SIZE 4096

#define check_env(env) \
({ \
	if (!getenv(env)) { \
		fprintf(stderr, "error: environment variable %s doesn't exist?!\n", env); \
		exit(1); \
	} \
})

int
main(int argc, char *argv[])
{
	int rank = 0;
	int size = 0;
	int ncore = 128;
	char hname[BUFFER_SIZE];
	int wait = 0;

	if (argc > 1 && !strcmp("--wait", argv[1])) {
		wait = 1;
	}

#ifdef FJ_CHECK_ENV
	{
		check_env("PMIX_RANK");
		check_env("OMPI_PLE_RANK_ON_NODE");
		check_env("PLE_RANK_ON_NODE");
		check_env("OMPI_MCA_orte_ess_vpid");
		check_env("FLIB_RANK_ON_NODE");
	}
#endif

	gethostname(hname, BUFFER_SIZE);
#ifdef MPI
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
#endif

#ifdef OPENMP
	#pragma omp parallel
#endif
	{
		int i;
		int tid;
		pid_t pid;
		cpu_set_t cpuset;
		char affinity[BUFFER_SIZE];
#ifdef OPENMP
		tid = omp_get_thread_num();
		pid = (pid_t)syscall(SYS_gettid);
#else
		tid = 0;
		pid = getpid();
#endif
		CPU_ZERO(&cpuset);
		if ((sched_getaffinity(pid, sizeof(cpu_set_t), &cpuset)) == 1) {
			perror("Error sched_getaffinity");
			exit(1);
		}

		affinity[0] = '\0';
		for (i = 0; i < ncore; i++) {
			if (CPU_ISSET(i, &cpuset) == 1) {
				sprintf(affinity, "%s %d", affinity, i);
			}
		}
		printf("hostname = %s, rank = %03d, PID: %4d, OMP tid = %d, TID = %d, CPU = %d, affinity =%s\n",
			hname, rank, getpgid(0), tid, pid, sched_getcpu(), affinity);
		if (rank == 0 && tid == 0 && wait == 1) {
			printf("Now press ENTER.\n");
			getchar();
		}
	}

#ifdef MPI
	MPI_Barrier(MPI_COMM_WORLD);
	MPI_Finalize();
#endif

	return 0;
}

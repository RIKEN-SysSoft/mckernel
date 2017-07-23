#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mpi.h>

#include <qlmpilib.h>

int
main(int argc, char **argv)
{
	int rc;
	int num_procs, my_rank;
	char hname[128];

	gethostname(hname, 128);

	MPI_Init(&argc, &argv);
	MPI_Comm_size(MPI_COMM_WORLD, &num_procs);
	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);

ql_loop:
	printf("INFO This is B. host=%s, rank:%d, pid:%d\n", hname, my_rank, getpid());

	printf("%d:done=yes\n", my_rank);
	fflush(stdout);

	rc = ql_client(&argc, &argv);

	//printf("ql_client returns: %d\n", rc);
	if (rc == QL_CONTINUE) {
		printf("%d:resume=go_back\n", my_rank);
		goto ql_loop;
	}
	else {
		printf("%d:resume=go_finalize\n", my_rank);
	}

	MPI_Finalize();
	printf("%d:finish=yes\n", my_rank);
	return 0;
}

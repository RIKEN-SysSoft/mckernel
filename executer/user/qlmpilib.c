#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>
#include "mpi.h"
#include "../include/qlmpilib.h"
#include "../include/qlmpi.h"
#include "../include/pmi.h"


#define BUF_SIZE        (32*1024)
#define NALLOC 10
#define QL_SUCCESS 0
#define QL_NORMAL 2 

//#define QL_DEBUG

static char ql_name[33];
static char swap_file[1024];
static char param_file[1024];
static int ql_mode_flg = 0; /* 0 is normal */
static int rank = -1;
static char buffer[BUF_SIZE];
static int ql_initialized;
int mck_ql_argc = NALLOC;
char **mck_ql_argv;
char **mck_ql_env;

static void freev(char **v)
{
	char **a;

	for (a = v; *a; a++)
		free(*a);
	free(v);
}

static void esc_get(char *in, char *out)
{
	char *p;
	char *q;
	int c;

	for (p = in, q = out; *p; p++) {
		if (*p == '%' && p[1] && p[2]) {
			int i;
			for (i = 0, c = 0; i < 2; i++) {
				p++;
				c <<= 4;
				if (*p >= '0' && *p <= '9')
					c += *p - '0';
				else if (*p >= 'A' && *p <= 'F')
					c += *p - 'A' + 10;
				else if (*p >= 'a' && *p <= 'f')
					c += *p - 'a' + 10;
			}
			*(q++) = c;
		}
		else
			*(q++) = *p;
	}
	*q = '\0';
}

static int swapout(char *fname, void *buf, size_t sz, int flag)
{
	int         cc;

	cc = syscall(801, fname, buf, sz, flag);

	return cc;
}

static int ql_get_option() {
	char *env_str;

	env_str = getenv(QL_NAME);
	if (env_str == NULL) {
		return 0;
	}
	else{
		strcpy(ql_name,env_str);
		return 1;
	}
	
}

static int ql_init() {
	char tmp_path[1024];
	char *env_str;

	if (ql_initialized) {
		return QL_CONTINUE;
	}

	ql_mode_flg = ql_get_option();
#ifdef QL_DEBUG
	printf("flg = %d \n",ql_mode_flg);
#endif

	if (ql_mode_flg) {
		MPI_Comm_rank(MPI_COMM_WORLD, &rank);
		/* get param_file path */
		env_str = getenv(QL_PARAM_ENV);
		if (env_str == NULL) {
			sprintf(tmp_path,"%s/",getenv("HOME"));
		}
		else{
			sprintf(tmp_path,"%s/",env_str);
		}
		sprintf(param_file,"%s%s%s",tmp_path,ql_name,QL_PARAM_EXTE);

#ifdef QL_DEBUG
		printf("param_file = %s\n",param_file);
#endif

		/* get swap_file path*/
		env_str = getenv(QL_SWAP_ENV);
		if (env_str == NULL) {
			strcpy(tmp_path,QL_SWAP_PATH);
		}
		else{
			strcpy(tmp_path,env_str);
		}
		sprintf(swap_file,"%s/%s%d",tmp_path,ql_name,rank);

#ifdef QL_DEBUG
		printf("swap_file = %s rank=%d\n",swap_file,rank);
#endif
		ql_initialized = 1;
		return QL_SUCCESS;		
	}

	ql_initialized = 1;
	return QL_NORMAL;
}

int ql_client(int *argc,char ***argv)
{
	int rc;
	int ret = QL_EXIT;
	char buf[4096];
	FILE *fp;
	char **envs;
	char **args;
	char **a;
	char **e;

	if (ql_mode_flg == 0) return(QL_EXIT);

	syscall(803);
	rc = PMI_Barrier();
	
	rc = swapout(swap_file, buffer, BUF_SIZE, 0);

#ifdef QL_DEBUG
	printf(" swapout rc=%d\n",rc);
#endif
	if (rc == -1) {
		/* terminate due to swap error */
		syscall(804);
		return QL_EXIT;
	}

	/* param file */
	if ((fp = fopen(param_file,"r")) == NULL) {
		/* param file open error */
#ifdef QL_DEBUG
		printf("param_file open error\n");
#endif
		syscall(804);
		return QL_EXIT;
	}

	a = args = NULL;
	e = envs = NULL;
	while ((fgets(buf, 4096, fp)) != NULL) {
		int cmd = buf[0];
		char *t;
		int n;

		// remove return code
		buf[strlen(buf) - 1] = '\0';
		if (cmd == QL_COMMAND) {
			t = strchr(buf, '=');
			if (!t ||
			    (t[1] != QL_RET_RESUME && t[1] != QL_RET_FINAL)) {
				fprintf(stderr, "invalid file format\n");
				exit(1);
			}
			t++;
			if (*t == QL_RET_RESUME) {
				ret = QL_CONTINUE;
#ifdef QL_DEBUG
				printf("COM = %c ret = %d\n", *t, ret);
#endif
			}
			else {
				ret = QL_EXIT;
#ifdef QL_DEBUG
				printf(" ret = %d",ret);
#endif
			}
			t = strchr(t, ' ');
			if (t) {
				n = atoi(t + 1);
				args = malloc(sizeof(char *) * (n + 1));
				a = args;
				t = strchr(t + 1, ' ');
				if (t) {
					n = atoi(t + 1);
					envs = malloc(sizeof(char *) * (n + 1));
					e = envs;
				}
			}

		}
		else if (cmd == QL_ARG) {
			if (!args)
				continue;
			t = strchr(buf, ' ');
			if (!t)
				continue;
			n = atoi(t + 1);
			t = strchr(t + 1, ' ');
			if (!t)
				continue;
			t++;
			*a = malloc(n + 1);
			esc_get(t, *a);
			a++;
		}
		else if (cmd == QL_ENV) {
			if (!envs)
				continue;
			t = strchr(buf, ' ');
			if (!t)
				continue;
			n = atoi(t + 1);
			t = strchr(t + 1, ' ');
			if (!t)
				continue;
			t++;
			*e = malloc(n + 1);
			esc_get(t, *e);
			e++;
		}
		else {
		}
	}
	fclose(fp);

	if (args) {
		*a = NULL;
		if (mck_ql_argv)
			freev(mck_ql_argv);
		mck_ql_argv = args;
		if (argv)
			*argv = args;
		for (mck_ql_argc = 0; mck_ql_argv[mck_ql_argc]; mck_ql_argc++);
		if (argc)
			*argc = mck_ql_argc;
	}
	if (envs) {
		*e = NULL;
		if (mck_ql_env)
			freev(mck_ql_env);
		mck_ql_env = envs;
		environ = envs;
	}

	syscall(804);
#ifdef QL_DEBUG
	printf(" return rtn = %d\n",ret);
#endif
	return ret;
	
}

int MPI_Init(int *argc,char ***argv){
	int rc = 0;
	
	rc = PMPI_Init(argc,argv);
	if (rc == MPI_SUCCESS)
		ql_init();
	
	return rc;
}

void
mpi_init_(int *ierr)
{
	extern void pmpi_init_(int *ierr) __attribute__ ((__weak__));

	if (!pmpi_init_) {
		*ierr = MPI_ERR_OTHER;
		return;
	}

	pmpi_init_(ierr);
	if (*ierr == MPI_SUCCESS)
		ql_init();

	return;
}

void ql_client_(int *ierr)
{
	int argc;
	char **argv;

	*ierr = ql_client(&argc, &argv);
}

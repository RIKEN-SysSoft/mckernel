/*----------------------------------------------------------------------*
*     file: pi_pth.c: pthread sample program                            *
*     2013/02/22 Written by Yuji Saeki <yuji.saeki.fz@hitachi.com>      *
*-----------------------------------------------------------------------*/
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#define NUM_THREADS 1

static long numdiv = 200000000; 

typedef struct {
  long istart;
  long iend;
  double psum;
} pi_arg_t;

void *pi_calc(void *arg)
{
  pi_arg_t *piarg = (pi_arg_t *)arg;
  long i; 
  double x, dx, sum=0.0;

  dx = 1.0 / (double)numdiv;
  for (i = piarg->istart; i < piarg->iend; i++) {
    x = ((double)i + 0.5) * dx;
    sum = sum + 4.0 / (1.0 + x*x);
  }
  piarg->psum = sum * dx;
  return NULL;
}

int main()
{
  pthread_t thr[NUM_THREADS];
  int iret[NUM_THREADS];
  pi_arg_t piargs[NUM_THREADS];
  int ith;
  double pi = 0.0;

  for (ith = 0; ith < NUM_THREADS; ith++) {
    piargs[ith].istart = ith * numdiv / NUM_THREADS;
    piargs[ith].iend = (ith + 1) * numdiv / NUM_THREADS;
    piargs[ith].psum = 0.0;
    iret[ith] = pthread_create(&thr[ith], NULL, pi_calc, &piargs[ith]);
  }
  for (ith = 0; ith < NUM_THREADS; ith++) {
    if (iret[ith] != 0) {
      printf("failed to create thread[%d]: %d\n", ith, iret[ith]);
      _exit(1);
    }
  }
  for (ith = 0; ith < NUM_THREADS; ith++) {
    pthread_join(thr[ith], NULL);
    pi += piargs[ith].psum;
  }
  printf("PI = %16.14f\n", pi);
  return 0;
}


/*----------------------------------------------------------------------*
*     file: pi_omp.c: OpenMP sample program                             *
*     2013/02/22 Written by Yuji Saeki <yuji.saeki.fz@hitachi.com>      *
*-----------------------------------------------------------------------*/
#include <stdio.h>
#include <omp.h>
int main()
{
  long i, numdiv = 200000000; 
  double x, dx, pi, sum=0.0;

  dx = 1.0 / (double)numdiv;
#pragma omp parallel for reduction(+:sum) private(x)
  for (i = 0; i < numdiv; i++) {
    x = ((double)i + 0.5) * dx;
    sum = sum + 4.0 / (1.0 + x*x);
  }
  pi = sum * dx;
  printf("PI = %16.14f\n", pi);
  return 0;
}

!-----------------------------------------------------------------------*
!     file: pi_omp.f90: OpenMP sample program                           *
!     2013/02/22 Written by Yuji Saeki <yuji.saeki.fz@hitachi.com>      *
!-----------------------------------------------------------------------*
program calculate_pi
integer :: i, numdiv
double precision :: x, dx, gsum, pi
numdiv = 200000000
dx = 1.0d0 / numdiv
gsum = 0.0d0
!$OMP PARALLEL DO PRIVATE(x) REDUCTION(+:gsum)
do i = 1, numdiv
  x = (i - 0.5d0 ) * dx
  gsum = gsum + 4.0d0 / (1.0d0 + x * x)
end do
!$OMP END PARALLEL DO
pi = gsum * dx
print *, 'PI = ', pi
end program calculate_pi

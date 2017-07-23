c---+c---1----+----2----+----3----+----4----+----5----+----6----+----7--!!!!!!!!
!$ use omp_lib
      include 'mpif.h'
      integer rank
      integer size
      external omp_get_thread_num
      external omp_get_num_threads
      integer omp_get_thread_num
      integer omp_get_num_threads

      call MPI_INIT(ierr)
 1000 continue
      call MPI_COMM_RANK(MPI_COMM_WORLD, rank, ierr)
      call MPI_COMM_SIZE(MPI_COMM_WORLD, size, ierr)

!$omp parallel
      print '(1h ,4hmpi=,i2,1h/,i2,6h, omp=,i2,1h/,i2)',
     c      rank, size, omp_get_thread_num(), omp_get_num_threads()
!$omp end parallel
c     repeat?
      call ql_client(ierr)
      if(ierr.eq.1)then
        print *,'repeat'
        goto 1000
      endif
      call MPI_FINALIZE(ierr)
      end

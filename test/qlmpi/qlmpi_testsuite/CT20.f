c---+c---1----+----2----+----3----+----4----+----5----+----6----+----7--!!!!!!!!
      include 'mpif.h'
      integer dsize
      parameter(dsize=536870912)
      character val*10
      integer ival
      integer ierr
      integer i
      integer*4 dat(dsize)
      common dat
      integer rank
      integer size
      integer st(MPI_STATUS_SIZE)

      call MPI_INIT(ierr)
 1000 continue
      call MPI_COMM_RANK(MPI_COMM_WORLD, rank, ierr)
      call MPI_COMM_SIZE(MPI_COMM_WORLD, size, ierr)

c     size check
      if(size.ne.2)then
        if(rank.eq.0)then
          print*,'bad MPI size'
        endif
        call MPI_FINALIZE(ierr)
        stop 1
      endif

c     read argument
      iargs = iargc()
      if(iargs.ne.1)then
        print *,'bad argument'
        call MPI_FINALIZE(ierr)
        stop 1
      endif
      call getarg(1, val)
      read(val, '(i10)')ival
      print *,'val=',ival

c     test
      if(rank.eq.0)then
        do 10 i=1, dsize
          dat(i) = -1
   10   continue
      print *,'r1 val=',ival
        call MPI_RECV(dat, dsize, MPI_INTEGER4, 1, 0, MPI_COMM_WORLD,
     c                st, ierr)
      print *,'r2 val=',ival
        do 20 i=1, dsize
          if(dat(i).ne.ival)then
            print *,'*** bad value idx=',i,', dat=',dat(i),
     c              ' , val=',ival
            goto 100
          endif
   20   continue
        print *,'*** MPI_Send/Recv OK *** '
  100   continue
      else
        do 30 i=1, dsize
          dat(i) = ival
   30   continue
        call MPI_SEND(dat, dsize, MPI_INTEGER4, 0, 0, MPI_COMM_WORLD,
     c                ierr)
      endif

c     repeat?
      call ql_client(ierr)
      if(ierr.eq.1)then
        print *,'repeat'
        goto 1000
      endif
      call MPI_FINALIZE(ierr)
      end

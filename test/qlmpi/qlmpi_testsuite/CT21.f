c---+c---1----+----2----+----3----+----4----+----5----+----6----+----7--!!!!!!!!
      include 'mpif.h'
      integer size
      parameter(size=536870912)
      character file*10
      character val*10
      integer ival
      integer ierr
      integer i
      integer*4 dat(size)
      common dat
      character myname*10

      call getarg(0, myname)
      call MPI_INIT(ierr)
 1000 continue
      iargs = iargc()
      if(iargs.ne.2)then
        print *,'bad argument'
        call MPI_FINALIZE(ierr)
        stop 1
      endif
      call getarg(1, file)
      call getarg(2, val)
      read(val, '(i10)')ival
      print *,' file=',file,', val=',ival
      open(1, file=file, status='old', form='unformatted',
     c     access='stream', err=999)
      do 10 i=1, size
        dat(i) = -1
   10 continue
      read(1, err=998)(dat(i), i=1, size)
      do 20 i=1, size
        if(dat(i).ne.ival)then
          print *,'*** FAIL *** BAD VALUE idx=',i,', val=',dat(i)
          goto 100
        endif
   20 continue
      print *,' *** data read OK ***'
  100 continue
      close(1)
      call ql_client(ierr)
      if(ierr.eq.1)then
        print *,'resume'
        goto 1000
      endif
      call MPI_FINALIZE(ierr)
      stop 0

  998 continue
      close(1)
      print *,'read error'
      goto 9999

  999 continue
      print *,'open error'
      goto 9999

 9999 continue
      call MPI_FINALIZE(ierr)
      stop 1
      end

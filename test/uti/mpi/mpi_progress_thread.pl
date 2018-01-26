#!/usr/bin/perl

# Usage ./mpi_progress.pl <#procs> <#nnodes> (mck|lin) (mpich|intel)

use File::Basename;
use File::Copy "cp";

($nprocs, $nnodes, $os, $mpi) = @ARGV;
$ppn = $nprocs / $nnodes;

@command = split /\s+/, basename($0);
@fn = split /\./, $command[0];

if($nnodes <= 16) {
    $rg = 'MCK-FLAT-QUADRANT';
} elsif($ARGV[1] <= 128) {
    $rg = 'debug-flat';
} else {
    $rg = 'regular-flat';
}

%elapse = (
'1', '00:10:00',
'2', '00:10:00',
'4', '00:10:00',
'8', '00:10:00',
'16', '00:10:00',
'32', '00:10:00',
'64', '00:05:00',
'128', '00:05:00',
'256', '00:10:00',
'512', '00:15:00',
'1024', '00:15:00',
'2048', '00:30:00',
    );

if ($os eq 'lin') {
    $use_mck =  '';
    $mck_mem = '';
    $mcexec = '';
    $mcexecopt = '';
} else {
    $path_to_mck = '/work/gg10/e29005/project/os/install';
    $use_mck = '#PJM -x MCK='.$path_to_mck;
    $mck_mem = '#PJM -x MCK_MEM=32G@0,8G@1';
    $mcexec = $path_to_mck.'/bin/mcexec';
    $mcexecopt = '-n '.$ppn;
}

if ($mpi eq 'intel') {
    $cc = 'mpiicc';
    $mpiexec = 'mpiexec';
    $genv = '';
    $progress = '-genv I_MPI_ASYNC_PROGRESS 1'; # -genv I_MPI_ASYNC_PROGRESS_PIN 1
} else {
    $mpi_lib = '/work/gg10/e29005/project/mpich/install';
    $cc = $mpi_lib.'/bin/mpicc';
    $mpiexec = $mpi_lib.'/bin/mpiexec';
    $genv = '-genv LD_LIBRARY_PATH '.$mpi_lib.'/lib:$LD_LIBRARY_PATH';
    $progress = '-genv MPIR_CVAR_ASYNC_PROGRESS 1';
}

system("make clean; make CC=$cc");

$dir=$ARGV[2].'_'.$ARGV[0].'_'.$ARGV[1].'_'.`date +%Y%m%d_%H%M%S`;
chomp($dir);
print 'less '.$dir.'/job.sh.o*'."\n";

mkdir $dir;
chdir $dir;
cp('../001', './001') or die 'copy failed';
open(IN, "../$fn[0].sh.in");
open(OUT, ">./job.sh");
while(<IN>) {
    s/\@rg@/$rg/g;
    s/\@nnodes@/$nnodes/g;
    s/\@nprocs@/$nprocs/g;
    s/\@elapse@/$elapse{$nnodes}/g;
    s/\@use_mck@/$use_mck/g;
    s/\@mck_mem@/$mck_mem/g;
    s/\@progress@/$progress/g;
    s/\@genv@/$genv/g;
    s/\@mpiexec@/$mpiexec/g;
    s/\@mcexec@/$mcexec/g;
    s/\@mcexecopt@/$mcexecopt/g;
    if(/\@env@/) {
	open(INCL, "../env_$mpi.sh");
	while(my $line = <INCL>) {
	    print OUT $line;
	}
	next;
    }
    print OUT $_;
}
close(IN);
close(OUT);

$cmd = 'PJM_MCK_AVAILABLE=1 pjsub ./job.sh';
#print $cmd."\n";
exec($cmd);

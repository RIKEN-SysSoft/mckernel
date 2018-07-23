#!/usr/bin/perl

use utf8;
use Encode qw/encode decode/;

sub count_occurence {
	my $err_num = 0;
	my $fn = shift();
	my @pattern = @_;
	my $lineno = 0;

	if (open(DATAFILE, "< $fn")) {
		while (my $line = <DATAFILE>) {
			my $check = 0;
			chomp $line;
			for (my $i = 0; $i <= $#pattern; $i++) {
				if ($line =~ /$pattern[$i]/) {
					$freq[$filecnt][$i]++;
					$check = 1;
					if ($loc[$i][$blockno] == 1) {
					    $blockno++;
					}
					$loc[$i][$blockno] = 1;
					last;
				}
			}
			$lineno++;
			if ($check == 0) {
				$no_match[$err_num] = $lineno;
				$err_num++;
			}
		}
	} else {
		return -1;
	}
	return $err_num;
}

if (@ARGV != 1) {
	print "Usage: file_format_check.pl filename\n";
	exit(1);
}

my @pattern1 = ();
my @pattern2 = ();
my $n = 1;
my $checkflg = 0;

open(DATAFILE, "< $ARGV[0]") or die("Error:$!");

while (my $line = <DATAFILE>) {
	chomp $line;
	if ($n == 1) {
		$checkfilepath = $line;
	} elsif ($n == 2) {
		$checkmode = $line;
	} elsif ($checkflg == 1) {
		push @pattern2, $line;
	} elsif ($line =~ /^$/) {
		$checkflg = 1;
	} else {
		push @pattern1, $line;
		push @pattern_check, 0;
	}
	$n++;
}

my $fname = "";
my $fnameflg = 0;
my $rtn_code = 0;
my $total_errcnt = 0;
my $my_tid = $$;
my $tmp_cmdls = "ls $checkfilepath";
my $cmdls = "ls $checkfilepath";
$cmdls =~ s/#pid#/$my_tid/g;

if ($tmp_cmdls eq $cmdls) {
  $fnameflg = 1;
}
if ($checkmode < 1 || $checkmode > 3) {
	$checkmode = 1;
}

my $cmdexec = `$cmdls`;
my @list = split(/\n/, $cmdexec);

$filecnt = 0;
foreach my $parts(@list) {
	$errcnt = 0;
	$freq = ();
	$loc = ();
	$no_match = ();
	$blockno = 0;

	# パターン検証サブルーチンコール
	my $rtn_code = &count_occurence($parts, @pattern1, @pattern2);

	if ($rtn_code == -1) {
		$err_msg = "$err_msg Err(ファイルが存在しませんでした)\n";
		$errcnt = 1;
	} else {
		for (my $i = 0; $i <= $#no_match; $i++) {
			$err_msg = "$err_msg Err(対象ファイルの$no_match[$i]行目がどのパターンにも合致しませんでした)\n";
			$errcnt++;
		}
		# pattern1
		if ($checkmode == 1) {
			for (my $i = 0; $i <= $#pattern1; $i++) {
				if ($freq[$filecnt][$i] == 0) {
					$err_msg = "$err_msg Err(チェックパターン($pattern1[$i])に一致する行が存在しませんでした)\n";
					$errcnt++;
				} elsif ($freq[$filecnt][$i] > 1) {
					$err_msg = "$err_msg Err(チェックパターン($pattern1[$i])に一致する行が複数回存在しました)\n";
					$errcnt++;
				}
			}
		# pattern2
		} elsif ($checkmode == 2) {
			for (my $i = 0; $i <= $#pattern1; $i++) {
				if ($freq[$filecnt][$i] == 0) {
					$err_msg = "$err_msg Err(チェックパターン($pattern1[$i])に一致する行が存在しませんでした)\n";
					$errcnt++;
				}
			}
		# pattern3
		} elsif ($checkmode == 3) {
			$count = $freq[$filecnt][0];
			for (my $i = 0; $i <= $#pattern1; $i++) {
				if ($freq[$filecnt][$i] == 0) {
					$err_msg = "$err_msg Err(全ブロックでチェックパターン($pattern1[$i])が存在しませんでした)\n";
					$errcnt++;
				} elsif ($freq[$filecnt][$i] != $count) {
					for (my $j = 0; $j <= $blockno; $j++) {
						if ($loc[$i][$j] != 1) {
							$bno = $j + 1;
							$err_msg = "$err_msg Err(${bno}ブロック目でチェックパターン($pattern1[$i])に一致する行が存在しませんでした)\n";
							$errcnt++;
						}
					}
				}
			}
		}
	}
	if ($fnameflg == 0) {
		$fname = $checkfilepath;
	} else {
		$fname = $parts;
	}
	if ($errcnt == 0) {
		print "[OK] $fname\n";
	} else {
		print "[NG] $fname\n";
		$err_msg = encode('UTF-8', $err_msg);
		print "$err_msg";
		system("cat $parts > NG_`basename $ARGV[0]`");
	}
	$total_errcnt = $total_errcnt + $errcnt;
	$filecnt++;
}
if ($total_errcnt == 0) {
	exit(0);
} else {
	exit($total_errcnt);
}

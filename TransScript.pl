#!C:\Strawberry\perl\bin\perl.exe
use v5.10; # state
use strict;
use warnings;

use Win32;
use Win32::Process; # cpanm Win32::Process::Info
use Win32::Process::Memory; # cpanm Win32::Process::Memory
use Win32::Process::List; # cpanm Win32::Process::List
use File::Monitor; # cpanm File::Monitor

my $mute = 0; $| = 1;
my $outputCode = Win32::GetConsoleOutputCP();
ConsoleLog("codepage = $outputCode\n\n");

my %pidList = ();

my $monitor = File::Monitor->new();
$monitor->watch('TransCatalog.txt', sub {
	while (my($pid, $info) = each(%pidList)) {
		&Update(1, $info);
	}
});

while (1) {
	&Loop();
	$monitor->scan;
	select(undef, undef, undef, 1.1);
}

sub Loop {
	my %liveCheck = %pidList;

	my $procList = Win32::Process::List->new();
	my %list = $procList->GetProcesses();

	while (my($pid,$exe) = each(%list)) {
		if ($exe eq 'bluecg.exe') {
			if (exists($pidList{ $pid })) {
				delete $liveCheck{ $pid };
			} else {
				ConsoleLog("new bluecg.exe($pid) Found !\n");
				select(undef, undef, undef, 2.0);
				my $proc = Win32::Process::Memory->new({ pid  => $pid, access=>'read/write/query/all' });
				$pidList{$pid}{'proc'} = $proc;

				my %blockTable = $proc->get_memlist;
				my $addrCheck = 0;
				$proc->search_sub('>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<', sub { $addrCheck = $_[0] });
				die if ($addrCheck == 0);

				my $memBytes = "";
				my $baseAddr = 0;
				while (my($blockBase, $blockLen) = each(%blockTable)) {
					my $blockEnd = $blockBase + $blockLen;

					next unless ($addrCheck > $blockBase && $addrCheck < $blockEnd);
					$baseAddr = $blockBase;

					my $buf;
					my $pos = $blockBase;
					while ($pos < $blockEnd) {
						my $getbytes = $proc->get_buf($pos, 0x10000, $buf);
						$memBytes .= $buf;
						$pos += 0x10000;
					}
				}

				$pidList{$pid}{'baseAddr'} = $baseAddr;

				my(%info);
				open(IN, "<", "TransCatalog.txt")
					or die;
				while (<IN>) {
					if (/^([0-9a-f]{6}) +(\d+) +\[([sdx]*)\]/) {
						my($hex, $len, $ph) = ($1, $2, $3);
						my $addr = hex($hex);
						scalar(<IN>);
						my $big5 = <IN>; chomp($big5); $big5 =~ s/\\n/\n/g;
						my $sjis = <IN>; chomp($sjis); $sjis =~ s/\\n/\n/g;
						scalar(<IN>);
						my $strBytes = substr($memBytes, $addr, $len + 1);
						my $checkZero = chop($strBytes);
						my $ph_mem = ""; $ph_mem .= $1 while ($strBytes =~ /\%[\+\-]?\d*([sdx])/g);

						die sprintf("[%s] [%d] %s [%02x]", $hex, $len, join(' ', map { sprintf("%02x", ord($_)) } split(//, $strBytes)), ord($checkZero))
							if (index($strBytes, "\0") >= 0 or $checkZero ne "\0");

						my $type = $strBytes eq $big5 ? 0 : $strBytes eq $sjis ? 2 : 4 ;

						die "$hex" if ($ph ne $ph_mem);
						$info{$hex} = [ $baseAddr + $addr, $len, $ph, $big5, $sjis, $strBytes, $type, "" ];
					}
				}
				close(IN);
				$pidList{$pid}{'info'} = \%info;

				$mute = 1;
				&Update(1, $pidList{$pid});
				$mute = 0;
				ConsoleLog("bluecg.exe($pid) Translated !\n\n");
			}
		}
	}
	while (my($pid, $info) = each(%liveCheck)) {
		ConsoleLog("bluecg.exe($pid) Lost.\n\n");
		my $p = $info->{'proc'};
		undef $p;
		delete $pidList{ $pid };
	}
}

sub Update {
	my $mode = shift;
	my $data = shift;
	my $proc = $data->{'proc'};
	my $baseAddr = $data->{'baseAddr'};

	open(IN, "<", "TransCatalog.txt")
		or die;

	while (1) {
		last if (eof(IN));

		my $line = <IN>; chomp($line);
		if ($line =~ /^([0-9a-f]{6}) +(\d+) +\[([sdx]*)\]/) {
			my $hex = $1;
			my $len = $2;
			my $ph = $3;
			my $addr = hex($hex);
			my $len1 = <IN>; chomp($len1); die unless ($len1 =~ /^\-+$/);
			my $big5 = <IN>; chomp($big5); $big5 =~ s/\\n/\n/g; my $big5_len = length($big5);
			my $sjis = <IN>; chomp($sjis); $sjis =~ s/\\n/\n/g; my $sjis_len = length($sjis);
			my $len2 = <IN>; chomp($len2); die unless ($len2 =~ /^\-+$/);

			unless (exists($data->{info}{$hex})) {
				ConsoleLog("[$hex] not found!\n\n");
				next;
			}

			my $info = $data->{info}{$hex};

			next if ($sjis eq $info->[5]);
			next if ($sjis eq $info->[7]);
			$info->[7] = $sjis;

			if ($sjis_len != $info->[1]) {
				ConsoleLog("[$hex] length not match!\n");
				if ($info->[5] ne $info->[3]) {
					$proc->set_buf($info->[0], $info->[3]);
					$info->[5] = $info->[3];
					$info->[6] = 1;
					ConsoleLog("[$hex] Set Default [$info->[3]]\n\n");
				} else {
					ConsoleLog("\n");
				}
				next;
			}

			my $ph_sjis = ""; $ph_sjis .= $1 while ($sjis =~ /\%[\+\-]?\d*([sdx])/g);
			if ($info->[2] ne $ph_sjis) {
				ConsoleLog(qq([$hex] sprintf("$info->[2]", ...) <> sprintf("$ph_sjis", ...)\n));

				if ($info->[5] ne $info->[3]) {
					$proc->set_buf($info->[0], $info->[3]);
					$info->[5] = $info->[3];
					$info->[6] = 1;
					ConsoleLog("[$hex] Set Default [$info->[3]]\n\n");
				} else {
					ConsoleLog("\n");
				}
				next;
			}

			if ($mode == 1) {
				my $buf;
				$proc->get_buf($info->[0], $len, $buf);
				if ($buf eq $sjis) {
					ConsoleLog("[$hex] Why? \n\n");
					next;
				}

				$proc->set_buf($info->[0], $sjis);
				$info->[5] = $sjis;
				$info->[6] = 3;

				my $dumpMem = $buf;  $dumpMem =~ s/\n/\\n/g;
				my $dumpJIS = $sjis; $dumpJIS =~ s/\n/\\n/g;
				ConsoleLog("[$hex] old [$dumpMem]\n[$hex] new [$dumpJIS]\n\n");
			}
		}
	}
	close(IN);
}

sub ConsoleLog {
	return if ($mute);

	if ($outputCode == 950) {
		print $_[0];
		return;
	}

	print &cp950ex_cp932($_[0]);
}

sub cp950ex_cp932 {
	$_ = shift;

	state $CP950EX_CP932_map;
	unless ($CP950EX_CP932_map) {
		open(DAT, "<", "CP950EX_CP932_map.dat")
			or die;
		$CP950EX_CP932_map = do { local $/; <DAT> };
		close(DAT);
	}

	my $ret = "";
	while (/(?:([\x80-\xff][\x40-\xff])|(.))/sg) {
		if (defined($2)) {
			$ret .= $2;
		} else {
			my($cc1, $cc2) = unpack('CC', $1);
			my $offset = ($cc1 - 0x80) * (0x100 - 0x40) + ($cc2 - 0x40);
			my $bytelen = ($cc1 == 0xc8 && ($cc2 >= 0xb9 && $cc2 <= 0xfe)) ? 1 : 2 ;
			$ret .= substr($CP950EX_CP932_map, $offset * 2, $bytelen);
		}
	}
	return $ret;
}

1;

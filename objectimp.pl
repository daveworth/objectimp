#!/usr/bin/perl -w

use Getopt::Std;
use vars qw($opt_h $opt_s $opt_i $opt_t $opt_M $opt_I $opt_S $opt_d $opt_R $opt_U $opt_e $opt_C);
use strict;

my ($objbin) = (&find_exec("objdump"));

my ($theobj, $architecture);
my (@sects, @obj, @objlist, %functrack);

if (!getopts('hsitM:IS:dRUeC:')) {
    print "Damn... getoptviolation in 0xfuck0ff!\n";
	exit;
} elsif (@ARGV) {
    $theobj = shift @ARGV;
    print "$theobj is not a binary!" && &usage if !-B $theobj;
}
else {
    &usage;
}

&usage if $opt_h;

@obj = `$objbin -D $theobj`;
map {s/^\s+// if !/^\s+$/} @obj;

if ($opt_C) {
	$opt_R = 0;
	if (stat($opt_C)) {
		open(FIZ, "$opt_C");
		$opt_C = "";
		while(<FIZ>){
			if (/^(.+?):/) {
				$opt_C .= "$1,"
			}
		}
		close(FIZ);
		$opt_C =~ s/,$//;
	}

	$opt_S = $opt_C;
}

if (!$opt_S) { push @sects, "main" }
else { @sects = split /(?:,| )/, $opt_S }

foreach my $sect (@sects) {
	&getfunc($sect);
}
$objlist[0]->{'name'} = $opt_M || "shellcode" if !$opt_d;

if ($opt_C) {
	&stitch_funcs;
}

if ($opt_I && (!$opt_d && !$opt_e)) {
	&shellinfo;
}

if ($opt_e) {
	print &rev_eng;
} elsif ($opt_d) {
	print &disasm;
} elsif ($opt_s) {
    print &hexmeupwoman;
} elsif ($opt_i) {
    print &getcharstar;
} elsif ($opt_t) {
    print &testes;
} else {
    &usage if !$opt_I;
}

exit;

sub stitch_funcs {
	my %nohash;
	$nohash{'name'} = $objlist[0]->{'name'};
    foreach my $func (@objlist) {
		$nohash{'spaces'} += $func->{'spaces'};
		$nohash{'nulls'}  += $func->{'nulls'};
		$nohash{'shell'}  += $func->{'shell'};
		$nohash{'nascii'} += $func->{'nascii'};
		foreach my $inst (@{$func->{'code'}}) {
			push @{$nohash{'code'}}, $inst
		}
	}
	@objlist = ();
	push @objlist, \%nohash;
}

sub rev_eng {
    my ($disasm);
    my ($inst, $maxinstlen, $maxasmlen,$codelen)  = ("",0,0,0);

    foreach my $func (@objlist) {
		$maxinstlen = 0;
		foreach $inst (@{$func->{'code'}}) {
			$maxinstlen = length($inst->[0])
				if (length($inst->[0]) > $maxinstlen);

		}
		$maxinstlen+=4;

		$maxasmlen = 0;
		foreach $inst (@{$func->{'code'}}) {
			$maxasmlen = length($inst->[1])
				if (length($inst->[1]) > $maxasmlen);

			if ($inst->[1] =~ /<(\w+)\+(0x[0-9a-fA-F]+)>/) {
				my $pos = int(hex($2));

				#XXX bogus n^2 operation (fix me!)
				foreach my $sfunc (@objlist) {
					if ($sfunc->{'name'} eq $1) {
						foreach my $sinst (@{$sfunc->{'code'}}) {
							if (!$pos) {
								$sinst->[2] .= " <$1+$2>";
								last;
							} else {
								$pos -= (length($sinst->[0])/4);
							}
						}
					}
				}
			}

		}
    }

    foreach my $func (@objlist) {
		$disasm .= "//" . "="x78 . "\n";
		$disasm .= "//  Function: $func->{'name'} \n";

		if ($opt_I) {
			$codelen = 0;
			foreach $inst (@{$func->{'code'}}) {
				$codelen += length($inst->[0])/4;
			}
			$disasm .= "//   Length: $codelen bytes\n";
			$disasm .= "//   Whitespace: $func->{'spaces'}\n";
			$disasm .= "//   Shell Chars: $func->{'shell'}\n";
			$disasm .= "//   Nulls: $func->{'nulls'}\n";
		}
		$disasm .= "//" . "="x78 . "\n\n";

		foreach $inst (@{$func->{'code'}}) {
			$disasm .= sprintf("%-".$maxasmlen."s // %s\n",
							   $inst->[1], $inst->[2]);
		}
		$disasm .= "\n//" . "-"x78 . "\n\n";
    }
    return ($disasm);
}

sub disasm {
    my ($disasm);
    my ($inst, $maxinstlen, $maxasmlen,$codelen)  = ("",0,0,0);

    foreach my $func (@objlist) {
		$maxinstlen = 0;
		foreach $inst (@{$func->{'code'}}) {
			$maxinstlen = length($inst->[0])
				if (length($inst->[0]) > $maxinstlen);
		}
		$maxinstlen+=4;

		$maxasmlen = 0;
		foreach $inst (@{$func->{'code'}}) {
			$maxasmlen = length($inst->[1])
				if (length($inst->[1]) > $maxasmlen);
		}
    }

    foreach my $func (@objlist) {
		$disasm .= "="x80 . "\n";
		$disasm .= "* Function: $func->{'name'} *\n";

		if ($opt_I) {
			$codelen = 0;
			foreach $inst (@{$func->{'code'}}) {
				$codelen += length($inst->[0])/4;
			}
			$disasm .= "   Length: $codelen bytes\n";
			$disasm .= "   Whitespace: $func->{'spaces'}\n";
			$disasm .= "   Shell Chars: $func->{'shell'}\n";
			$disasm .= "   Nulls: $func->{'nulls'}\n";
			$disasm .= "   Non-ASCII: $func->{'nascii'}\n";
			$disasm .= "   Numeric: $func->{'numeric'}\n";
			$disasm .= "   Upper-Case: $func->{'ucase'}\n";
			$disasm .= "   Lower-Case: $func->{'lcase'}\n";
		}
		$disasm .= "="x80 . "\n\n";

		foreach $inst (@{$func->{'code'}}) {
			$disasm .= sprintf("%-".$maxinstlen."s  %-".$maxasmlen."s\n",
							   $inst->[0],
							   $inst->[1] . $inst->[2]);
		}
		$disasm .= "\n" . "-"x80 . "\n\n";
    }
    return ($disasm);
}

sub hexmeupwoman {
    my ($str);
    foreach my $func (@objlist) {

		$str .= " * $func->{'name'} *\n" . "="x80 . "\n";
		foreach my $inst (@{$func->{'code'}}) {
			$str .= $inst->[0];
		}
		$str .= "\n" . "="x80 . "\n\n";
    }
    return $str;
}

sub getcharstar {
    my ($charstar);

    foreach my $func (@objlist) {

		my ($inst, $maxinstlen, $maxasmlen, $codelen)  = ("",0,0,0);

		$maxinstlen = 0;
		foreach $inst (@{$func->{'code'}}) {
			$maxinstlen = length($inst->[0])
				if (length($inst->[0]) > $maxinstlen);
		}
		$maxinstlen+=4;

		$maxasmlen = 0;
		foreach $inst (@{$func->{'code'}}) {
			if ($opt_I) {
				$maxasmlen = length($inst->[1] . $inst->[2])
					if length($inst->[1] . $inst->[2]) > $maxasmlen;
			} else {
				$maxasmlen = length($inst->[1])
					if (length($inst->[1]) > $maxasmlen);
			}
		}

		foreach $inst (@{$func->{'code'}}) {
			$codelen += length($inst->[0])/4;
		}

		$charstar .= "#define " . uc($func->{'name'}) . "_LENGTH $codelen\n\n";

		$charstar .= "char $func->{'name'}\[\] = \n";
		foreach $inst (@{$func->{'code'}}) {
			$charstar .= sprintf("%-".$maxinstlen."s/*  %-".$maxasmlen."s  */\n",
								 "\"$inst->[0]\"",
								 $inst->[1] . $inst->[2]);
		}
		$charstar .= ";\n\n";
    }
    return $charstar;
}

sub testes {
    my $testes = &getcharstar;
    my $firstarray = $objlist[0]->{'name'};

    if (@objlist > 1) {
		print STDERR "  ** Warning... this makes little sense now...\n  ** Try using the -C option to list segment to concatenate!\n";
    }

    $testes .= <<"FOOBER";
int main(void) {
   int *ret;

   ret = (int *)&ret + 2;
   (*ret) = (int)$firstarray;

   return(0);
}
FOOBER

    return $testes;
}

sub shellinfo {
    my ($func,$codelen,$inst);
	foreach $func (@objlist) {
		print STDERR "=> Function: $func->{'name'}\n";
		$codelen = 0;
		foreach $inst (@{$func->{'code'}}) {
			$codelen += length($inst->[0])/4;
		}
		print STDERR "   Length: $codelen bytes\n";
		print STDERR "   Whitespace: $func->{'spaces'}\n";
		print STDERR "   Shell Chars: $func->{'shell'}\n";
		print STDERR "   Nulls: $func->{'nulls'}\n";
		print STDERR "   Non-ASCII: $func->{'nascii'}\n";
		print STDERR "   Numeric: $func->{'numeric'}\n";
		print STDERR "   Upper-Case: $func->{'ucase'}\n";
		print STDERR "   Lower-Case: $func->{'lcase'}\n";
	}
}

sub getfunc {
    my ($func) = @_;
    my (%codehash, @func, $hexstr, $codes);

    if (!defined($functrack{$func})) {
		@func = getasmblock($func);
		if (@func) {
			$functrack{$func} = 1;
			$codes = makehexhash(\@func);

			$codehash{'name'} = $func;
			$codehash{'spaces'} = shift @{$codes};
			$codehash{'nulls'} = shift @{$codes};
			$codehash{'shell'} = shift @{$codes};
			$codehash{'nascii'} = shift @{$codes};
			$codehash{'numeric'} = shift @{$codes};
			$codehash{'ucase'} = shift @{$codes};
			$codehash{'lcase'} = shift @{$codes};
			$codehash{'code'} = $codes;

			push @objlist, \%codehash;

			if ($opt_R) {
				foreach (@func) {
					if (/<(_?\w+?)(?:(\+|-)0x(\d|[a-f])+)?>/i) {
						getfunc($1);
					}
				}
			}
		}
    }
}

sub getasmblock {
    my ($func) = @_;
    my (@func,$lines);

    $lines = 0;
    for (my $x = 0; $x < @obj; $x++) {
        if ($obj[$x] =~ /^(?:\d|[a-zA-Z])+\s+<$func>:$/) {
            $x++;
            while ($obj[$x] !~ /^\s+$/ &&
				   $obj[$x] !~ /^Disassembly/i &&
				   $obj[$x] !~ /^\.\.\.$/) {
                push @func, $obj[$x++];
            }
			last;
        }
    }
    return @func;
}

sub makehexhash {
    my ($func) = @_;
    my (@hex,$hex,$asm,$info,@codes);

    my ($spaces,$nulls,$nascii,$shellcnt,$shells,@shells) = (0,0,0,0,"",());
	my ($numeric,$nums,@nums)   = (0,"",());
	my ($ucase,$uchars,@uchars) = (0,"",());
	my ($lcase,$lchars,@lchars) = (0,"",());


    foreach (@$func) {
		(@shells,@nums,@uchars,@lchars) = ();

		if ($asm = (split /\t/)[2]) {
			$asm =~ s/\s+$//;
			$asm =~ s/,/, /g;
		} else {
			$asm = "";
		}

		$info = "";

		@hex = split /\s+/, (split /\t/)[1];

		foreach (@hex) {
			if ($opt_I) {
				if (chr(hex($_)) =~ /(?:\s|0b)/i) {
					$spaces++;
					$info .= " (WS)" if $info !~ /\(WS\)/;
				}
				if ($_ eq "00") {
					$nulls++;
					$info .= " (NULL)" if $info !~ /\(NULL\)/;
				}
				if (chr(hex($_)) =~ /(\d)/) {
					$numeric++;
					push @nums, $1 if !grep /$1/,@nums;
					$info .= " (#)" if $info !~ /\(#\)/;
				}
				if (chr(hex($_)) =~ /([A-Z])/) {
					$ucase++;
					push @uchars, $1 if !grep /$1/,@uchars;
					$info .= " (UC)" if $info !~ /\(UC\)/;
				}
				if (chr(hex($_)) =~ /([a-z])/) {
					$lcase++;
					push @lchars, $1 if !grep /$1/,@lchars;
					$info .= " (lc)" if $info !~ /\(lc\)/;
				}
				if (hex($_) < hex("20") || hex($_) > hex("7e")) {
					$nascii++;
					$info .= " (!ASC)" if $info !~ /\(!ASC\)/;
				}
				if (chr(hex($_)) =~ /(!|&|;|\'|\`|\\|\/|\"|\||\*|\?|~|<|>|\^|\(|\)|\[|\]|\$|{|}|\n|\r)/) {
					$shellcnt++;
					push @shells, $1 if !grep /$1/,@shells;
					$info .= " (SH)" if $info !~ /\(SH\)/;
				}
			}
		}

		if ($opt_I) {
			$shells = join ' ',@shells;
			$info =~ s/\(SH\)/\(SH \"$shells\"\)/;

			$nums = join ' ',@nums;
			$info =~ s/\(#\)/\(# \"$nums\"\)/;

			$uchars = join ' ', @uchars;
			$info =~ s/\(UC\)/\(UC \"$uchars\"\)/;

			$lchars = join ' ', @lchars;
			$info =~ s/\(lc\)/\(lc \"$lchars\"\)/;
		}

		map {$_ = uc($_)} @hex if $opt_U;
		map {$_ = "\\x$_"} @hex;
		$hex = join "", @hex;

		push @codes, [$hex,$asm,$info];
    }
    unshift @codes, ($spaces,$nulls,$shellcnt,$nascii,$numeric,$ucase,$lcase);

    return \@codes;
}

sub find_exec {
    my ($prog, $lpath) = @_;

    my (%ph);

    #if No $lpath is passed then make a good generic one!
    # Always append the environment's path to the end of the provided one!
    $lpath = "/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin"
        if !defined($lpath);
    $lpath .= $ENV{'PATH'};

    #verify unicity... unnecessary
    foreach (split /:/, $lpath) {
        $ph{$_} = 1;
    }

    foreach my $path (keys %ph) {
        if (-e "$path/$prog") {
            return("$path/$prog");
        }
    }

    print STDERR "Cannot find $prog in $lpath!\n";
    return "";
}

sub usage {
    my $cmd = $0;
    $cmd =~ s/.*\/(.*)\s*$/$1/;

    print <<"USAGE";
Usage: $cmd <options> [Object]

Options: -h               : Display this message
         -d               : Simply disassemble cleanly
         -s               : Output a raw hex string
         -i               : Output a c-style header file
         -e               : Output reverse-engineer style output
         -C <file|segs>   : Output a list of segments sequentially
         -t               : Attempt to output a test file with header
         -M <Name>        : Specify a name to associate with "main" in output
                            i.e. The first header array (usually named
                                 "shellcode") will be named <Name> instead.
         -I               : Produce informational output about each function.
         -S <Section>     : Begin in <Section> instead of main
         -R               : Recursively parse called functions
         -U               : Output shellcode in uppercase hex
USAGE
    exit(1);
}

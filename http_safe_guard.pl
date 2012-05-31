#!/usr/bin/perl

use strict;

#-----------------------------------------------------------------------#
#	HTTP SAFE GUARD version 0.1  @zembutsu (May 18, 2012)
#	To detect DoS Attack and auto filtering with iptables.
#	This script is under MIT License.
#-----------------------------------------------------------------------#

##################
# HTTP threshold #
my $LIMIT = 100;
##################


my $netstat = "netstat -atun | awk '{print \$5}' | cut -d: -f1 | sed -e '/^\$/d' |sort | uniq -c | sort -nr";

my $LOG = "/var/log/http_safe_guard.log"; 
my @IPT;

# main

open(CMD,"$netstat |");
foreach my $cmd (<CMD>) {
#	print $cmd;
	chomp $cmd;
	if ($cmd =~ /(\s+)(\d+)(\s)(.*)/) {
		next if ($4 eq '0.0.0.0');
#		print "$2, $4\n";
		if ($2 > $LIMIT) {
			print "$4 ($2)\n";
			print "/sbin/iptables -A INPUT -s $4 -p tcp --dport 80 -j DROP\n";
			my $IPT = "/sbin/iptables -A INPUT -s $4 -p tcp --dport 80 -j DROP";
			system($IPT);
			push (@IPT, $IPT); 
		}
	}

}
close(CMD);


if (@IPT) {
	if(open(LOG, ">>$LOG")) {	
		foreach my $ipt (@IPT) {
			print LOG $ipt,"\n";
		}
	}
}

exit;

1;


#!/usr/bin/perl

use strict;
use Net::SNMP;
use Net::IPv4Addr;
use Data::Dumper;

our $comunity = shift @ARGV;
our $altComunity = shift @ARGV;
our $centralRouterIP = $ARGV[0];
our @queue = @ARGV;
our %visited;

our %rt;
our %ifIP;
our %hopToName;
our %foreign;

our $nameOid = ".1.3.6.1.2.1.1.5"; # SNMPv2-MIB::sysName
our $descrOid = ".1.3.6.1.2.1.1.1"; # SNMPv2-MIB::sysDescr
our $rfc1213Oid = ".1.3.6.1.2.1.4.21.1"; # RFC1213-MIB::ipRouteEntry
our $ipforwardOid = ".1.3.6.1.2.1.4.24.4.1"; # IP-FORWARD-MIB::ipCidrRouteEntry
our $ifIndexOid = ".1.3.6.1.2.1.4.20.1.2"; # RFC1213-MIB::ipAdEntIfIndex

our %rfc1213Map = (
	"nextHop" => ".7",
	"dest"    => ".1",
	"mask"    => ".11",
	"type"    => ".8",
	"ifIndex" => ".2",
);

our %ipforwardMap = (
	"nextHop" => ".4",
	"dest"    => ".1",
	"mask"    => ".2",
	"type"    => ".6",
	"ifIndex" => ".5",
);

our %routeType = (
	3 => "local",
	4 => "remota",
);

sub fillIf($\%@) {
	my $name = shift;
	my $table = shift;
	my @names = @_;

	for my $oid (@names) {
		my ($ip) = $oid =~ /$ifIndexOid\.(.*)/;
		$ifIP{$name}{$table->{$oid}} = $ip;
		$hopToName{$ip} = $name;
	}
}

sub fillRT($$$\%\%@) {
	my $name = shift;
	my $hop = shift;
	my $base = shift;
	my $table = shift;
	my $map = shift;
	my @names = @_;

	my $nextHop = $base . $map->{nextHop};
	my $dest = $base . $map->{dest};
	my $mask = $base . $map->{mask};
	my $type = $base . $map->{type};
	my $ifIndex = $base . $map->{ifIndex};

	for my $oid (grep { /$nextHop/ } @names) {
		my ($id) = $oid =~ /$nextHop(.*)/;
		my $nextHopIP = $table->{$oid};
		my $dest = $table->{$dest . $id};
		my $mask = $table->{$mask . $id};
		my $ifIndex = $table->{$ifIndex . $id};
		my $type = $routeType{$table->{$type . $id}};

		next if $nextHopIP eq "0.0.0.0" && $type eq "remota";

		my ($ip,$cidr) = Net::IPv4Addr::ipv4_parse( "${dest} / ${mask}" );

		$rt{$name}{ip} = $hop;

		$rt{$name}{dest}{"$ip/$cidr"}{nextHop} = $nextHopIP;
		$rt{$name}{dest}{"$ip/$cidr"}{type} = $type;

		$rt{$name}{nextHop}{$nextHopIP} = $ifIP{$name}{$ifIndex} unless $type eq "local";

		$foreign{$nextHopIP}{"$ip/$cidr"} = 1;
	}

	#print "rt: ", Dumper($rt{$name});

	return keys %{$rt{$name}{nextHop}};
}

while(@queue) {
	my $hop = pop @queue;
	# If you need to change IPs to avoid firewall rules,
	# do so here:
	#$hop =~ s/blocked ip/allowed ip/;

	next unless $hop =~ /^(10\.|172\.1|192\.168)/;

	if (!$visited{$hop}) {
		$visited{$hop} = 1;

		#print "Visiting $hop\n";

		my ($session, $error) = Net::SNMP->session(
				   -hostname      => $hop,
				   -version       => "2c",
				   -community     => $comunity,   # v1/v2c
			);

		if ($session) {
			my $nameTable = $session->get_table(-baseoid => $nameOid);
			if (!defined($nameTable)) {
				$session->close();
				($session, $error) = Net::SNMP->session(
					   -hostname      => $hop,
					   -version       => "2c",
					   -community     => $altComunity,   # v1/v2c
				);
				$nameTable = $session->get_table(-baseoid => $nameOid);
			}
			my $descrTable = $session->get_table(-baseoid => $descrOid);

			if (defined($nameTable)) {
				my $name = join "", values %{$nameTable};
				next if defined($rt{$name});

				$rt{$name}{"descr"} = join "", values %{$descrTable};
				$rt{$name}{"descr"} =~ s%[\n\r]% %g;

				my $ifTable = $session->get_table(-baseoid	=> $ifIndexOid);
				my @ifNames = $session->var_bind_names();
				fillIf($name, %{$ifTable}, @ifNames);

				my $rfc1213Table = $session->get_table(-baseoid	=> $rfc1213Oid);
				my @rfc1213Names = $session->var_bind_names();
				my @rfc1213NextHops = fillRT($name, $hop, $rfc1213Oid, %{$rfc1213Table}, %rfc1213Map, @rfc1213Names);
				push @queue, grep { ! $visited{$_} } @rfc1213NextHops;

				my $ipforwardTable = $session->get_table(-baseoid	=> $ipforwardOid);
				my @ipforwardNames = $session->var_bind_names();
				my @ipforwardNextHops = fillRT($name, $hop, $ipforwardOid, %{$ipforwardTable}, %ipforwardMap, @ipforwardNames);
				push @queue, grep { ! $visited{$_} } @ipforwardNextHops;
			}

			$session->close();
		} else {
			warn "Error opening session: $error\n";
		}
	}
}

#print Dumper(%rt);
#print Dumper(%ifIP);
#print Dumper(%hopToName);

print "digraph network {\n";
print "rankdir=LR;\n";
my $centralRouter = $hopToName{$centralRouterIP};
for my $router (sort keys %rt) {
	my $descr = $rt{$router}{descr};
	my $ip = $rt{$router}{ip};
	$descr =~ s/^(.{0,40}).*/$1/;

	for my $nextHop (sort keys %{$rt{$router}{nextHop}}) {
		if (defined($rt{$hopToName{$nextHop}})) {
			print "\t\"$router\" -> \"$hopToName{$nextHop}\" [ style=bold label=\"$rt{$router}{nextHop}{$nextHop}\" ];\n";
		}
	}

	print "\tsubgraph {\n";
	print "\t\t\"$router\" [ shape=record style=rounded scale=true label=\" { $router | $ip } | $descr\" ];\n";
	for my $nextHop (sort keys %{$rt{$router}{nextHop}}) {
		if (!defined($rt{$hopToName{$nextHop}})) {
			print "\t\t\t\"$router\" -> \"$nextHop\" [ style=dotted label=\"$rt{$router}{nextHop}{$nextHop}\" ];\n";
			print "\t\t\t\t\"$nextHop\" [ shape=doublecircle rank=min ];\n";
			for my $net (sort keys %{$foreign{$nextHop}}) {
				if (($net eq "0.0.0.0/0") || ($net eq "")) {
					print "\t\t\t\t\t\"$nextHop\" -> \"$centralRouter\" [ style=dotted dir=both ];\n";
				} else {
					print "\t\t\t\t\t\"$nextHop\" -> \"$net\" [ style=dotted dir=both ];\n";
				}
			}
		}
	}
	for my $dest (sort keys %{$rt{$router}{dest}}) {
		next if $rt{$router}{dest}{$dest}{type} eq "remota";
		print "\t\t\t\"$router\" -> \"$dest\" [ arrowhead=odiamond style=dashed ];\n";
		print "\t\t\t\t\"$dest\" [ shape=ellipse rank=min ];\n";
	}
	print "\t}\n";
}
print "}\n";


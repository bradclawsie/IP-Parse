use v6;
use Test;
use Net::IP::Parse;
use Subsets::Common;

lives-ok {
    my IP $ip = IP.new(addr=><1.2.3.4>);
    is ($ip.version == 4), True, 'is ipv4';
    my IP $ip2 = IP.new(octets=>Array[UInt8].new(1,2,3,4));
    is ($ip ip== $ip2), True, 'constructors equivalent';
}, 'valid';

lives-ok {
    my IP $ip = IP.new(octets=>Array[UInt8].new(1,2,3,4));
    is ($ip.version == 4), True, 'is ipv4';
}, 'valid';

lives-ok {
    my IP $ip = IP.new(octets=>Array[UInt8].new(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16));
    is ($ip.version == 6), True, 'is ipv6';
}, 'valid';

dies-ok {
    my IP $ip = IP.new(octets=>Array[UInt8].new(1,2,3));
    my IP $ips = IP.new(addr=><1.2.3>);
}, 'undersized octets array';

dies-ok {
    my IP $ip = IP.new(octets=>Array[UInt8].new(1,2,3,256));
}, 'overflow octet';

dies-ok {
    my IP $ip = IP.new(octets=>Array[UInt8].new(-1,2,3,255));
}, 'underflow octet';

dies-ok {
    my IP $ip = IP.new(octets=>Array[UInt8].new(1,2,3,4,5));
}, 'oversized octets array';

dies-ok {
    my IP $ip = IP.new(octets=>Array[UInt8].new(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15));
}, 'undersized octets array';

dies-ok {
    my IP $ip = IP.new(octets=>Array[UInt8].new(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17));
}, 'oversized octets array';

lives-ok {
    my $ip = IP.new(addr=><1.2.3.4>);
    is ($ip.str eq ip_str($ip) eq '1.2.3.4'), True, 'str is valid';
}, 'valid string output';

lives-ok {
    my $ip0 = IP.new(addr=>'8.8.8.8');
    my $ip1 = IP.new(addr=>'8.8.8.0');
    is ($ip0 ip== $ip0), True, 'addrs are equivalent';
    is ($ip0 ip== $ip1), False, 'addrs are not equivalent';
    is ($ip0 ip>= $ip1), True, 'lhs gt rhs';
    is ($ip1 ip<= $ip0), True, 'lhs gt rhs';
}, 'valid comparisons';

lives-ok {
    my $ip = IP.new(addr=>'8.8.8.8');
    is ($ip.version == 4), True, 'is ipv4';
}, 'valid string constructor';

dies-ok {
    my $ip = IP.new(addr=>'8.8.88');
}, 'detected invalid string constructor';

dies-ok {
    my $ip = IP.new(addr=><8.8.8.8.8>);
}, 'bad number of address chunks detected';

dies-ok {
    my $ip = IP.new(addr=><8.8.8>);
}, 'bad number of address chunks detected';

dies-ok {
    my $ip = IP.new(addr=><8.8.8.256>);
}, 'address overflow detected';

dies-ok {
    my $ip = IP.new(addr=><8.8.8.-1>);
}, 'address underflow detected';

lives-ok {
    my $t = 0xdfea;
    my ($l,$r) = word_bytes $t;
    my $word = bytes_word $l, $r;
    is ($word == $t), True, 'word to bytes to word'
}, 'word to bytes to word';

dies-ok {
    my $t = 65536;
    my ($l,$r) = word_bytes $t;
}, 'word overflow';

lives-ok {
    my $t = 0xdfea;
    my ($l,$r) = word_bytes $t;
    my $word = bytes_word $l, $l;
    is ($word == $t), False, 'word to bytes not to word'
}, 'bad bytes detected';

dies-ok {
    my @b = ipv6_octets_right_align (1,2);
}, 'detected undersized array';

dies-ok {
    my @b = ipv6_octets_right_align (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17);
}, 'detected oversized array';

dies-ok {
    my @b = ipv6_octets_right_align (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,9999999);
}, 'detected bad array element';

lives-ok {
    my @in = (255,240,128,12,0,0,0,0,0,0,0,0,0,0,0,0);
    my @expected = (0,0,0,0,0,0,0,0,0,0,0,0,255,240,128,12);
    my @out = ipv6_octets_right_align @in;
    is ((@out Z== @expected).all.so), True, 'output is expected';
}, 'right align';

lives-ok {
    my @in = (0,0,0,0,0,0,0,0,0,0,0,0,255,240,128,12);
    my @expected = (0,0,0,0,0,0,0,0,0,0,0,0,255,240,128,12);
    my @out = ipv6_octets_right_align @in;
    is ((@out Z== @expected).all.so), True, 'output is expected';
}, 'right align';

lives-ok {
    my @in = (12,0,0,0,0,0,0,0,0,0,0,0,255,240,128,12);
    my @expected = (12,0,0,0,0,0,0,0,0,0,0,0,255,240,128,12);
    my @out = ipv6_octets_right_align @in;
    is ((@out Z== @expected).all.so), True, 'output is expected';
}, 'right align';

lives-ok {
    my @in = (12,0,30,0,0,0,0,0,0,0,0,0,0,0,0,0);
    my @expected = (0,0,0,0,0,0,0,0,0,0,0,0,12,0,30,0);
    my @out = ipv6_octets_right_align @in;
    is ((@out Z== @expected).all.so), True, 'output is expected';
}, 'right align';

lives-ok {
    my @in = (0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0);
    my @expected = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1);
    my @out = ipv6_octets_right_align @in;
    is ((@out Z== @expected).all.so), True, 'output is expected';
}, 'right align';

lives-ok {
    my @in = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0);
    my @expected = @in;
    my @out = ipv6_octets_right_align @in;
    is ((@out Z== @expected).all.so), True, 'output is expected';
}, 'right align';

lives-ok {
    my IP $ip = IP.new(addr=><::1>);
    is ($ip.version == 6), True, 'is ipv6';
}, 'valid';

lives-ok {
    my IP $ip = IP.new(addr=><1::>);
    my @octets = 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0;
    is (($ip.version == 6) && ($ip.octets == @octets)), True, 'is ipv6';
}, 'valid';

lives-ok {
    my IP $ip = IP.new(addr=><2001:db8:a0b:12f0::1>);
    my @octets = 32,1,13,184,10,11,18,240,0,0,0,0,0,0,0,1;
    is ($ip.version == 6), True, 'is ipv6';
}, 'valid';

lives-ok {
    my IP $ip = IP.new(addr=><1:2:3:4:5:6:7:8>);
    my @octets = 0,1,0,2,0,3,0,4,0,5,0,6,0,7,0,8;
    is (($ip.version == 6) && ($ip.octets == @octets)), True, 'is ipv6';
}, 'valid';

dies-ok {
    my $ip = IP.new(addr=><1::10000>);
}, 'address overflow detected';

dies-ok {
    my $ip = IP.new(addr=><1::-1>);
}, 'address underflow detected';

lives-ok {
    my IP $ip = IP.new(addr=><2001:db8:a0b:12f0::1%eth0>);
    is (($ip.version == 6) && ($ip.zone_id eq 'eth0')), True, 'is ipv6 with zone id';
}, 'valid';

dies-ok {
    my IP $ip = IP.new(addr=><2001:db8:a0b:12f0::1:1:1>);
}, 'bad addr detected';

dies-ok {
    my IP $ip = IP.new(addr=><1:2:3:4:5:6:7:8:9>);
}, 'bad addr detected';

dies-ok {
    my IP $ip = IP.new(addr=><2001:db8:a0b:12f0::1%>);
}, 'empty zone detected';

dies-ok {
    my IP $ip = IP.new(addr=>'');
}, 'empty address detected';

dies-ok {
    my IP $ip = IP.new(addr=><%eth0>);
}, 'empty address detected';

lives-ok {
    my IP $ip = IP.new(addr=><2001:db8:a0b:12f0::1:1>);
    is (ip_str($ip) eq '2001:db8:a0b:12f0:0:0:1:1'), True, 'str is valid';
}, 'valid string output';

lives-ok {
    my IP $ip = IP.new(addr=><1:0:0:1:0:0:0:1>);
    my $compressed = ipv6_compress_str($ip);
    is ($compressed eq '1:0:0:1::1'), True, 'compressed';
}, 'valid compress';

lives-ok {
    my IP $ip = IP.new(addr=><2001:db8:a0b:12f0::1:1>);
    my $compressed = ipv6_compress_str($ip);
    is ($compressed eq '2001:db8:a0b:12f0::1:1'), True, 'compressed';
}, 'valid compress';

lives-ok {
    my IP $ip = IP.new(addr=><1:1:0:0:0:0:0:0>);
    my $compressed = ipv6_compress_str($ip);
    is ($compressed eq '1:1::'), True, 'compressed';
}, 'valid compress';

lives-ok {
    my IP $ip = IP.new(addr=><0:0:0:0:0:0:0:1>);
    my $compressed = ipv6_compress_str($ip);
    is ($compressed eq '::1'), True, 'compressed';
}, 'valid compress';

lives-ok {
    my IP $ip = IP.new(addr=><1:0:0:0:1:0:0:1>);
    my $compressed = ipv6_compress_str($ip);
    is ($compressed eq '1::1:0:0:1'), True, 'compressed';
}, 'valid compress';

lives-ok {
    my $s = '::ffff:ffff:ffff:ffff:ffff:ffff';
    my IP $ip = IP.new(addr=>$s);
    my IP $ref = IP.new(addr=>'0:0:ffff:ffff:ffff:ffff:ffff:ffff');
    is ($ip ip== $ref), True, 'equivalent with reference';
    my $compressed = ipv6_compress_str($ip);
    is ($compressed eq $s), True, 'compressed';
    
}, 'valid compress';

lives-ok {
    my CIDR $cidr = CIDR.new(cidr=>'8.8.8.8/16');
    my IP $addr = IP.new(addr=><8.8.8.8>);   
    is ($addr ip== $cidr.addr), True, 'addr equal';
    my IP $prefix_addr = IP.new(addr=><255.255.0.0>);
    is ($prefix_addr ip== $cidr.prefix_addr), True, 'prefix equal';
    my IP $wildcard_addr = IP.new(addr=><0.0.255.255>);
    is ($wildcard_addr ip== $cidr.wildcard_addr), True, 'wildcard equal';
    my IP $network_addr = IP.new(addr=><8.8.0.0>);
    is ($network_addr ip== $cidr.network_addr), True, 'network equal';
    my IP $broadcast_addr = IP.new(addr=><8.8.255.255>);
    is ($broadcast_addr ip== $cidr.broadcast_addr), True, 'broadcast equal';
}, 'valid ipv4 cidr';

lives-ok {
    my CIDR $cidr = CIDR.new(cidr=>'2001:db8::/32');
    my IP $addr = IP.new(addr=>'2001:0db8:0000:0000:0000:0000:0000:0000');
    is ($addr ip== $cidr.addr), True, 'addr equal';
    my IP $prefix_addr = IP.new(addr=>'ffff:ffff::');
    is ($prefix_addr ip== $cidr.prefix_addr), True, 'prefix equal';
    my IP $wildcard_addr = IP.new(addr=>'0:0:ffff:ffff:ffff:ffff:ffff:ffff');
    is ($wildcard_addr ip== $cidr.wildcard_addr), True, 'wildcard equal';
    my IP $network_addr = IP.new(addr=>'2001:db8:0:0:0:0:0:0');
    is ($network_addr ip== $cidr.network_addr), True, 'network equal';
    my IP $broadcast_addr = IP.new(addr=>'2001:db8:ffff:ffff:ffff:ffff:ffff:ffff');
    is ($broadcast_addr ip== $cidr.broadcast_addr), True, 'broadcast equal';
}, 'valid ipv6 cidr';

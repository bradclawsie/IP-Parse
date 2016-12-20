use v6;
use Test;
use Net::IP::Parse;

lives-ok {
    my IP $ip = IP.new(addr=><8.8.8.8>);
    is ($ip.version == 4), True, 'is ipv4';
}, 'valid';

lives-ok {
    my $ip = IP.new(addr=><1.2.3.4>);
    is (ip_str($ip) eq '1.2.3.4'), True, 'str is valid';
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
    say '1:0:0:1:0:0:0:1';
    my $compressed = ipv6_compress_str($ip);
    say $compressed;
}, 'valid string output';

lives-ok {
    my IP $ip = IP.new(addr=><2001:db8:a0b:12f0::1:1>);
    my $compressed = ipv6_compress_str($ip);
    say $compressed;
}, 'valid string output';

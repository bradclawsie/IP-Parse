use v6;
use Test;
use Net::IP::Parse;

lives-ok {
    my IP $ip = IP.new(addr=><8.8.8.8>);
    is ($ip.version == 4), True, 'is ipv4';
}, 'valid';

#lives-ok {
#    my $ip = IP.new(addr=><8.8.8.8>);
#    is ($ip.to_str() eq '8.8.8.8'), True, 'str is valid';
#}, 'valid string match';


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


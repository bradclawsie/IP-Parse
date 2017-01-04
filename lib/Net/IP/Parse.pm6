use v6;
use Subsets::Common;

unit module Net::IP::Parse:auth<bradclawsie>:ver<0.0.1>;

my package EXPORT::DEFAULT {
    class VersionError is Exception {
        has $.input;
        method message() { 'no IP version detected: ' ~ $.input; }
    }
    
    class AddressError is Exception {
        has $.input;
        method message() { 'bad address detected: ' ~ $.input; }
    }

    subset IPVersion of Int where * == 4|6;

    my sub word_bytes(UInt16:D $word --> List:D[UInt8]) {
        return (($word +> 8) +& 0xff),($word +& 0xff); 
    }
    
    my sub bytes_word(UInt8:D $left_byte, UInt8:D $right_byte --> UInt16:D) {
        return (($left_byte +& 0xff ) +< 8) +| ($right_byte +& 0xff);
    }

    # Parse and return just the octets part of an IPv6 address.
    my sub ipv6_octets(Str:D $addr --> Array:D[UInt8]) {
        my UInt8 @bytes[16];
        @bytes[^16] = (loop { 0 });
        my (Str @left_words_strs, Str @right_words_strs);

        given ($addr.comb: '::').Int {
            when 0 {
                @left_words_strs = $addr.split: ':';
                AddressError.new(input => "addr len: $addr").throw if @left_words_strs.elems != 8;
            }
            when 1 {                    
                my ($left_words_str,$right_words_str) = $addr.split: '::', 2;
                my sub f(Str:D $s --> Seq:D) { return ($s.split: ':').grep: {.chars > 0}; }
                @left_words_strs = f $left_words_str;
                @right_words_strs = f $right_words_str;
                if @left_words_strs.elems + @right_words_strs.elems > 6 {
                    AddressError.new(input => "bad segment count: $addr").throw;
                }
            }
            default { AddressError.new(input => "bad addr on split: $addr").throw; }
        }

        my ($i,$j) = (0,15);
        for @left_words_strs -> $word_str {
            my UInt16 $word = $word_str.parse-base: 16;
            (@bytes[$i++],@bytes[$i++]) = word_bytes $word;
        }
        for @right_words_strs.reverse -> $word_str {
            my UInt16 $word = $word_str.parse-base: 16;
            my ($l,$r) = word_bytes $word;
            (@bytes[$j--],@bytes[$j--]) = ($r,$l);
        }
        return @bytes;
    }
    
    class IP {
        has UInt8 @.octets;
        has IPVersion $.version = Nil;
        has Str $.zone_id = Nil;
        
        multi submethod BUILD(Str:D :$addr) {
            if ($addr ~~ /\./) {
                my $matches = (rx|^(\d+).(\d+).(\d+).(\d+)$|).ACCEPTS: $addr;
                AddressError.new(input=>$addr).throw unless so $matches;
                my UInt8 @octets = $matches.list.map: {.UInt};
                self.BUILD(octets=>@octets);
            } elsif ($addr ~~ /\:/) {
                my ($routable_part,$zone_id_part) = $addr.split: '%',2;
                if $zone_id_part ~~ Str {
                    if $zone_id_part eq '' {
                        AddressError.new(input=>"malformed zone from $addr").throw;
                    }
                    $!zone_id := $zone_id_part
                }
                self.BUILD(octets=>ipv6_octets $routable_part);
            } else {
                AddressError.new(input=>"no version detected from $addr").throw;
            }
        }

        multi submethod BUILD(Array:D[UInt8] :$octets where $octets.elems == 4|16) {
            @!octets = Array[UInt8].new((0..^$octets.elems));
            my $i = 0;
            for @($octets) -> $octet { @!octets[$i++] := $octet; }
            $!version := $octets.elems == 4 ?? 4 !! 6;
        }
        
        method str(--> Str:D) {
            if $!version == 4 {
                return @!octets.join: '.';
            } else {
                return (@!octets.map: {sprintf("%x", bytes_word($^a,$^b))}).join: ':';
            }
        }

        method compress_str(--> Str:D) {
            if $!version == 4 {
                return self.str;
            } else {
                my ($i,$max_start,$max_end,$max_len,$start) = (0,0,0,0,-1);
                for @!octets -> $left_byte,$right_byte {
                    if $left_byte == 0 && $right_byte == 0 {
                        $start = $i if $start == -1;
                        my ($end,$len) = ($i,$i - $start);
                        ($max_start,$max_end,$max_len) = ($start,$end,$len) if $len > $max_len;
                    } else {
                        $start = -1;
                    }
                    $i++;
                }
                if $start != -1 {
                    my $len = 7 - $start;
                    ($max_start,$max_end,$max_len) = ($start,7,$len) if $len > $max_len;
                }

                my @print_words = @!octets.map: {sprintf("%x", bytes_word($^a,$^b))};
                if $max_len != 0 {                    
                    my ($pre,$post) = ('','');
                    $pre = @print_words[0..($max_start-1)].join: ':' if $max_start > 0;
                    $post = @print_words[($max_end+1)..7].join: ':' if $max_end < 8;
                    return $pre ~ '::' ~ $post;
                } else {
                    return @print_words.join: ':';
                }
            }
        }
    }
    
    my sub cmp(IP:D $lhs, IP:D $rhs --> Bool:D) {
        my $l := ($lhs.version == 4) ?? 4 !! 16;
        return $lhs.octets == $l && $rhs.octets == $l;
    }
    
    our sub infix:<< ip== >> (IP:D $lhs, IP:D $rhs --> Bool:D) {
        return cmp($lhs,$rhs) && so ($lhs.octets Z== $rhs.octets).all;
    }

    our sub infix:<< ip<= >> (IP:D $lhs, IP:D $rhs --> Bool:D) {
        return cmp($lhs,$rhs) && so ($lhs.octets Z<= $rhs.octets).all;
    }

    our sub infix:<< ip>= >> (IP:D $lhs, IP:D $rhs --> Bool:D) {
        return cmp($lhs,$rhs) && so ($lhs.octets Z>= $rhs.octets).all;
    }

    class CIDR {

        has UInt $.prefix;
        has IP $.addr;       
        has IP $.prefix_addr;
        has IP $.broadcast_addr;
        has IP $.network_addr;
        has IP $.wildcard_addr;
        
        multi submethod BUILD(Str:D :$cidr) {
            my Str @s = split('/',$cidr);
            unless (@s.elems == 2 && @s[0] ne '' && @s[1] ne '') {
                AddressError.new(input=>"bad cidr $cidr").throw;
            }
            my $prefix = (@s[1]).parse-base(10);
            AddressError.new(input=>"bad cidr $cidr").throw unless $prefix ~~ Int;
            self.BUILD(addr=>IP.new(addr=>@s[0]),prefix=>$prefix);
        }

        multi submethod BUILD(IP:D :$addr, UInt:D :$prefix) {
            my $octet_count = 4;
            my $max_prefix = 32;
            ($octet_count,$max_prefix) = (16,128) if $addr.version == 6;
            AddressError.new(input=>"prefix $prefix out of range").throw if $prefix > $max_prefix;

            # calculate mask
            my UInt8 @b[16];
            @b[^16] = (loop { 0 });
            my $div = $prefix div 8;
            for 0..^$div -> $i { @b[$i] = 255; }
            @b[$div] = 255 +^ (2**((($div + 1) * 8) - $prefix)-1);
            
            my UInt8 @mask_octets[$octet_count] = $addr.version == 4 ?? @b[0..3] !! @b;
            my UInt8 @wildcard_octets[$octet_count];
            my UInt8 @network_octets[$octet_count];
            my UInt8 @broadcast_octets[$octet_count];
            for 0..^$octet_count -> $i {
                @wildcard_octets[$i] = 255 - @mask_octets[$i];
                @network_octets[$i] = @mask_octets[$i] +& $addr.octets[$i];
                @broadcast_octets[$i] = @wildcard_octets[$i] +| $addr.octets[$i];
            }
            $!addr := $addr;
            $!prefix := $prefix;
            $!prefix_addr := IP.new(octets=>@mask_octets);
            $!network_addr := IP.new(octets=>@network_octets);
            $!wildcard_addr := IP.new(octets=>@wildcard_octets);
            $!broadcast_addr := IP.new(octets=>@broadcast_octets);
        }

        method str(--> Str:D) {
            return $!addr.str ~ '/' ~ $!prefix;
        }
    }

    our sub infix:<< in_cidr >> (IP:D $ip, CIDR:D $cidr where $ip.version == $cidr.addr.version --> Bool:D) {
        return $ip ip>= $cidr.network_addr && $ip ip<= $cidr.broadcast_addr;
    }
}

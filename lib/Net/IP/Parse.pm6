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

    # Parse and return a 16-byte (UInt8) array from a substring
    # of an uncompressed IPv6 address string.
    my sub ipv6_octets_substring(Str:D $addr, UInt $expected? --> Array:D[UInt8]) {
        my UInt8 @bytes[16];
        @bytes[^16] = (loop { 0 });
        return Array[UInt8].new(@bytes) if $addr eq '';
        my ($i,$j) = (0,0);
        for $addr.split: ':' -> $word_str {
            my $word := $word_str.parse-base(16);
            if $word !~~ Int || !(0 <= $word <= 0xffff) {
                AddressError.new(input => "malformed word: $word_str from $addr").throw;
            }
            (@bytes[$i++],@bytes[$i++]) = word_bytes $word;
            $j++;
        }
        if $expected && $j != $expected {
            AddressError.new(input => "split $addr = $i, not $expected").throw;
        }
        return Array[UInt8].new(@bytes);
    }

    # Parse and return just the octets part of an IPv6 address.
    my sub ipv6_octets(Str:D $addr --> Array:D[UInt8]) {
        my UInt8 @bytes[16];
        @bytes[^16] = (loop { 0 });
        given ($addr.comb: '::').Int {
            when 0 {
                return ipv6_octets_substring $addr, 8;
            }
            when 1 {                    
                my ($left_words_str,$right_words_str) = $addr.split: '::', 2;
                
                if ($left_words_str.split(':').map({$_ if $_ ne ''}).elems +
                    $right_words_str.split(':').map({$_ if $_ ne ''}).elems) > 6 {
                    AddressError.new(input => "bad segment count: $addr").throw;
                }
                
                my UInt8 @left_bytes[16] = ipv6_octets_substring $left_words_str;
                my UInt8 @right_bytes[16] = ipv6_octets_substring $right_words_str;

                # rotate @right_bytes so that all words (byte pairs) are aligned to the right
                # of the sequence...i.e.:
                # (255,240,128,12,0,0,0,0,0,0,0,0,0,0,0,0) - >
                # (0,0,0,0,0,0,0,0,0,0,0,0,255,240,128,12)
                my ($n,$m) = (0,0);
                for @right_bytes -> $l,$r { $m = $n+1 if ($l != 0 || $r != 0); $n++ };
                @right_bytes = @right_bytes.rotate($m*2);

                # now merge these arrays to expose the sequence of zeros in the
                # middle represented by '::'.
                for ^16 -> $i { @bytes[$i] = @left_bytes[$i] +| @right_bytes[$i] }
                
                # Remove size constraint. Necessary to allow this to be input
                # to functions that accept Array[UInt8].                  
                return Array[UInt8].new(@bytes);
            }
            default { AddressError.new(input => "bad addr on split: $addr").throw; } 
        } 
    }
    
    class IP {
        has UInt8 @.octets;
        has IPVersion $.version = Nil;
        has Str $.zone_id = Nil;
        
        multi submethod BUILD(Str:D :$addr) {
            if ($addr ~~ /\./) {
                my $matches = (rx|^(\d+).(\d+).(\d+).(\d+)$|).ACCEPTS($addr);
                AddressError.new(input=>$addr).throw unless so $matches;
                my UInt8 @octets = $matches.list.map({.UInt});
                self.BUILD(octets=>@octets);
            } elsif ($addr ~~ /\:/) {
                my ($routable_part,$zone_id_part) = $addr.split: '%',2;
                if $zone_id_part ~~ Str {
                    if $zone_id_part eq '' {
                        AddressError.new(input=>"malformed zone from $addr").throw;
                    }
                    $!zone_id = $zone_id_part
                }
                self.BUILD(octets=>ipv6_octets $routable_part);
            } else {
                AddressError.new(input=>"no version detected from $addr").throw;
            }
        }

        multi submethod BUILD(Array:D[UInt8] :$octets where $octets.elems == 4|16) {
            @!octets = @($octets);
            $!version = $octets.elems == 4 ?? 4 !! 6;
        }
        
        method str(--> Str:D) {
            if $!version == 4 {
                return @!octets.join: '.';
            } else {
                return @!octets.map({sprintf("%x", bytes_word($^a,$^b))}).join: ':';
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

                my @print_words = @!octets.map({sprintf("%x", bytes_word($^a,$^b))});
                if $max_len != 0 {                    
                    my ($pre,$post) = ('','');
                    $pre = @print_words[0..($max_start-1)].join(':') if $max_start > 0;
                    $post = @print_words[($max_end+1)..7].join(':') if $max_end < 8;
                    return ($pre ~ '::' ~ $post);
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
            $!addr = $addr;
            $!prefix = $prefix;
            $!prefix_addr = IP.new(octets=>@mask_octets);
            $!network_addr = IP.new(octets=>Array[Int].new(@network_octets));
            $!wildcard_addr = IP.new(octets=>Array[Int].new(@wildcard_octets));
            $!broadcast_addr = IP.new(octets=>Array[Int].new(@broadcast_octets));
        }

        method str(--> Str:D) {
            return $!addr.str ~ '/' ~ $!prefix;
        }
    }

    our sub infix:<< in_cidr >> (IP:D $ip, CIDR:D $cidr where $ip.version == $cidr.addr.version --> Bool:D) {
        return $ip ip>= $cidr.network_addr && $ip ip<= $cidr.broadcast_addr;
    }
}

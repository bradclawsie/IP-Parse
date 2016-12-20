use v6;
use Subsets::Common;

unit module Net::IP::Parse:auth<bradclawsie>:ver<0.0.1>;

my package EXPORT::DEFAULT {
    class VersionError is Exception {
        has $.input;
        method message() { "no IP version detected:" ~ $.input; }
    }
    
    class AddressError is Exception {
        has $.input;
        method message() { "bad address detected:" ~ $.input; }
    }

    subset IPVersion of Int where * == 4|6;

    my sub valid_octet(Int:D $o --> Bool:D) is pure { return 0 <= $o <= 255; }
    
    our sub word_bytes(UInt16:D $word --> List:D[UInt8]) is pure {
        return (($word +> 8) +& 0xFF),($word +& 0xFF); 
    }
    
    our sub bytes_word(UInt8:D $left_byte, UInt8:D $right_byte --> UInt16:D) is pure {
        return (($left_byte +& 0xFF ) +< 8) +| ($right_byte +& 0xFF);
    }
    
    class IP {
        has UInt8 @.octets;
        has IPVersion $.version = Nil;
        has Str $.zone_id = Nil;

        # Parse and return just the octets part of an IPv4 address.
        our sub ipv4_octets(Str:D $addr --> Array:D[UInt8]) {
            my $matches = (rx|^(\d+).(\d+).(\d+).(\d+)$|).ACCEPTS($addr);
            AddressError.new(input=>$addr).throw unless so $matches;
            my UInt8 @octets = $matches.list.map({.Int});
            return @octets;
        }

        # Parse and return just the octets part of an IPv6 address.
        our sub ipv6_octets(Str:D $addr --> Array:D[UInt8]) {
            my UInt8 @bytes[16];
            @bytes[^16] = (loop { 0 });
            given ($addr.comb: '::').Int {
                when 0 {
                    my @words = $addr.split: ':';
                    AddressError.new(input => "words count:$addr").throw if @words.elems != 8;
                    my $i = 0;
                    for @words -> $word_str {
                        my $word := $word_str.parse-base(16);
                        if $word ~~ Failure {
                            AddressError.new(input => "malformed word $word_str").throw;
                        }
                        (@bytes[$i++],@bytes[$i++]) =  word_bytes $word;
                    }
                    # Remove size constraint. Necessary to allow this to be input
                    # to functions that accept Array[UInt8].
                    return Array[UInt8].new(@bytes); 
                }
                when 1 {
                    my UInt8 @left_bytes[16];
                    @left_bytes[^16] = (loop { 0 });
                    my ($left_words_str,$right_words_str) = $addr.split: '::', 2;
                    my @left_words = $left_words_str.split: ':';
                    my @right_words = $right_words_str.split: ':';
                    if (@left_words.elems + @right_words.elems) > 6 {
                        AddressError.new(input => "too many words in abbrev: $addr").throw;
                    }
                    my $i = 0;
                    for @left_words -> $word_str {
                        if $word_str ne '' {
                            my $word := $word_str.parse-base(16);
                            if $word ~~ Failure {
                                AddressError.new(payload => "malformed word $word_str").throw;
                            }
                            (@left_bytes[$i++],@left_bytes[$i++]) =  word_bytes $word;
                        }
                    }
                    my UInt8 @right_bytes[16];
                    @right_bytes[^16] = (loop { 0 });
                    $i = 15;
                    for @right_words.reverse -> $word_str {
                        if $word_str ne '' {
                            my $word = $word_str.parse-base(16);
                            if $word ~~ Failure {
                                AddressError.new(payload => "malformed word $word_str").throw;
                            }
                            my ($left_byte,$right_byte) = word_bytes $word;
                            @right_bytes[$i--] = $right_byte;
                            @right_bytes[$i--] = $left_byte;
                        }
                    }
                    for ^16 -> $i { @bytes[$i] = @left_bytes[$i] +| @right_bytes[$i] }
                    
                    # Remove size constraint. Necessary to allow this to be input
                    # to functions that accept Array[UInt8].                  
                    return Array[UInt8].new(@bytes);
                }
                default { AddressError.new(payload => "bad addr on split: $addr").throw; } 
            } 
        }
        
        multi submethod BUILD(Str:D :$addr) {
            if ($addr ~~ /\./) {
                self.BUILD(octets=>ipv4_octets $addr);
            } elsif ($addr ~~ /\:/) {
                my ($routable_part,$zone_id_part) = $addr.split: '%',2;
                if $zone_id_part ~~ Str {
                    if $zone_id_part eq '' {
                        AddressError.new(input=>$addr ~ "; malformed zone").throw;
                    }
                    $!zone_id = $zone_id_part
                }
                self.BUILD(octets=>ipv6_octets $routable_part);
            } else {
                AddressError.new(input=>$addr ~ "; no version detected").throw;
            }
        }

        multi submethod BUILD(Int:D :@octets) {
            given @octets.elems {
                when (4|16) {
                    AddressError.new(input=>@octets.gist ~ "; invalid octet").throw unless
                    @octets.map(&valid_octet).all.so;
                    @!octets = @octets;
                    $!version = 4 when 4;
                    $!version = 6 when 16;
                }
                default { AddressError.new(input=>@octets.gist ~ "; no version detected").throw; } 
            }
        }
    }

    my sub cmp(IP $lhs, IP $rhs) of Bool:D is pure {
        my $l := ($lhs.version == 4) ?? 4 !! 16;
        return $lhs.octets == $l && $rhs.octets == $l;
    }
    
    our sub infix:<< ip== >> (IP $lhs, IP $rhs) of Bool:D is pure {
        return cmp($lhs,$rhs) && so ($lhs.octets Z== $rhs.octets).all;
    }

    our sub infix:<< ip<= >> (IP $lhs, IP $rhs) of Bool:D is pure {
        return cmp($lhs,$rhs) && so ($lhs.octets Z<= $rhs.octets).all;
    }

    our sub infix:<< ip>= >> (IP $lhs, IP $rhs) of Bool:D is pure {
        return cmp($lhs,$rhs) && so ($lhs.octets Z>= $rhs.octets).all;
    }

    our sub ipv6_range_compress(IP:D $ip where $ip.version == 6) {
        my ($i,$longest_start, $longest_end, $len,$current_start) = (0,0,0,0,-1);
        for $ip.octets -> $left_byte,$right_byte {
            if $left_byte == 0 && $right_byte == 0 {
                $current_start = $i if $current_start == -1;
            } else {
                if $current_start != -1 {
                    my $current_end = $i - 1;
                    if ($current_end - $current_start) > $len {
                        ($longest_start,$longest_end,$len) =
                        ($current_start,$current_end,$current_end - $current_start);
                    }
                    $current_start = -1;
                }
            }
            $i++;
        }
        if $len > 0 {
            my @print_words = $ip.octets.map({sprintf("%x", bytes_word($^a,$^b))});
            my ($pre,$post) = ('','');
            if $longest_start > 0 {
                $pre = @print_words[0..($longest_start-1)].join(':');
            }
            if $longest_end < 8 { 
                $post = @print_words[($longest_end+1)..7].join(':');
            }
            say ($pre ~ '::' ~ $post);
        }
    }
    
    our sub ip_str(IP:D $ip --> Str:D) {
        if $ip.version == 4 {
            return $ip.octets.join: '.';
        } else {
            my @print_words = $ip.octets.map({sprintf("%x", bytes_word($^a,$^b))});
            return @print_words.join: ':';
        }        
    }
}

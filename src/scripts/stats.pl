#!/usr/bin/perl
use strict;

if ( $#ARGV < 0 ) { die "you need to specify an input file.\n"; }

open FILE, "<$ARGV[0]" or die "can't open $!\n";;


####################
# hashes to store our histograms
# and other related variables
my($num_deserializations);
my(%deserialized_classes);
my(%stack_locations);
my($num_memcache, $memcache_check_flag);


####################
# function: handle_class
# adds the class to the class statistics hash(es)
sub handle_class {
  my($klass) = (split ' ', shift)[-1];
  $deserialized_classes{$klass}++;
  $num_deserializations++;
  $memcache_check_flag = 1; # OK to check for memcache in stack
                            # flag helps avoid duplicates
}



###################
# function: handle_stack
# adds the stack to the various stack statistcs hashes
sub handle_stack {
  my($stack_location) = (split ' ', shift)[-1];
  $stack_locations{$stack_location}++;

  if( $memcache_check_flag ) { 
    if( $stack_location =~ /memcache/i ) {
      $num_memcache++;
      $memcache_check_flag = 0; # wait for next stack to check for memcache
                                # to avoid double counting
    }
  }
}




####################
# main
#

# chew up all lines prior to the first output we care about
my($line);
UNINTERESTING_LINE: while($line = <FILE>) {
  chomp $line;
  if( $line =~ /contrast/ ) {
    last UNINTERESTING_LINE;
  }
}

# now start processing our stuff
LINE: while($line = <FILE>) {
  # skip lines that are clearly not our stuff...
  if( not $line =~ /\./  ) { next LINE; }
  if( $line =~ /\//      ) { next LINE; }
  if( $line =~ /NRMUtil/ ) { next LINE; }

  if( $line =~ /contrast-rO0/ ) {
    handle_class($line);
    next LINE;
  }
  handle_stack($line);

}


############
# print histograms
my($klass,$count);
my(@klasses) = keys %deserialized_classes;
my(%packages, @packages, $package);
foreach $klass (@klasses) {
  # count the number of unique classes deserialized
  $count += $deserialized_classes{$klass};

  # get and count the unique packages deserialized
  @packages = split /\./, $klass;
  $package = @packages[0...$#packages-1];
  $packages{$package}++;
}
my(@stack_locations) = keys %stack_locations;

printf "recorded $count deserializations out of $num_deserializations\n";
printf "number of unique classes deserialized: $#klasses\n";
printf "number of unique packages from which deserialized classes were found: $#packages\n";
printf "number of unique stack locations involved (includes multiple entries for each deserialize event): $#stack_locations \n";
printf "number of traces that have memcache in the stack: $num_memcache\n";




#my($max)=50;
#printf "top $max highest stack locations (occuring least often in the histograms): \n";
#
#my($i)=0;
#my($loc);
#foreach $loc (  sort {$stack_locations{$a} <=> $stack_locations{$b}} keys %stack_locations) {
#   printf "$stack_locations{$loc} $loc\n";
#   if( $i++ > $max ) { last; }
#}


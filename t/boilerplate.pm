package t::boilerplate;

use strict;
use warnings;
use File::Spec::Functions qw( catdir updir );
use FindBin               qw( $Bin );
use lib               catdir( $Bin, updir, 'lib' ), catdir( $Bin, 'lib' );

use Test::More;
use Test::Requires { version => 0.88 };
use Module::Build;
use Sys::Hostname;

my $perl_ver;

BEGIN {
   my $builder; my $host = lc hostname; my $notes = {}; my $osname = lc $^O;

   $builder   = eval { Module::Build->current };
   $builder and $notes = $builder->notes;
   $perl_ver  = $notes->{min_perl_version} || 5.008;
   $Bin =~ m{ : .+ : }mx and plan skip_all => 'Two colons in $Bin path';
  ($osname eq 'mswin32' or $osname eq 'cygwin' or $osname eq 'darwin')
      and plan skip_all => 'OS not supported';
}

use Test::Requires "${perl_ver}";

sub import {
   strict->import;
   $] < 5.008 ? warnings->import : warnings->import( NONFATAL => 'all' );
   return;
}

1;

# Local Variables:
# mode: perl
# tab-width: 3
# End:
# vim: expandtab shiftwidth=3:

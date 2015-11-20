package t::boilerplate;

use strict;
use warnings;
use File::Spec::Functions qw( catdir catfile updir );
use FindBin               qw( $Bin );
use lib               catdir( $Bin, updir, 'lib' ), catdir( $Bin, 'lib' );

use Module::Build;
use Sys::Hostname;

sub plan (;@) {
   $_[ 0 ] eq 'skip_all' and print '1..0 # SKIP '.$_[ 1 ]."\n" and exit 0;
}

my ($builder, $host, $notes, $osname, $perl_ver);

BEGIN {
   $osname   = lc $^O;
   $host     = lc hostname;
   $builder  = eval { Module::Build->current };
   $notes    = $builder ? $builder->notes : {};
   $perl_ver = $notes->{min_perl_version} || 5.008;

   eval { require Test::Requires }; $@ and plan skip_all => 'No Test::Requires';

   $Bin =~ m{ : .+ : }mx and plan skip_all => 'Two colons in $Bin path';

   if ($notes->{testing}) {
      ($osname eq 'mswin32' or $osname eq 'cygwin' or $osname eq 'darwin')
         and plan skip_all => 'OS not supported';

      my $dumped = catfile( 't', 'exceptions.dd' );
      my $except = {}; -f $dumped and $except = do $dumped;

      exists $except->{ $host } and plan skip_all =>
         'Broken smoker '.$except->{ $host };
   }
}

use Test::Requires "${perl_ver}";
use Test::Requires { version => 0.88 };

use version; our $VERSION = qv( '0.2.1' );

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

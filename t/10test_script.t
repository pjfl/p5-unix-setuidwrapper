use t::boilerplate;

use Test::More;
use English qw( -no_match_vars );
use File::DataClass::IO;

use_ok 'Unix::SetuidWrapper';

{  package TestProg;

   use Moo;

   extends q(Class::Usul::Programs);
   with    q(Unix::SetuidWrapper);

   $INC{ 'TestProg.pm' } = __FILE__;
}

my $group = getgrgid( $GID );
my $subf  = io( [ 't', "${group}.sub" ] );

$subf->println( 'init_suid_wrapper' );

my $wrapper = TestProg->new( config  => { tempdir => 't', vardir => 't' },
                             noask   => 1,
                             secsdir => 't', );

ok exists $wrapper->_role_map->{root}, 'Root exists';

$wrapper = TestProg->new_with_options( config  => { tempdir => 't',
                                                    vardir  => 't' },
                                       method  => 'init_suid_wrapper',
                                       noask   => 1,
                                       secsdir => 't');

is $wrapper->secsdir->pathname, io( [ 't' ] )->pathname, 'Secure dir';

like $wrapper->untainted_cmd, qr{ \.10test_script\.t }mx, 'Untainted cmd';

done_testing;

# Local Variables:
# mode: perl
# tab-width: 3
# End:
# vim: expandtab shiftwidth=3:

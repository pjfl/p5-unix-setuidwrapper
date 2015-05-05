use t::boilerplate;

use Test::More;

use_ok 'Unix::SetuidWrapper';

{  package TestProg;

   use Moo;

   extends q(Class::Usul::Programs);
   with    q(Unix::SetuidWrapper);

   $INC{ 'TestProg.pm' } = __FILE__;
}

my $wrapper = TestProg->new( config => { tempdir => 't', vardir => 't' },
                             noask  => 1, );

ok exists $wrapper->_role_map->{root}, 'Root exists';

done_testing;

# Local Variables:
# mode: perl
# tab-width: 3
# End:
# vim: expandtab shiftwidth=3:

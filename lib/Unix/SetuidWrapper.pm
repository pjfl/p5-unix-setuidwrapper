package Unix::SetuidWrapper;

use 5.010001;
use namespace::autoclean;
use version; our $VERSION = qv( sprintf '0.1.%d', q$Rev: 5 $ =~ /\d+/gmx );

use Class::Usul::Constants  qw( AS_PARA FAILED FALSE NUL OK SPC TRUE );
use Class::Usul::Functions  qw( is_member loginid untaint_cmdline );
use Class::Usul::Types      qw( ArrayRef HashRef Object SimpleStr );
use Config;
use English                 qw( -no_match_vars );
use File::DataClass::Types  qw( Directory File );
use File::UnixAuth;
use List::Util              qw( first );
use Moo::Role;

# An instance of Class::Usul::Programs provides these
requires qw( config error exit_usage info method new_with_options
             output run_cmd untainted_argv yorn );

my $HASH_CHAR        = chr 35;
my $SUID_WRAPPER_SRC = do { local $RS = undef; <DATA> };

# Attribute constructors
my $_build_role_map = sub {
   my $self       = shift;
   my $group_data = $self->_unix_group->load->{group};
   my $user_data  = $self->_unix_passwd->load->{passwd};
   my $gmap       = {};
   my $umap       = {};

   for my $group (keys %{ $group_data }) {
      $gmap->{ $group_data->{ $group }->{gid} } = $group;
   }

   for my $user (keys %{ $user_data }) {
      $umap->{ $user } = [ $gmap->{ $user_data->{ $user }->{pgid} } ];
   }

   for my $group (keys %{ $group_data }) {
      for my $user (@{ $group_data->{ $group }->{members} }) {
         exists $umap->{ $user } or next;
         not is_member $group, $umap->{ $user }
                   and push @{ $umap->{ $user } }, $group;
      }
   }

   return $umap;
};

# Public attributes
has 'group_file'       => is => 'lazy', isa => File,
   builder             => sub { [ NUL, 'etc', 'group' ] }, coerce => TRUE;

has 'passwd_file'      => is => 'lazy', isa => File,
   builder             => sub { [ NUL, 'etc', 'passwd' ] }, coerce => TRUE;

has 'public_methods'   => is => 'ro',   isa => ArrayRef,  default => sub {
   [ qw( authenticate dump_config_attr dump_self list_methods ) ] };

has 'secure_dir'       => is => 'lazy', isa => Directory, coerce => TRUE,
   default             => sub { [ $_[ 0 ]->config->vardir, 'secure' ] };

has 'secure_extension' => is => 'ro',   isa => SimpleStr, default => '.sub';

# Private attributes
has '_authorised_user' => is => 'rwp',  isa => SimpleStr, default => NUL,
   reader              => 'authorised_user';

has '_role_map'        => is => 'lazy', isa => HashRef,
   builder             => $_build_role_map;

has '_unix_group'      => is => 'lazy', isa => Object, builder => sub {
   File::UnixAuth->new( builder     => $_[ 0 ],
                        cache_class => 'none',
                        path        => $_[ 0 ]->group_file,
                        source_name => 'group', ) };

has '_unix_passwd'     => is => 'lazy', isa => Object, builder => sub {
   File::UnixAuth->new( builder     => $_[ 0 ],
                        cache_class => 'none',
                        path        => $_[ 0 ]->passwd_file,
                        source_name => 'passwd', ) };

# Private functions
my $_find_method = sub {
   my ($wanted, $io) = @_;

   return first { $_ eq $wanted }
          map   { (split m{ \s+ $HASH_CHAR }mx, "${_} ${HASH_CHAR}")[ 0 ] }
          grep  { length } $io->chomp->getlines;
};

my $_split_perl5lib = sub {
   my $sep   = $Config{path_sep};
   my $nlibs = my @libs = split m{ $sep }mx, $ENV{PERL5LIB}, -1;

   return $nlibs, @libs;
};

my $_substitute = sub {
   my ($csrc,  $prog) = @_;
   my ($nlibs, @libs) = $_split_perl5lib->();
   my $libs           = join ', ', map { '"'.$_.'"' } @libs;

   $csrc =~ s{ \[% \s* executable_name \s* %\] }{$EXECUTABLE_NAME}imx;
   $csrc =~ s{ \[% \s* program_name    \s* %\] }{$prog}imx;
   $csrc =~ s{ \[% \s* nlibs           \s* %\] }{$nlibs}imx;
   $csrc =~ s{ \[% \s* libs            \s* %\] }{$libs}imx;

   return $csrc;
};

# Private methods
my $_list_auth_files = sub {
   my ($self, $user) = @_; my $extn = $self->secure_extension;

   return grep { $_->is_file }
          map  { $self->secure_dir->catfile( "${_}${extn}" ) }
              @{ $self->_role_map->{ $user } };
};

my $_is_setuid_authorised = sub {
   my ($self, $user) = @_; $user or return FALSE;

   my $wanted = $self->method; $wanted =~ s{ [\-] }{_}gmx;

   first { $wanted eq $_ } @{ $self->public_methods }
      and $self->_set__authorised_user( $user )
      and return TRUE;

   first { $_find_method->( $wanted, $_ ) } $self->$_list_auth_files( $user )
      and $self->_set__authorised_user( $user )
      and return TRUE;

   return FALSE;
};

# Construction
around 'new_with_options' => sub {
   my ($orig, @args) = @_;

   $ENV{CDPATH} = NUL; # For taint mode
   $ENV{PATH} = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

   my $self = $orig->( @args ); $self->method or $self->exit_usage( 0 );

   $EFFECTIVE_USER_ID == 0 or return $self; my $user = loginid $REAL_USER_ID;

   unless ($self->$_is_setuid_authorised( $user )) {
      $self->error( 'Access denied to '.$self->method." for ${user}" );
      exit FAILED;
   }

   $REAL_USER_ID = 0; $REAL_GROUP_ID = 0;

   return $self;
};

# Public methods
sub init_suid_wrapper : method {
   my $self = shift;
   my $conf = $self->config;
   my $prog = $conf->pathname;
   my $bind = $prog->parent;
   my $file = $prog->basename;
   my $secd = $self->secure_dir;
   my $extn = $self->secure_extension;
   my $gid  = $conf->pathname->stat->{gid};
   my $objf = $bind->catfile( ".${file}"   );
   my $srcf = $bind->catfile( ".${file}.c" );
   my @libs = $_split_perl5lib->(); shift @libs;
   my $text = 'Enable wrapper which allows limited access to some root '.
              'only functions like password checking and user management. '.
              'Necessary if the OS authentication store is used';

   $self->output( $text, AS_PARA );
   $self->output( 'Compiling [_1]',        { args => [ $objf ] } );
   $self->output( 'Perl [_1]',             { args => [ $EXECUTABLE_NAME ] } );
   $self->output( 'Libs [_1]',             { args => [ $_ ] } ) for (@libs);
   $self->output( 'Secure directory [_1]', { args => [ $secd ] } );
   $self->yorn( '+Enable suid root', FALSE, TRUE, 0 ) or return OK;
   $self->info( 'Compiling [_1]', { args => [ $objf ], quiet => TRUE } );

   # Restrict access for these files to root only
   chown 0, $gid, $secd; chmod oct '0700', $secd;

   for ($secd->filter( sub { m{ \Q$extn\E \z }mx } )->all_files) {
      chown 0, $gid, "${_}"; chmod oct '600', "${_}";
   }

   # Create the setuid root binary wrapper
   $srcf->print( $_substitute->( $SUID_WRAPPER_SRC, $prog ) );
   $self->run_cmd( [ 'make', ".${file}" ], { working_dir => $bind } );
   chown 0, $gid, $objf; chmod oct '04750', $objf; $srcf->unlink;
   return OK;
}

sub is_uid_zero {
   return $EFFECTIVE_USER_ID == 0 ? TRUE : FALSE;
}

sub wrapped_cmdline {
   my $self = shift; my $path = $self->config->pathname;

   return $path->parent->catfile( '.'.$path->basename ),
       @{ $self->untainted_argv };
}

1;

=pod

=encoding utf-8

=head1 Name

Unix::SetuidWrapper - Creates a setuid root wrapper for a Perl program

=head1 Synopsis

   package Admin;

   use namespace::autoclean;

   use English qw( -no_match_vars );
   use Moo;

   extends q(Class::Usul::Programs);
   with    q(Unix::SetuidWrapper);

   our $VERSION = '0.1';

   sub test_cmd : method {
      my $self = shift; $self->info( "User id $EFFECTIVE_USER_ID" ); return 0;
   }

   $INC{ 'Admin' } = __FILE__;

   package main;

   use Admin;

   my $app = Admin->new_with_options
      (  config => { tempdir => 't', vardir => 't' }, noask  => 1, );

   $app->is_uid_zero or exec $app->wrapped_cmdline or exit 1;

   exit $app->run;

=head1 Description

Creates a setuid root wrapper for a Perl program

=head1 Configuration and Environment

Defines the following attributes;

=over 3

=item C<authorised_user>

The name of the authorised user. This attribute is C<NULL> until the
authorisation check is complete

=item C<group_file>

A L<File::DataClass::IO> object reference for the Unix group file

=item C<passwd_file>

A L<File::DataClass::IO> object reference for the Unix password file

=item C<public_methods>

These methods are allowed to be executed by anyone with execute permission on
the original script

=item C<secure_dir>

The directory containing the files used to restrict access to methods. Each
file is named after a Unix group. If the method the user wants to run is in
one of the files and the user is in that group then the method execution
is allowed, otherwise permission is denied

=item C<secure_extension>

The extension applied to files in L</secure_dir>. Defaults to F<.sub>

=back

=head1 Subroutines/Methods

=head2 init_suid_wrapper

This method needs to be run a the super-user. It writes out the C source code
of the wrapper, compiles it, and sets it to run C<setuid> root. It also
restricts permission on L</secure_dir> and it's contents so that only root
can access them

=head2 is_uid_zero

Returns true if the effective user id is zero, false otherwise

=head2 wrapped_cmdline

Returns the command line used to invoke the script with the script name
replaced with that of the C<setuid> wrapper. The arguments on the command line
are untainted

=head1 Diagnostics

None

=head1 Dependencies

=over 3

=item L<Class::Usul>

=item L<File::DataClass>

=item L<File::UnixAuth>

=item L<Moo>

=back

=head1 Incompatibilities

There are no known incompatibilities in this module

=head1 Bugs and Limitations

There are no known bugs in this module. Please report problems to
http://rt.cpan.org/NoAuth/Bugs.html?Dist=Unix-SetuidWrapper.
Patches are welcome

=head1 Acknowledgements

Larry Wall - For the Perl programming language

=head1 Author

Peter Flanigan, C<< <pjfl@cpan.org> >>

=head1 License and Copyright

Copyright (c) 2015 Peter Flanigan. All rights reserved

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself. See L<perlartistic>

This program is distributed in the hope that it will be useful,
but WITHOUT WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE

=cut

# Local Variables:
# mode: perl
# tab-width: 3
# End:
# vim: expandtab shiftwidth=3:

__DATA__
#include <stdio.h>

#define EXECUTABLE_NAME "[% executable_name %]"
#define PROGRAM_NAME    "[% program_name %]"

static int  nlibs   = [% nlibs %];
static char *libs[] = { [% libs %] };

main( ac, av ) char **av; {
   int offset = 1 + 2 * nlibs; char *args[ ac + offset ]; int i;

   args[ 0 ] = "suidperl";

   for (i = 0; i < nlibs; i++) {
      args[ 2 * i + 1 ] = "-I"; args[ 2 * i + 2 ] = libs[ i ];
   }

   args[ offset ] = PROGRAM_NAME;

   for (i = 1; i < ac; i++) args[ offset + i ] = av[ i ];

   args[ offset + ac ] = (char *) NULL;
   execv( EXECUTABLE_NAME, args );
}

<div>
    <a href="https://travis-ci.org/pjfl/p5-unix-setuidwrapper"><img src="https://travis-ci.org/pjfl/p5-unix-setuidwrapper.svg?branch=master" alt="Travis CI Badge"></a>
    <a href="http://badge.fury.io/pl/Unix-SetuidWrapper"><img src="https://badge.fury.io/pl/Unix-SetuidWrapper.svg" alt="CPAN Badge"></a>
    <a href="http://cpants.cpanauthors.org/dist/Unix-SetuidWrapper"><img src="http://cpants.cpanauthors.org/dist/Unix-SetuidWrapper.png" alt="Kwalitee Badge"></a>
</div>

# Name

Unix::SetuidWrapper - Creates a setuid root wrapper for a Perl program

# Synopsis

    package Admin;

    use namespace::autoclean;

    our $VERSION = '0.1';

    use English qw( -no_match_vars );
    use Moo;

    extends q(Class::Usul::Programs);
    with    q(Unix::SetuidWrapper);

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

# Description

Creates a setuid root wrapper for a Perl program.  See the example file
from which the synopsis was taken

Run once as root with

    perl examples/admin -c init-suid-wrapper

This creates the setuid root wrapper as a dotfile in the examples directory.
Thereafter run as a normal user

    perl examples/admin -c test-cmd
    perl examples/admin -c not-allowed

If the normal user executing the commands is in the `users` group then the
first command will succeed, the second command should generate the
permission denied response

# Configuration and Environment

Defines the following attributes;

- `authorised_user`

    The name of the authorised user. This attribute is `NULL` until the
    authorisation check is complete

- `config_file_extn`

    The extension applied to files in ["secure\_dir"](#secure_dir). Defaults to `.sub`

- `public_methods`

    These methods are allowed to be executed by anyone with execute permission on
    the original script

- `secure_dir`

    The directory containing the files used to restrict access to methods. Each
    file is named after a Unix group. If the method the user wants to run is in
    one of the files and the user is in that group then the method execution
    is allowed, otherwise permission is denied

# Subroutines/Methods

## init\_suid\_wrapper

This method needs to be run a the super-user. It writes out the C source code
of the wrapper, compiles it, and sets it to run `setuid` root. It also
restricts permission on ["secure\_dir"](#secure_dir) and it's contents so that only root
can access them

## is\_euid\_zero

Returns true if the effective user id is zero, false otherwise

## wrapped\_cmdline

Returns the command line used to invoke the script with the script name
replaced with that of the `setuid` wrapper. The arguments on the command line
are untainted

# Diagnostics

None

# Dependencies

- [Class::Usul](https://metacpan.org/pod/Class::Usul)
- [File::DataClass](https://metacpan.org/pod/File::DataClass)
- [File::UnixAuth](https://metacpan.org/pod/File::UnixAuth)
- [Moo](https://metacpan.org/pod/Moo)

# Incompatibilities

There are no known incompatibilities in this module

# Bugs and Limitations

There are no known bugs in this module. Please report problems to
http://rt.cpan.org/NoAuth/Bugs.html?Dist=Unix-SetuidWrapper.
Patches are welcome

# Acknowledgements

Larry Wall - For the Perl programming language

# Author

Peter Flanigan, `<pjfl@cpan.org>`

# License and Copyright

Copyright (c) 2015 Peter Flanigan. All rights reserved

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself. See [perlartistic](https://metacpan.org/pod/perlartistic)

This program is distributed in the hope that it will be useful,
but WITHOUT WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE

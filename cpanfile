requires "Class::Usul" => "v0.60.0";
requires "File::DataClass" => "v0.60.0";
requires "File::UnixAuth" => "v0.22.0";
requires "Moo" => "2.000001";
requires "namespace::autoclean" => "0.22";
requires "perl" => "5.010001";

on 'build' => sub {
  requires "Module::Build" => "0.4004";
  requires "Test::Requires" => "0.06";
  requires "version" => "0.88";
};

on 'configure' => sub {
  requires "Module::Build" => "0.4004";
  requires "version" => "0.88";
};

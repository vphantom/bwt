use Test::More tests => 1;
use Pod::Checker;
my $errors = podchecker('lib/BWT.pm');
is($errors, 0, "POD syntax is valid");

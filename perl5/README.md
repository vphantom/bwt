# Perl 5 BWT

Perl 5 implementation of Binary Web Tokens.

As of this version, the only dependencies are:

* `Digest::SHA`
* `JSON` (testing only)

## Installation

This package is not published on CPAN.  The simplest approach is vendoring: copy the single file `lib/BWT.pm` into your project.

## Cryptographically Secure Key Generation

You might want to use `Crypt::Random::Seed`:

```perl
my $today = Crypt::Random::Seed->new()->random_bytes(64);
```

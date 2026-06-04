# Perl 5 BWT

Perl 5 implementation of Binary Web Tokens.

As of this version, the only dependencies are:

* `Digest::SHA`
* `JSON` (testing only)

## TODO

- [ ] Create `lib/BWT.pm`
- [ ] Create `t/01_safehex.t`
- [ ] Create `t/02_vectors.t` using `../test-vectors.json`

## Cryptographically Secure Key Generation

You might want to use `Crypt::Random::Seed`:

```perl
my $today = Crypt::Random::Seed->new()->random_bytes(64);
```

package BWT;

use 5.020;
use strict;
use warnings;

use Carp qw(croak);
use Digest::SHA qw(hmac_sha224);

our $VERSION = '1.00';
our $errstr  = '';

BEGIN {
	require Config;
	die "BWT requires a 64-bit platform\n"
		unless $Config::Config{uvsize} >= 8;
}

my $EPOCH_OFFSET     = 1_750_750_750;
my $SAFEHEX_ALPHABET = 'GHJKLMNPQRSTVWXZ';
my %NIBBLE_OF;
@NIBBLE_OF{ split //, $SAFEHEX_ALPHABET } = 0 .. 15;

sub _err {
	$errstr = $_[0];
	return;
}

# Constant-time string equality.
# The early return on length is safe because we only compare HMAC outputs whose
# expected length is pre-validated.
sub _ct_eq {
	my ($a, $b) = @_;
	my $la = length $a;
	return 0 if $la != length $b;
	my $diff = 0;
	for my $i (0 .. $la - 1) {
		$diff |= vec($a, $i, 8) ^ vec($b, $i, 8);
	}
	return ($diff == 0) ? 1 : 0;
}

sub _sign {
	my ($key, $data) = @_;
	return hmac_sha224($data, $key);
}

sub _validate_key {
	my ($key, $context) = @_;
	croak "$context: missing key" unless defined $key;
	my $kl = length $key;
	croak "$context: key length not in 64..128: $kl"
		unless $kl >= 64 && $kl <= 128;
}

sub _validate_sig {
	my ($sig_len, $yesterday, $today, $to_sign, $sig_raw) = @_;
	my $check = sub {
		my ($key) = @_;
		my $hmac = _sign($key, $to_sign);
		$hmac = substr($hmac, 0, $sig_len) if $sig_len < 28;
		return _ct_eq($hmac, $sig_raw);
	};
	return 1 if $check->($today);
	return 1 if defined $yesterday && $check->($yesterday);
	return _err('BWT::validate_sig: bad signature');
}

sub _split_token {
	my ($str) = @_;
	my @parts = split /9/, $str, -1;
	return _err('BWT::split_token: malformed token') unless @parts == 2;
	return @parts;
}

sub safehex_of_int {
	my ($n) = @_;
	croak 'BWT::safehex_of_int: negative input' if $n < 0;
	return 'G' if $n == 0;
	my $result = '';
	my $shift = 60;
	$shift -= 4 while $shift > 0 && (($n >> $shift) & 0xF) == 0;
	while ($shift >= 0) {
		$result .= substr($SAFEHEX_ALPHABET, ($n >> $shift) & 0xF, 1);
		$shift -= 4;
	}
	return $result;
}

sub safehex_to_int {
	my ($s) = @_;
	my $len = length $s;
	return _err('BWT::safehex: bad safe-hex')
		if $len == 0 || ($len > 1 && substr($s, 0, 1) eq 'G');
	return _err('BWT::safehex: integer overflow') if $len > 16;
	my $acc = 0;
	for my $i (0 .. $len - 1) {
		my $nibble = $NIBBLE_OF{substr($s, $i, 1)};
		return _err('BWT::safehex: bad safe-hex') unless defined $nibble;
		$acc = ($acc << 4) | $nibble;
	}
	return $acc;
}

sub safehex_of_string {
	my ($s) = @_;
	my $result = '';
	for my $i (0 .. length($s) - 1) {
		my $byte = vec($s, $i, 8);
		$result .= substr($SAFEHEX_ALPHABET, $byte >> 4, 1)
			. substr($SAFEHEX_ALPHABET, $byte & 0xF, 1);
	}
	return $result;
}

sub safehex_to_string {
	my ($s) = @_;
	my $len = length $s;
	return _err('BWT::safehex: malformed token') if $len & 1;
	my $result = '';
	for my $j (0 .. ($len / 2) - 1) {
		my $hi = $NIBBLE_OF{substr($s, $j * 2, 1)};
		my $lo = $NIBBLE_OF{substr($s, $j * 2 + 1, 1)};
		return _err('BWT::safehex: bad safe-hex')
			unless defined $hi && defined $lo;
		$result .= chr(($hi << 4) | $lo);
	}
	return $result;
}

package BWT::Session;

use strict;
use warnings;
use Carp qw(croak);

sub issued_at { $_[0]->{issued_at} }
sub expires   { $_[0]->{expires}   }
sub user_id   { $_[0]->{user_id}   }
sub admin_id  { $_[0]->{admin_id}  }

sub encode {
	my (%args) = @_;
	my $key     = $args{key}     // croak 'BWT::Session::encode: missing key';
	my $user_id = $args{user_id} // croak 'BWT::Session::encode: missing user_id';
	my $expires = $args{expires} // croak 'BWT::Session::encode: missing expires';
	my $salt     = $args{salt}     // '';
	my $admin_id = $args{admin_id};

	BWT::_validate_key($key, 'BWT::Session::encode');
	croak 'BWT::Session::encode: negative user_id' if $user_id < 0;
	croak 'BWT::Session::encode: negative admin_id'
		if defined $admin_id && $admin_id < 0;
	return BWT::_err('BWT::Session: bad expires')
		unless $expires >= 1 && $expires <= 1440;

	my $now = $args{now} // int(time);
	my $issued_off = $now - $EPOCH_OFFSET;
	return BWT::_err('BWT::Session: now before epoch') if $issued_off < 0;

	my $payload = BWT::safehex_of_int($issued_off) . '5'
				. BWT::safehex_of_int($expires)    . '5'
				. BWT::safehex_of_int($user_id);
	$payload .= '5' . BWT::safehex_of_int($admin_id) if defined $admin_id;

	my $hmac = BWT::_sign($key, $salt . ':' . $payload);

	return $payload . '9' . BWT::safehex_of_string($hmac);
}

sub decode {
	my (%args) = @_;
	my $today = $args{today} // croak 'BWT::Session::decode: missing today';
	my $token = $args{token} // croak 'BWT::Session::decode: missing token';
	my $salt  = $args{salt}  // '';
	my $yesterday = $args{yesterday};

	BWT::_validate_key($today, 'BWT::Session::decode');
	BWT::_validate_key($yesterday, 'BWT::Session::decode')
		if defined $yesterday;

	return BWT::_err('BWT::Session: token too long')
		unless length($token) <= 124;

	my ($payload, $sig_hex) = BWT::_split_token($token);
	return unless defined $payload;

	my $sig_raw = BWT::safehex_to_string($sig_hex);
	return unless defined $sig_raw;

	return BWT::_err('BWT::Session: bad signature length')
		unless length($sig_raw) == 28;

	my $to_sign = $salt . ':' . $payload;
	return unless BWT::_validate_sig(
		28, $yesterday, $today, $to_sign, $sig_raw
	);

	my @fields = split /5/, $payload, -1;
	return BWT::_err('BWT::Session: malformed payload')
		unless @fields == 3 || @fields == 4;

	my $issued_off = BWT::safehex_to_int($fields[0]);
	return unless defined $issued_off;
	my $expires = BWT::safehex_to_int($fields[1]);
	return unless defined $expires;
	my $user_id = BWT::safehex_to_int($fields[2]);
	return unless defined $user_id;

	my $admin_id;
	if (@fields == 4) {
		$admin_id = BWT::safehex_to_int($fields[3]);
		return unless defined $admin_id;
	}

	return BWT::_err('BWT::Session: bad expires')
		unless $expires >= 1 && $expires <= 1440;

	return bless {
		issued_at => $issued_off + $EPOCH_OFFSET,
		expires   => $expires,
		user_id   => $user_id,
		admin_id  => $admin_id,
	}, 'BWT::Session';
}

sub validate {
	my (%args) = @_;
	my $token = $args{token} // croak 'BWT::Session::validate: missing token';
	croak 'BWT::Session::validate: not a BWT::Session token'
		unless ref $token && $token->isa('BWT::Session');
	my $logout_at = $args{logout_at}
		// croak 'BWT::Session::validate: missing logout_at';
	my $admin_logout_at = $args{admin_logout_at};

	my $now = $args{now} // int(time);

	return BWT::_err('BWT::Session: future token')
		unless $token->{issued_at} <= $now + 5;

	return BWT::_err('BWT::Session: expired')
		unless $now < $token->{issued_at} + ($token->{expires} * 60);

	if (defined $token->{admin_id}) {
		return BWT::_err('BWT::Session: missing admin_logout_at')
			unless defined $admin_logout_at;
		return BWT::_err('BWT::Session: admin logged out')
			unless $token->{issued_at} > $admin_logout_at;
	}
	else {
		return BWT::_err('BWT::Session: logged out')
			unless $token->{issued_at} > $logout_at;
	}

	# Fresh if less than 20% of expiration has elapsed
	return ($now < $token->{issued_at} + ($token->{expires} * 12)) ? 1 : 0;
}

package BWT::Link;

use strict;
use warnings;
use Carp qw(croak);

sub issued_at { $_[0]->{issued_at} }
sub expires   { $_[0]->{expires}   }
sub user_id   { $_[0]->{user_id}   }

sub encode {
	my (%args) = @_;
	my $key     = $args{key}     // croak 'BWT::Link::encode: missing key';
	my $user_id = $args{user_id} // croak 'BWT::Link::encode: missing user_id';
	my $expires = $args{expires} // croak 'BWT::Link::encode: missing expires';
	my $action  = $args{action}  // croak 'BWT::Link::encode: missing action';
	BWT::_validate_key($key, 'BWT::Link::encode');
	croak 'BWT::Link::encode: empty action'    unless length $action;
	croak 'BWT::Link::encode: negative user_id' if $user_id < 0;
	return BWT::_err('BWT::Link: bad expires')
		unless $expires >= 1 && $expires <= 1440;

	my $now = $args{now} // int(time);
	my $issued_off = $now - $EPOCH_OFFSET;
	return BWT::_err('BWT::Link: timestamp before epoch') if $issued_off < 0;

	my $payload = BWT::safehex_of_int($issued_off) . '5'
				. BWT::safehex_of_int($expires)    . '5'
				. BWT::safehex_of_int($user_id);
	my $hmac    = BWT::_sign($key, $action . '=' . $payload);
	my $sig_raw = substr($hmac, 0, 16);

	return $payload . '9' . BWT::safehex_of_string($sig_raw);
}

sub decode {
	my (%args) = @_;
	my $today  = $args{today}  // croak 'BWT::Link::decode: missing today';
	my $token  = $args{token}  // croak 'BWT::Link::decode: missing token';
	my $action = $args{action} // croak 'BWT::Link::decode: missing action';
	my $yesterday = $args{yesterday};

	BWT::_validate_key($today, 'BWT::Link::decode');
	BWT::_validate_key($yesterday, 'BWT::Link::decode')
		if defined $yesterday;

	return BWT::_err('BWT::Link: token too long') unless length($token) <= 83;

	my ($payload, $sig_hex) = BWT::_split_token($token);
	return unless defined $payload;

	my $sig_raw = BWT::safehex_to_string($sig_hex);
	return unless defined $sig_raw;

	return BWT::_err('BWT::Link: bad signature length')
		unless length($sig_raw) == 16;

	my $to_sign = $action . '=' . $payload;
	return unless BWT::_validate_sig(
		16, $yesterday, $today, $to_sign, $sig_raw
	);

	my @fields = split /5/, $payload, -1;
	return BWT::_err('BWT::Link: malformed payload') unless @fields == 3;

	my $issued_off = BWT::safehex_to_int($fields[0]);
	return unless defined $issued_off;
	my $expires = BWT::safehex_to_int($fields[1]);
	return unless defined $expires;
	my $user_id = BWT::safehex_to_int($fields[2]);
	return unless defined $user_id;

	return BWT::_err('BWT::Link: bad expires')
		unless $expires >= 1 && $expires <= 1440;

	return bless {
		issued_at => $issued_off + $EPOCH_OFFSET,
		expires   => $expires,
		user_id   => $user_id,
	}, 'BWT::Link';
}

sub validate {
	my (%args) = @_;
	my $token = $args{token} // croak 'BWT::Link::validate: missing token';
	croak 'BWT::Link::validate: not a BWT::Link token'
		unless ref $token && $token->isa('BWT::Link');
	my $last_nonce_at = $args{last_nonce_at}
		// croak 'BWT::Link::validate: missing last_nonce_at';

	my $now = $args{now} // int(time);

	return BWT::_err('BWT::Link: future token')
		unless $token->{issued_at} <= $now + 5;

	return BWT::_err('BWT::Link: no longer valid')
		unless $token->{issued_at} > $last_nonce_at;

	return BWT::_err('BWT::Link: expired')
		unless $now < $token->{issued_at} + ($token->{expires} * 60);

	return 1;
}

package BWT::CSRF;

use strict;
use warnings;
use Carp qw(croak);

sub encode {
	my (%args) = @_;
	my $key     = $args{key}     // croak 'BWT::CSRF::encode: missing key';
	my $user_id = $args{user_id} // croak 'BWT::CSRF::encode: missing user_id';
	my $form_id = $args{form_id} // croak 'BWT::CSRF::encode: missing form_id';
	BWT::_validate_key($key, 'BWT::CSRF::encode');
	croak 'BWT::CSRF::encode: empty form_id'    unless length $form_id;
	croak 'BWT::CSRF::encode: negative user_id' if $user_id < 0;

	my $rand;
	if (defined $args{rand}) {
		$rand = $args{rand};
		croak 'BWT::CSRF::encode: rand out of range'
			unless $rand >= 0 && $rand <= 0xFFFFFFFF;
	}
	else {
		$rand = int(rand(0xFFFFFFFF));
	}

	my $payload = BWT::safehex_of_int($rand);
	my $salt    = $form_id . ':' . BWT::safehex_of_int($user_id);
	my $hmac    = BWT::_sign($key, $salt . '~' . $payload);
	my $sig_raw = substr($hmac, 0, 12);

	return $payload . '9' . BWT::safehex_of_string($sig_raw);
}

sub validate {
	my (%args) = @_;
	my $today   = $args{today}   // croak 'BWT::CSRF::validate: missing today';
	my $token   = $args{token}   // croak 'BWT::CSRF::validate: missing token';
	my $form_id = $args{form_id} // croak 'BWT::CSRF::validate: missing form_id';
	my $user_id = $args{user_id} // croak 'BWT::CSRF::validate: missing user_id';
	my $yesterday = $args{yesterday};

	BWT::_validate_key($today, 'BWT::CSRF::validate');
	BWT::_validate_key($yesterday, 'BWT::CSRF::validate')
		if defined $yesterday;

	return BWT::_err('BWT::CSRF: token too long') unless length($token) <= 41;

	my ($payload, $sig_hex) = BWT::_split_token($token);
	return unless defined $payload;

	my $sig_raw = BWT::safehex_to_string($sig_hex);
	return unless defined $sig_raw;

	return BWT::_err('BWT::CSRF: bad signature length')
		unless length($sig_raw) == 12;

	return BWT::_err('BWT::CSRF: malformed payload')
		if index($payload, '5') >= 0;

	my $rand_val = BWT::safehex_to_int($payload);
	return unless defined $rand_val;

	my $salt = $form_id . ':' . BWT::safehex_of_int($user_id);
	return BWT::_validate_sig(
		12, $yesterday, $today, $salt . '~' . $payload, $sig_raw
	);
}

=encoding utf8

=head1 NAME

BWT - Binary Web Tokens

=head1 SYNOPSIS

	use BWT;

	# Safe-hex encoding
	my $hex = BWT::safehex_of_int(42);        # "JS"
	my $val = BWT::safehex_to_int("JS")       # 42
		// die $BWT::errstr;

	# Session tokens
	my $token = BWT::Session::encode(
		key     => $key,
		user_id => 12345,
		expires => 60,
	) // die $BWT::errstr;

	my $session = BWT::Session::decode(
		today => $key_today,
		token => $token,
	) // die $BWT::errstr;

	my $fresh = BWT::Session::validate(
		token     => $session,
		logout_at => $user_logout_at,
	);
	if (defined $fresh) {
		# $fresh: 1 = fresh, 0 = stale (re-issue cookie)
	}

	# Link tokens (one-time URLs)
	my $link = BWT::Link::encode(
		key     => $key,
		action  => 'password-reset',
		user_id => 12345,
		expires => 30,
	) // die $BWT::errstr;

	# CSRF tokens
	my $csrf = BWT::CSRF::encode(
		key     => $key,
		user_id => 12345,
		form_id => 'settings',
	) // die $BWT::errstr;

=head1 DESCRIPTION

Perl 5 implementation of Binary Web Tokens.  Inspired by the basic principles of
JSON Web Tokens, but with an explicit requirement for server-side information in
order to guarantee timely logouts, all in a format compact enough to use in
e-mail verification links and cookies.

BWT defines three token forms:

=over 4

=item B<Session> — HTTP session cookies (224-bit signature)

=item B<Link> — One-time action URLs such as password resets (128-bit signature)

=item B<CSRF> — Cross-site request forgery guards (96-bit signature)

=back

=head2 Error Handling

B<Developer errors> (invalid key length, negative IDs, empty action strings,
etc.) raise exceptions via C<croak>.  These indicate programming mistakes that
should never occur in production.

B<Decode and validation failures> (bad signatures, expired tokens, malformed
input, etc.) return C<undef> and set C<$BWT::errstr> to a descriptive error
string.  Callers should check with C<defined>:

	my $result = BWT::Session::decode(...)
		// do { warn $BWT::errstr; return };

B<Session validation> returns a three-valued scalar: C<1> (valid and fresh),
C<0> (valid but stale — the application should re-issue the cookie), or C<undef>
(invalid, with reason in C<$BWT::errstr>).

=head2 Key Management

Keys must be between 64 and 128 bytes in length, generated from a
cryptographically secure random source.  Servers maintain two keys (I<today> and
I<yesterday>), rotating daily.  Both keys are accepted during signature
verification.

See L<Crypt::Random::Seed> for a recommended way to generate keys.

=head2 Safe-Hex Functions

BWT uses an alternative hexadecimal alphabet (C<GHJKLMNPQRSTVWXZ>) that avoids
vowels and vowel-lookalikes, preventing false positives from profanity filters
in e-mailed URLs.

=over 4

=item B<BWT::safehex_of_int>(I<$n>)

Returns the safe-hex string representation of non-negative integer I<$n>.
Croaks on negative input.  The full unsigned 64-bit range is supported.

	BWT::safehex_of_int(0)   # "G"
	BWT::safehex_of_int(42)  # "JS"

=item B<BWT::safehex_to_int>(I<$s>)

Returns the integer value of the safe-hex string I<$s>, or C<undef> on error
(with C<$BWT::errstr> set).  Leading C<G> characters are rejected except for the
single-character string C<"G"> representing zero.

	my $n = BWT::safehex_to_int("JS") // die $BWT::errstr;  # 42

=item B<BWT::safehex_of_string>(I<$s>)

Returns the safe-hex encoding of the binary string I<$s>.  Each byte produces
exactly two safe-hex characters.

	BWT::safehex_of_string("\x00\xFF")  # "GGZZ"

=item B<BWT::safehex_to_string>(I<$s>)

Returns the binary string decoded from the safe-hex string I<$s>, or C<undef> on
error (with C<$BWT::errstr> set).  The input must have even length.

	my $bin = BWT::safehex_to_string("GGZZ") // die $BWT::errstr;  # "\x00\xFF"

=back

=head2 BWT::Session

Session tokens for HTTP cookies.  They carry the full 224-bit HMAC-SHA-224
signature and support optional admin impersonation.

Decoded Session tokens are blessed objects with the following accessors:

=over 4

=item C<issued_at> — Seconds since UNIX Epoch when the token was issued

=item C<expires> — Validity duration in minutes (1–1440)

=item C<user_id> — User identifier

=item C<admin_id> — Admin identifier if impersonating, or C<undef>

=back

=over 4

=item B<BWT::Session::encode>(I<%args>)

Creates a new Session token.  Returns the token string, or C<undef> on failure
(with C<$BWT::errstr> set).  Croaks on invalid arguments.

Required arguments:

=over 4

=item C<key> — HMAC key (64–128 bytes)

=item C<user_id> — Non-negative integer identifying the user

=item C<expires> — Validity in minutes (1–1440)

=back

Optional arguments:

=over 4

=item C<salt> — Context string (defaults to C<"">)

=item C<admin_id> — Non-negative integer identifying an impersonating admin

=item C<now> — Current UNIX timestamp (defaults to C<time()>)

=back

	my $token = BWT::Session::encode(
		key     => $key,
		user_id => $uid,
		expires => 60,
		salt    => 'session',
	) // die $BWT::errstr;

=item B<BWT::Session::decode>(I<%args>)

Decodes and verifies the signature of a Session token.  Returns a blessed
C<BWT::Session> object, or C<undef> on failure (with C<$BWT::errstr> set).
Croaks on invalid keys or missing arguments.

The returned object proves the token was not tampered with, but is meaningless
until validated with C<validate>.

Required arguments:

=over 4

=item C<today> — Current day's HMAC key (64–128 bytes)

=item C<token> — The Session token string to decode

=back

Optional arguments:

=over 4

=item C<salt> — Context string matching the one used in C<encode> (defaults to C<"">)

=item C<yesterday> — Previous day's HMAC key (64–128 bytes)

=back

	my $session = BWT::Session::decode(
		today => $key_today,
		token => $cookie_value,
		salt  => 'session',
	) // do { warn $BWT::errstr; return };

=item B<BWT::Session::validate>(I<%args>)

Validates a decoded Session token.  Returns C<1> if the token is valid and
fresh, C<0> if valid but stale (the application should re-issue the cookie), or
C<undef> on failure (with C<$BWT::errstr> set).  Croaks on missing arguments or
if C<token> is not a C<BWT::Session> object.

A token is considered stale when at least 20% of its expiration time has elapsed
since C<issued_at>.

Required arguments:

=over 4

=item C<token> — A C<BWT::Session> object from C<decode>

=item C<logout_at> — The user's logout timestamp

=back

Optional arguments:

=over 4

=item C<admin_logout_at> — The user's admin impersonation logout timestamp
(required if the token has an C<admin_id>)

=item C<now> — Current UNIX timestamp (defaults to C<time()>)

=back

	my $fresh = BWT::Session::validate(
		token     => $session,
		logout_at => $user_logout_at,
	);
	if (defined $fresh) {
		# valid: $fresh is 1 (fresh) or 0 (stale, re-issue)
	}
	else {
		warn "Session invalid: $BWT::errstr";
	}

=back

=head2 BWT::Link

Link tokens for one-time action URLs such as password resets, e-mail
verification and magic login links.  They carry a 128-bit truncated HMAC-SHA-224
signature, salted with an action string that binds the token to a specific
purpose.

Decoded Link tokens are blessed objects with the following accessors:

=over 4

=item C<issued_at> — Seconds since UNIX Epoch when the token was issued

=item C<expires> — Validity duration in minutes (1–1440)

=item C<user_id> — User identifier

=back

=over 4

=item B<BWT::Link::encode>(I<%args>)

Creates a new Link token.  Returns the token string, or C<undef> on failure
(with C<$BWT::errstr> set).  Croaks on invalid arguments.

Required arguments:

=over 4

=item C<key> — HMAC key (64–128 bytes)

=item C<action> — Non-empty string identifying the purpose (e.g. C<"password-reset">)

=item C<user_id> — Non-negative integer identifying the user

=item C<expires> — Validity in minutes (1–1440)

=back

Optional arguments:

=over 4

=item C<now> — Current UNIX timestamp (defaults to C<time()>)

=back

	my $link = BWT::Link::encode(
		key     => $key,
		action  => 'password-reset',
		user_id => $uid,
		expires => 30,
	) // die $BWT::errstr;

=item B<BWT::Link::decode>(I<%args>)

Decodes and verifies the signature of a Link token.  Returns a blessed
C<BWT::Link> object, or C<undef> on failure (with C<$BWT::errstr> set).  Croaks
on invalid keys or missing arguments.

The returned object proves the token was not tampered with, but is meaningless
until validated with C<validate>.

Required arguments:

=over 4

=item C<today> — Current day's HMAC key (64–128 bytes)

=item C<token> — The Link token string to decode

=item C<action> — The action string that was used when encoding

=back

Optional arguments:

=over 4

=item C<yesterday> — Previous day's HMAC key (64–128 bytes)

=back

	my $link = BWT::Link::decode(
		today  => $key_today,
		token  => $token_str,
		action => 'password-reset',
	) // do { warn $BWT::errstr; return };
	my $uid = $link->user_id;

=item B<BWT::Link::validate>(I<%args>)

Validates a decoded Link token.  Returns C<1> on success, C<undef> on failure
(with C<$BWT::errstr> set).  Croaks on missing arguments or if C<token> is not a
C<BWT::Link> object.

Required arguments:

=over 4

=item C<token> — A C<BWT::Link> object from C<decode>

=item C<last_nonce_at> — The user's last nonce consumption timestamp

=back

Optional arguments:

=over 4

=item C<now> — Current UNIX timestamp (defaults to C<time()>)

=back

	my $ok = BWT::Link::validate(
		token         => $link,
		last_nonce_at => $user_last_nonce_at,
	) // do { warn $BWT::errstr; return };

=back

=head2 BWT::CSRF

CSRF tokens for cross-site request forgery protection.  They carry a 96-bit
truncated HMAC-SHA-224 signature over a random 32-bit payload, salted with a
form identifier and user ID.  CSRF tokens have no explicit expiration; they are
implicitly bounded by key rotation (at most ~48 hours).

=over 4

=item B<BWT::CSRF::encode>(I<%args>)

Creates a new CSRF token.  Returns the token string.  Croaks on invalid
arguments.

Required arguments:

=over 4

=item C<key> — HMAC key (64–128 bytes)

=item C<user_id> — Non-negative integer identifying the user

=item C<form_id> — Non-empty string identifying the form or action

=back

Optional arguments:

=over 4

=item C<rand> — Explicit 32-bit unsigned integer payload (for testing)

=back

	my $csrf = BWT::CSRF::encode(
		key     => $key,
		user_id => $uid,
		form_id => 'settings',
	);

=item B<BWT::CSRF::validate>(I<%args>)

Validates a CSRF token.  Returns C<1> on success, C<undef> on failure (with
C<$BWT::errstr> set).  Croaks on invalid keys or missing arguments.

Required arguments:

=over 4

=item C<today> — Current day's HMAC key (64–128 bytes)

=item C<token> — The CSRF token string to validate

=item C<form_id> — The form identifier that was used when encoding

=item C<user_id> — The user ID that was used when encoding

=back

Optional arguments:

=over 4

=item C<yesterday> — Previous day's HMAC key (64–128 bytes)

=back

	my $ok = BWT::CSRF::validate(
		today   => $key_today,
		token   => $csrf_token,
		form_id => 'settings',
		user_id => $uid,
	) // warn $BWT::errstr;

=back

=head1 SEE ALSO

The full BWT specification and test vectors are available at
L<https://github.com/vphantom/bwt>.

=head1 AUTHOR

Stéphane Lavergne L<https://github.com/vphantom>

=head1 LICENSE

Copyright (c) 2025-2026 Stéphane Lavergne.

Distributed under the MIT (X11) License.
See L<https://opensource.org/license/mit>.

=cut

1;

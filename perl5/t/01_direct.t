use strict;
use warnings;
use Test::More;
use Digest::SHA qw(hmac_sha224);
use BWT;

my $key_today     = 'T' x 64;
my $key_yesterday = 'Y' x 64;
my $key_short     = 'X' x 63;
my $key_long      = 'X' x 129;
my $bwt_epoch     = 1_750_750_750;
my $fixed_now     = $bwt_epoch + 10_000_000;

# Forge a Session token by signing payload with key and salt, producing a token
# with a valid signature over an arbitrary payload.
sub forge_session {
	my (%args) = @_;
	my $key     = $args{key};
	my $salt    = $args{salt} // '';
	my $payload = $args{payload};
	my $raw_sig  = hmac_sha224($salt . ':' . $payload, $key);
	my $full_sig = BWT::safehex_of_string($raw_sig);
	return $payload . '9' . substr($full_sig, 0, 56);
}

# Safe-Hex integers

subtest 'safehex_of_int' => sub {
	is(BWT::safehex_of_int(0),   'G',   'zero');
	is(BWT::safehex_of_int(1),   'H',   'n=1');
	is(BWT::safehex_of_int(15),  'Z',   'n=15');
	is(BWT::safehex_of_int(16),  'HG',  'n=16');
	is(BWT::safehex_of_int(255), 'ZZ',  'n=255');
	is(BWT::safehex_of_int(256), 'HGG', 'n=256');

	eval { BWT::safehex_of_int(-1) };
	like($@, qr/negative/, 'negative croaks');
};

subtest 'safehex_to_int' => sub {
	is(BWT::safehex_to_int('G'),   0,   'G => 0');
	is(BWT::safehex_to_int('H'),   1,   'H => 1');
	is(BWT::safehex_to_int('Z'),   15,  'Z => 15');
	is(BWT::safehex_to_int('HG'),  16,  'HG => 16');
	is(BWT::safehex_to_int('ZZ'),  255, 'ZZ => 255');
	is(BWT::safehex_to_int('HGG'), 256, 'HGG => 256');

	# Invalid inputs
	is(BWT::safehex_to_int(''),   undef, 'empty');
	is(BWT::safehex_to_int('g'),  undef, 'lowercase');
	is(BWT::safehex_to_int('0'),  undef, 'digit');
	is(BWT::safehex_to_int('A'),  undef, 'hex letter');
	is(BWT::safehex_to_int('GA'), undef, 'mixed valid/invalid');
	is(BWT::safehex_to_int('GG'), undef, 'leading zero');

	# Overflow: 17 chars exceeds 64-bit range
	is(BWT::safehex_to_int('H' . ('G' x 16)), undef, '17 chars overflow');
	like($BWT::errstr, qr/integer overflow/, 'overflow error message');
};

subtest 'safehex int round-trip' => sub {
	for my $n (0, 1, 15, 16, 255, 256, 1_000, 1_000_000,
			   2**32 - 1, 2**32, 2**48) {
		is(BWT::safehex_to_int(BWT::safehex_of_int($n)), $n,
			"round-trip $n");
	}
};

# Safe-Hex strings

subtest 'safehex_of_string' => sub {
	is(BWT::safehex_of_string(''),         '',     'empty');
	is(BWT::safehex_of_string("\x00"),      'GG',   '\\x00');
	is(BWT::safehex_of_string("\xff"),      'ZZ',   '\\xff');
	is(BWT::safehex_of_string("\x00\xff"),  'GGZZ', '\\x00\\xff');
	is(BWT::safehex_of_string("\x1a"),      'HS',   '\\x1a');
};

subtest 'safehex_to_string' => sub {
	is(BWT::safehex_to_string(''),     '',          'empty');
	is(BWT::safehex_to_string('GG'),   "\x00",      'GG');
	is(BWT::safehex_to_string('ZZ'),   "\xff",      'ZZ');
	is(BWT::safehex_to_string('GGZZ'), "\x00\xff",  'GGZZ');

	# Odd lengths
	is(BWT::safehex_to_string('H'),   undef, 'odd length 1');
	is(BWT::safehex_to_string('HHH'), undef, 'odd length 3');

	# Invalid characters
	is(BWT::safehex_to_string('Ha'), undef, 'lowercase');
	is(BWT::safehex_to_string('0G'), undef, 'digit');
	is(BWT::safehex_to_string('AG'), undef, 'hex letter');
};

subtest 'safehex string round-trip' => sub {
	for my $s ('', "\x00", "\xff", "\x00\xff\x42\xab") {
		is(BWT::safehex_to_string(BWT::safehex_of_string($s)), $s,
			'round-trip ' . unpack('H*', $s));
	}
};

# Constant-time comparison

subtest '_ct_eq' => sub {
	is(BWT::_ct_eq('abc', 'abc'), 1, 'equal strings');
	is(BWT::_ct_eq('abc', 'abd'), 0, 'differ in last byte');
	is(BWT::_ct_eq('abc', 'xbc'), 0, 'differ in first byte');
	is(BWT::_ct_eq('abc', 'ab'),  0, 'different lengths');
	is(BWT::_ct_eq('',    ''),    1, 'both empty');
	is(BWT::_ct_eq('',    'a'),   0, 'empty vs non-empty');
	is(BWT::_ct_eq("\x00\x00", "\x00\x00"), 1, 'null bytes equal');
	is(BWT::_ct_eq("\x00\x00", "\x00\x01"), 0, 'null bytes differ');
};

subtest 'CSRF' => sub {

	subtest 'encode implicit rand' => sub {
		my $token = BWT::CSRF::encode(
			key => $key_today, user_id => 1, form_id => 'login',
		);
		ok(defined $token, 'encode succeeds');
		my $ok = BWT::CSRF::validate(
			today => $key_today, token => $token,
			form_id => 'login', user_id => 1,
		);
		is($ok, 1, 'validates');
	};

	subtest 'token structure' => sub {
		my $token = BWT::CSRF::encode(
			key => $key_today, rand => 42,
			user_id => 1, form_id => 'login',
		);
		ok(length($token) <= 41, 'length <= 41');
		my $sep = index($token, '9');
		ok($sep >= 0, 'has separator');
		is(length($token) - $sep - 1, 24, 'sig is 24 chars');
	};

	subtest 'max token length' => sub {
		my $token = BWT::CSRF::encode(
			key => $key_today, rand => 4_294_967_295,
			user_id => 1, form_id => 'test',
		);
		ok(length($token) <= 41, 'max rand fits in 41 chars');
	};

	subtest 'encode developer errors' => sub {
		eval { BWT::CSRF::encode(user_id => 1, form_id => 'x') };
		like($@, qr/missing key/, 'missing key');

		eval { BWT::CSRF::encode(key => $key_today, form_id => 'x') };
		like($@, qr/missing user_id/, 'missing user_id');

		eval { BWT::CSRF::encode(key => $key_today, user_id => 1) };
		like($@, qr/missing form_id/, 'missing form_id');

		eval { BWT::CSRF::encode(
			key => $key_today, user_id => 1, form_id => '',
		) };
		like($@, qr/empty form_id/, 'empty form_id');

		eval { BWT::CSRF::encode(
			key => $key_today, user_id => -1, form_id => 'x',
		) };
		like($@, qr/negative user_id/, 'negative user_id');

		eval { BWT::CSRF::encode(
			key => $key_today, user_id => 1, form_id => 'x', rand => -1,
		) };
		like($@, qr/rand out of range/, 'rand negative');

		eval { BWT::CSRF::encode(
			key => $key_today, user_id => 1, form_id => 'x',
			rand => 4_294_967_296,
		) };
		like($@, qr/rand out of range/, 'rand > uint32');

		eval { BWT::CSRF::encode(
			key => $key_short, user_id => 1, form_id => 'x', rand => 42,
		) };
		like($@, qr/key length/, 'key too short');

		eval { BWT::CSRF::encode(
			key => $key_long, user_id => 1, form_id => 'x', rand => 42,
		) };
		like($@, qr/key length/, 'key too long');
	};

	subtest 'validate developer errors' => sub {
		my $tok = BWT::CSRF::encode(
			key => $key_today, rand => 42, user_id => 1, form_id => 'login',
		);

		eval { BWT::CSRF::validate(
			token => $tok, form_id => 'login', user_id => 1,
		) };
		like($@, qr/missing today/, 'missing today');

		eval { BWT::CSRF::validate(
			today => $key_today, form_id => 'login', user_id => 1,
		) };
		like($@, qr/missing token/, 'missing token');

		eval { BWT::CSRF::validate(
			today => $key_today, token => $tok, user_id => 1,
		) };
		like($@, qr/missing form_id/, 'missing form_id');

		eval { BWT::CSRF::validate(
			today => $key_today, token => $tok, form_id => 'login',
		) };
		like($@, qr/missing user_id/, 'missing user_id');

		eval { BWT::CSRF::validate(
			today => $key_short, token => $tok,
			form_id => 'login', user_id => 1,
		) };
		like($@, qr/key length/, 'today key too short');

		eval { BWT::CSRF::validate(
			today => $key_long, token => $tok,
			form_id => 'login', user_id => 1,
		) };
		like($@, qr/key length/, 'today key too long');

		eval { BWT::CSRF::validate(
			today => $key_today, yesterday => $key_short,
			token => $tok, form_id => 'login', user_id => 1,
		) };
		like($@, qr/key length/, 'yesterday key too short');
	};

	subtest 'malformed signatures' => sub {
		# 23-char sig (odd → safehex_to_string fails)
		is(BWT::CSRF::validate(
			today => $key_today, form_id => 'login', user_id => 1,
			token => 'JS9' . ('H' x 23),
		), undef, 'sig too short');

		# 25-char sig (odd → safehex_to_string fails)
		is(BWT::CSRF::validate(
			today => $key_today, form_id => 'login', user_id => 1,
			token => 'JS9' . ('H' x 25),
		), undef, 'sig too long');
	};

	subtest 'payload with delimiter rejected' => sub {
		is(BWT::CSRF::validate(
			today => $key_today, form_id => 'login', user_id => 1,
			token => 'H5H9' . ('H' x 24),
		), undef, 'payload with 5 rejected');
	};

};

subtest 'Link' => sub {

	subtest 'encode implicit now round-trip' => sub {
		my $token = BWT::Link::encode(
			key => $key_today, action => 'login',
			user_id => 1, expires => 60,
		);
		ok(defined $token, 'encode succeeds');
		my $link = BWT::Link::decode(
			today => $key_today, action => 'login', token => $token,
		);
		ok(defined $link, 'decode succeeds');
		my $ok = BWT::Link::validate(
			token => $link, last_nonce_at => 0,
		);
		is($ok, 1, 'validates');
	};

	subtest 'token structure' => sub {
		my $token = BWT::Link::encode(
			key => $key_today, now => $fixed_now, action => 'login',
			user_id => 1, expires => 60,
		);
		ok(length($token) <= 83, 'length <= 83');
		my $sep = index($token, '9');
		ok($sep >= 0, 'has separator');
		is(length($token) - $sep - 1, 32, 'sig is 32 chars');
	};

	subtest 'yesterday key accepted' => sub {
		my $token = BWT::Link::encode(
			key => $key_yesterday, now => $fixed_now,
			action => 'login', user_id => 1, expires => 60,
		);
		my $link = BWT::Link::decode(
			today => $key_today, yesterday => $key_yesterday,
			action => 'login', token => $token,
		);
		ok(defined $link, 'decoded with yesterday key');
	};

	subtest 'encode soft errors' => sub {
		is(BWT::Link::encode(
			key => $key_today, now => $fixed_now, action => 'login',
			user_id => 1, expires => 0,
		), undef, 'expires=0');

		is(BWT::Link::encode(
			key => $key_today, now => $fixed_now, action => 'login',
			user_id => 1, expires => 1441,
		), undef, 'expires=1441');

		is(BWT::Link::encode(
			key => $key_today, now => $bwt_epoch - 1, action => 'login',
			user_id => 1, expires => 60,
		), undef, 'now before epoch');
	};

	subtest 'encode developer errors' => sub {
		eval { BWT::Link::encode(
			action => 'login', user_id => 1, expires => 60,
		) };
		like($@, qr/missing key/, 'missing key');

		eval { BWT::Link::encode(
			key => $key_today, action => 'login', expires => 60,
		) };
		like($@, qr/missing user_id/, 'missing user_id');

		eval { BWT::Link::encode(
			key => $key_today, action => 'login', user_id => 1,
		) };
		like($@, qr/missing expires/, 'missing expires');

		eval { BWT::Link::encode(
			key => $key_today, user_id => 1, expires => 60,
		) };
		like($@, qr/missing action/, 'missing action');

		eval { BWT::Link::encode(
			key => $key_today, action => '', user_id => 1, expires => 60,
		) };
		like($@, qr/empty action/, 'empty action');

		eval { BWT::Link::encode(
			key => $key_today, action => 'login', user_id => -1, expires => 60,
		) };
		like($@, qr/negative user_id/, 'negative user_id');

		eval { BWT::Link::encode(
			key => $key_short, action => 'login', user_id => 1, expires => 60,
		) };
		like($@, qr/key length/, 'key too short');

		eval { BWT::Link::encode(
			key => $key_long, action => 'login', user_id => 1, expires => 60,
		) };
		like($@, qr/key length/, 'key too long');
	};

	subtest 'decode developer errors' => sub {
		my $tok = BWT::Link::encode(
			key => $key_today, now => $fixed_now, action => 'login',
			user_id => 1, expires => 60,
		);

		eval { BWT::Link::decode(action => 'login', token => $tok) };
		like($@, qr/missing today/, 'missing today');

		eval { BWT::Link::decode(today => $key_today, action => 'login') };
		like($@, qr/missing token/, 'missing token');

		eval { BWT::Link::decode(today => $key_today, token => $tok) };
		like($@, qr/missing action/, 'missing action');

		eval { BWT::Link::decode(
			today => $key_short, action => 'login', token => $tok,
		) };
		like($@, qr/key length/, 'today key too short');

		eval { BWT::Link::decode(
			today => $key_long, action => 'login', token => $tok,
		) };
		like($@, qr/key length/, 'today key too long');

		eval { BWT::Link::decode(
			today => $key_today, yesterday => $key_short,
			action => 'login', token => $tok,
		) };
		like($@, qr/key length/, 'yesterday key too short');
	};

	subtest 'validate developer errors' => sub {
		my $tok = BWT::Link::encode(
			key => $key_today, now => $fixed_now, action => 'login',
			user_id => 1, expires => 60,
		);
		my $link = BWT::Link::decode(
			today => $key_today, action => 'login', token => $tok,
		);

		eval { BWT::Link::validate(last_nonce_at => 0) };
		like($@, qr/missing token/, 'missing token');

		eval { BWT::Link::validate(token => 'not_blessed', last_nonce_at => 0) };
		like($@, qr/not a BWT::Link/, 'not a BWT::Link');

		eval { BWT::Link::validate(token => $link) };
		like($@, qr/missing last_nonce_at/, 'missing last_nonce_at');
	};

};

subtest 'Session' => sub {

	subtest 'encode implicit now round-trip' => sub {
		my $token = BWT::Session::encode(
			key => $key_today, user_id => 1, expires => 60,
		);
		ok(defined $token, 'encode succeeds');
		my $session = BWT::Session::decode(
			today => $key_today, token => $token,
		);
		ok(defined $session, 'decode succeeds');
		my $fresh = BWT::Session::validate(
			token => $session, logout_at => 0,
		);
		ok(defined $fresh, 'validates');
	};

	subtest 'token structure' => sub {
		my $token = BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, expires => 60,
		);
		ok(length($token) <= 124, 'length <= 124');
		my $sep = index($token, '9');
		ok($sep >= 0, 'has separator');
		is(length($token) - $sep - 1, 56, 'sig is 56 chars');
	};

	subtest 'token structure with admin' => sub {
		my $token = BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, admin_id => 99, expires => 60,
		);
		ok(length($token) <= 124, 'length <= 124 (with admin)');
		my $sep = index($token, '9');
		ok($sep >= 0, 'has separator');
		is(length($token) - $sep - 1, 56, 'sig is 56 chars');
	};

	subtest 'yesterday key accepted' => sub {
		my $token = BWT::Session::encode(
			key => $key_yesterday, now => $fixed_now,
			user_id => 1, expires => 60,
		);
		my $session = BWT::Session::decode(
			today => $key_today, yesterday => $key_yesterday,
			token => $token,
		);
		ok(defined $session, 'decoded with yesterday key');
	};

	subtest 'accessors' => sub {
		my $token = BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 42, admin_id => 99, expires => 30,
		);
		my $session = BWT::Session::decode(
			today => $key_today, token => $token,
		);
		is($session->issued_at, $fixed_now, 'issued_at');
		is($session->expires,   30,         'expires');
		is($session->user_id,   42,         'user_id');
		is($session->admin_id,  99,         'admin_id');
	};

	subtest 'admin_id undef when absent' => sub {
		my $token = BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, expires => 60,
		);
		my $session = BWT::Session::decode(
			today => $key_today, token => $token,
		);
		is($session->admin_id, undef, 'admin_id is undef');
	};

	subtest 'encode soft errors' => sub {
		is(BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, expires => 0,
		), undef, 'expires=0');

		is(BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, expires => 1441,
		), undef, 'expires=1441');

		is(BWT::Session::encode(
			key => $key_today, now => $bwt_epoch - 1,
			user_id => 1, expires => 60,
		), undef, 'now before epoch');
	};

	subtest 'encode developer errors' => sub {
		eval { BWT::Session::encode(user_id => 1, expires => 60) };
		like($@, qr/missing key/, 'missing key');

		eval { BWT::Session::encode(key => $key_today, expires => 60) };
		like($@, qr/missing user_id/, 'missing user_id');

		eval { BWT::Session::encode(key => $key_today, user_id => 1) };
		like($@, qr/missing expires/, 'missing expires');

		eval { BWT::Session::encode(
			key => $key_today, user_id => -1, expires => 60,
		) };
		like($@, qr/negative user_id/, 'negative user_id');

		eval { BWT::Session::encode(
			key => $key_today, user_id => 1, admin_id => -1, expires => 60,
		) };
		like($@, qr/negative admin_id/, 'negative admin_id');

		eval { BWT::Session::encode(
			key => $key_short, user_id => 1, expires => 60,
		) };
		like($@, qr/key length/, 'key too short');

		eval { BWT::Session::encode(
			key => $key_long, user_id => 1, expires => 60,
		) };
		like($@, qr/key length/, 'key too long');
	};

	subtest 'encode expires=-1' => sub {
		is(BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, expires => -1,
		), undef, 'expires=-1');
		like($BWT::errstr, qr/bad expires/, 'error message');
	};

	subtest 'decode developer errors' => sub {
		my $tok = BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, expires => 60,
		);

		eval { BWT::Session::decode(token => $tok) };
		like($@, qr/missing today/, 'missing today');

		eval { BWT::Session::decode(today => $key_today) };
		like($@, qr/missing token/, 'missing token');

		eval { BWT::Session::decode(today => $key_short, token => $tok) };
		like($@, qr/key length/, 'today key too short');

		eval { BWT::Session::decode(today => $key_long, token => $tok) };
		like($@, qr/key length/, 'today key too long');

		eval { BWT::Session::decode(
			today => $key_today, yesterday => $key_short, token => $tok,
		) };
		like($@, qr/key length/, 'yesterday key too short');
	};

	subtest 'validate developer errors' => sub {
		my $tok = BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, expires => 60,
		);
		my $session = BWT::Session::decode(
			today => $key_today, token => $tok,
		);

		eval { BWT::Session::validate(logout_at => 0) };
		like($@, qr/missing token/, 'missing token');

		eval { BWT::Session::validate(
			token => 'not_blessed', logout_at => 0,
		) };
		like($@, qr/not a BWT::Session/, 'not a BWT::Session');

		eval { BWT::Session::validate(token => $session) };
		like($@, qr/missing logout_at/, 'missing logout_at');
	};

	subtest 'validate: admin without admin_logout_at' => sub {
		my $tok = BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, admin_id => 99, expires => 60,
		);
		my $session = BWT::Session::decode(
			today => $key_today, token => $tok,
		);
		my $result = BWT::Session::validate(
			token => $session, now => $fixed_now, logout_at => 0,
		);
		is($result, undef, 'undef without admin_logout_at');
		like($BWT::errstr, qr/missing admin_logout_at/, 'error message');
	};

	subtest 'validate: stale token' => sub {
		my $tok = BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, expires => 60,
		);
		my $session = BWT::Session::decode(
			today => $key_today, token => $tok,
		);
		# 20% of 60 minutes = 12 minutes = 720 seconds
		# At issued_at + 720, the token becomes stale
		my $result = BWT::Session::validate(
			token     => $session,
			now       => $fixed_now + 720,
			logout_at => 0,
		);
		ok(defined $result, 'still valid');
		is($result, 0, 'stale (0)');
	};

	subtest 'validate: fresh token' => sub {
		my $tok = BWT::Session::encode(
			key => $key_today, now => $fixed_now,
			user_id => 1, expires => 60,
		);
		my $session = BWT::Session::decode(
			today => $key_today, token => $tok,
		);
		my $result = BWT::Session::validate(
			token     => $session,
			now       => $fixed_now,
			logout_at => 0,
		);
		is($result, 1, 'fresh (1)');
	};

	# --- Forged payload tests ---

	subtest 'issued_at overflow' => sub {
		# 17-char safe-hex exceeds 64-bit, triggers overflow in safehex_to_int
		my $payload = 'H' . ('G' x 16) . '5H5H';
		my $tok = forge_session(key => $key_today, payload => $payload);
		my $session = BWT::Session::decode(
			today => $key_today, token => $tok,
		);
		ok(!defined $session, 'oversized issued_at rejects');
		like($BWT::errstr, qr/integer overflow/, 'overflow error');
	};

	subtest 'token length exactly 124' => sub {
		# sig=56 + separator=1 → payload must be 67 for total 124
		my $payload = 'H5H5H5' . ('H' x 61);
		my $tok = forge_session(key => $key_today, payload => $payload);
		is(length($tok), 124, 'token is 124 chars');
		my $session = BWT::Session::decode(
			today => $key_today, token => $tok,
		);
		ok(!defined $session, 'decode fails');
		unlike($BWT::errstr, qr/token too long/,
			'not rejected for length');
	};

	subtest 'token length 125 rejected' => sub {
		my $payload = 'H5H5H5' . ('H' x 62);
		my $tok = forge_session(key => $key_today, payload => $payload);
		is(length($tok), 125, 'token is 125 chars');
		my $session = BWT::Session::decode(
			today => $key_today, token => $tok,
		);
		ok(!defined $session, 'decode fails');
		like($BWT::errstr, qr/token too long/, 'rejected for length');
	};

};

done_testing;

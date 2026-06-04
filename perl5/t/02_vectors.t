use strict;
use warnings;
use Test::More;
use JSON ();
use FindBin;
use BWT;

my $vectors_path;
for my $candidate (
	"$FindBin::Bin/../test-vectors.json",
	"$FindBin::Bin/../../test-vectors.json",
) {
	if (-f $candidate) {
		$vectors_path = $candidate;
		last;
	}
}
BAIL_OUT('Cannot find test-vectors.json') unless defined $vectors_path;

my $vectors = do {
	open my $fh, '<', $vectors_path
		or BAIL_OUT("Cannot open $vectors_path: $!");
	local $/;
	JSON::decode_json(<$fh>);
};

sub vector_key {
	my ($name) = @_;
	return pack('H*', $vectors->{keys}{$name});
}

sub optional_yesterday {
	my ($obj) = @_;
	return defined $obj->{yesterday}
		? (yesterday => vector_key($obj->{yesterday}))
		: ();
}

subtest 'Metadata' => sub {
	is($vectors->{spec_version}, '1.0rc5', 'spec_version');
	is($vectors->{generated_by}, 'ocaml/bwt_vectors.ml', 'generated_by');
	is($vectors->{bwt_epoch}, 1_750_750_750, 'bwt_epoch');
	is($vectors->{fixed_now}, 1_760_750_750, 'fixed_now');

	ok(exists $vectors->{keys}{today}, 'today key exists');
	ok(exists $vectors->{keys}{yesterday}, 'yesterday key exists');
	is(length($vectors->{keys}{today}), 128, 'today key hex length');
	is(length($vectors->{keys}{yesterday}), 128, 'yesterday key hex length');
	isnt($vectors->{keys}{today}, $vectors->{keys}{yesterday}, 'keys differ');

	for my $section (qw(session link csrf)) {
		ok(@{ $vectors->{$section}{positive} } > 0,
			"$section positive non-empty");
		ok(@{ $vectors->{$section}{negative} } > 0,
			"$section negative non-empty");
	}
};

subtest 'Session/positive' => sub {
	for my $v (@{ $vectors->{session}{positive} }) {
		subtest $v->{name} => sub {
			my $enc = $v->{encode};
			my $dec = $v->{decode};
			my $val = $v->{validate};

			my $token = BWT::Session::encode(
				key     => vector_key($enc->{key}),
				salt    => $enc->{salt},
				now     => $enc->{now},
				user_id => $enc->{user_id},
				(defined $enc->{admin_id}
					? (admin_id => $enc->{admin_id}) : ()),
				expires => $enc->{expires},
			);
			is($token, $v->{expected_token}, 'encode');

			my $session = BWT::Session::decode(
				today => vector_key($dec->{today}),
				optional_yesterday($dec),
				salt  => $dec->{salt},
				token => $v->{expected_token},
			);
			ok(defined $session, 'decode succeeds')
				or diag("decode error: $BWT::errstr"), return;
			is($session->issued_at, $enc->{now}, 'issued_at');
			is($session->expires, $enc->{expires}, 'expires');
			is($session->user_id, $enc->{user_id}, 'user_id');
			is($session->admin_id, $enc->{admin_id}, 'admin_id');

			my $result = BWT::Session::validate(
				token     => $session,
				now       => $val->{now},
				logout_at => $val->{logout_at},
				(defined $val->{admin_logout_at}
					? (admin_logout_at => $val->{admin_logout_at}) : ()),
			);
			if ($val->{expected} eq 'fresh') {
				is($result, 1, 'validate: fresh');
			}
			elsif ($val->{expected} eq 'stale') {
				ok(defined $result && $result eq '0',
					'validate: stale');
			}
			else {
				fail("unknown expected: $val->{expected}");
			}
		};
	}
};

subtest 'Session/negative' => sub {
	for my $v (@{ $vectors->{session}{negative} }) {
		subtest $v->{name} => sub {
			my $dec     = $v->{decode};
			my $fail_at = $v->{should_fail_at};

			if ($fail_at eq 'decode') {
				my $session = BWT::Session::decode(
					today => vector_key($dec->{today}),
					optional_yesterday($dec),
					salt  => $dec->{salt},
					token => $v->{token},
				);
				ok(!defined $session, 'decode fails');
			}
			elsif ($fail_at eq 'validate') {
				my $session = BWT::Session::decode(
					today => vector_key($dec->{today}),
					optional_yesterday($dec),
					salt  => $dec->{salt},
					token => $v->{token},
				);
				ok(defined $session, 'decode succeeds')
					or diag("decode error: $BWT::errstr"), return;

				my $val = $v->{validate};
				my $result = BWT::Session::validate(
					token     => $session,
					now       => $val->{now},
					logout_at => $val->{logout_at},
					(defined $val->{admin_logout_at}
						? (admin_logout_at => $val->{admin_logout_at})
						: ()),
				);
				ok(!defined $result, 'validate fails');
			}
			else {
				fail("unknown should_fail_at: $fail_at");
			}
		};
	}
};

subtest 'Link/positive' => sub {
	for my $v (@{ $vectors->{link}{positive} }) {
		subtest $v->{name} => sub {
			my $enc = $v->{encode};
			my $dec = $v->{decode};
			my $val = $v->{validate};

			my $token = BWT::Link::encode(
				key     => vector_key($enc->{key}),
				action  => $enc->{action},
				now     => $enc->{now},
				user_id => $enc->{user_id},
				expires => $enc->{expires},
			);
			is($token, $v->{expected_token}, 'encode');

			my $link = BWT::Link::decode(
				today  => vector_key($dec->{today}),
				optional_yesterday($dec),
				action => $dec->{action},
				token  => $v->{expected_token},
			);
			ok(defined $link, 'decode succeeds')
				or diag("decode error: $BWT::errstr"), return;
			is($link->issued_at, $enc->{now}, 'issued_at');
			is($link->expires, $enc->{expires}, 'expires');
			is($link->user_id, $enc->{user_id}, 'user_id');

			my $result = BWT::Link::validate(
				token         => $link,
				now           => $val->{now},
				last_nonce_at => $val->{last_nonce_at},
			);
			is($result, 1, 'validate: valid');
		};
	}
};

subtest 'Link/negative' => sub {
	for my $v (@{ $vectors->{link}{negative} }) {
		subtest $v->{name} => sub {
			my $dec     = $v->{decode};
			my $fail_at = $v->{should_fail_at};

			if ($fail_at eq 'decode') {
				my $link = BWT::Link::decode(
					today  => vector_key($dec->{today}),
					optional_yesterday($dec),
					action => $dec->{action},
					token  => $v->{token},
				);
				ok(!defined $link, 'decode fails');
			}
			elsif ($fail_at eq 'validate') {
				my $link = BWT::Link::decode(
					today  => vector_key($dec->{today}),
					optional_yesterday($dec),
					action => $dec->{action},
					token  => $v->{token},
				);
				ok(defined $link, 'decode succeeds')
					or diag("decode error: $BWT::errstr"), return;

				my $val = $v->{validate};
				my $result = BWT::Link::validate(
					token         => $link,
					now           => $val->{now},
					last_nonce_at => $val->{last_nonce_at},
				);
				ok(!defined $result, 'validate fails');
			}
			else {
				fail("unknown should_fail_at: $fail_at");
			}
		};
	}
};

subtest 'CSRF/positive' => sub {
	for my $v (@{ $vectors->{csrf}{positive} }) {
		subtest $v->{name} => sub {
			my $enc = $v->{encode};
			my $val = $v->{validate};

			my $token = BWT::CSRF::encode(
				key     => vector_key($enc->{key}),
				rand    => $enc->{rand},
				user_id => $enc->{user_id},
				form_id => $enc->{form_id},
			);
			is($token, $v->{expected_token}, 'encode');

			my $result = BWT::CSRF::validate(
				today   => vector_key($val->{today}),
				optional_yesterday($val),
				form_id => $val->{form_id},
				user_id => $val->{user_id},
				token   => $v->{expected_token},
			);
			is($result, 1, 'validate: valid');
		};
	}
};

subtest 'CSRF/negative' => sub {
	for my $v (@{ $vectors->{csrf}{negative} }) {
		subtest $v->{name} => sub {
			my $val = $v->{validate};

			my $result = BWT::CSRF::validate(
				today   => vector_key($val->{today}),
				optional_yesterday($val),
				form_id => $val->{form_id},
				user_id => $val->{user_id},
				token   => $v->{token},
			);
			ok(!defined $result, 'validate fails');
		};
	}
};

done_testing;

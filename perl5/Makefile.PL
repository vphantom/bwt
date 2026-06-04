use 5.020;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
	NAME             => 'BWT',
	VERSION_FROM     => 'lib/BWT.pm',
	ABSTRACT         => 'Binary Web Tokens',
	AUTHOR           => 'Stéphane Lavergne <https://github.com/vphantom>',
	LICENSE          => 'mit',
	MIN_PERL_VERSION => '5.020',
	PREREQ_PM        => {
		'Digest::SHA' => '5.95',
	},
	TEST_REQUIRES    => {
		'JSON'       => '2.90',
		'Test::More' => '0.96',
		'Test::Pod'  => '1.00',
	},
	META_MERGE => {
		'meta-spec' => { version => 2 },
		resources   => {
			repository => {
				type => 'git',
				url  => 'https://github.com/vphantom/bwt.git',
				web  => 'https://github.com/vphantom/bwt',
			},
		},
	},
);

#!/usr/bin/perl

use warnings;
use strict;

use File::Temp qw(tempdir);

use APNIC::RPKI::Publication::OpenSSL;
use APNIC::RPKI::Publication::CA;

use Test::More tests => 13;

{
    eval { APNIC::RPKI::Publication::CA->new() };
    ok($@, 'Unable to instantiate CA without CA path');
    like($@, qr/ca_path.*argument must be provided/,
        'Got correct error message');

    my $ca_dir = tempdir(CLEANUP => 1);
    my $ca = APNIC::RPKI::Publication::CA->new(ca_path => $ca_dir);
    ok($ca, 'Got new CA');

    rmdir $ca_dir or die $!;
    eval { $ca->_chdir_ca() };
    ok($@, 'Unable to change to CA directory');
    mkdir $ca_dir;

    eval { $ca->_chdir_ca() };
    ok((not $@), 'Able to change to CA directory');

    my $res = $ca->initialise('test');
    ok($res, 'Initialised CA successfully');

    eval { $ca->initialise('test') };
    ok($@, 'Unable to initialise CA twice');
    like($@, qr/CA has already been initialised/,
        'Got correct error message');

    $res = $ca->issue_new_ee_certificate();
    ok($res, 'Issued new EE certificate');

    $res = $ca->issue_crl();
    ok($res, 'Issued new CRL');

    $res = $ca->cycle();
    ok($res, 'Cycled CA');

    my $openssl = $ca->{'openssl'};
    my $cms = $ca->sign_cms('asdf');
    my $cert = '-----BEGIN X509 CERTIFICATE-----'."\n".
               $ca->get_ca_pem()."\n".
               '-----END X509 CERTIFICATE-----';
    $res = eval { $openssl->verify_cms($cms, $cert) };
    ok((not $@), 'Verified CMS successfully');
    diag $@ if $@;
    is($res, 'asdf', 'Decoded CMS successfully');
}

1;

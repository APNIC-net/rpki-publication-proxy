#!/usr/bin/perl

use warnings;
use strict;

use File::Temp qw(tempdir);

use APNIC::RPKI::Publication::OpenSSL;
use APNIC::RPKI::Publication::CA;

use Test::More tests => 2;

{
    my $openssl =
        APNIC::RPKI::Publication::OpenSSL->new(
            debug => 1,
            path  => '/usr/local/ssl/bin/openssl'
        );

    my $ca1_dir = tempdir(CLEANUP => 1);
    my $ca1 =
        APNIC::RPKI::Publication::CA->new(
            openssl => $openssl,
            ca_path => $ca1_dir
        );
    $ca1->initialise('test');
    $ca1->cycle();

    my $ca2_dir = tempdir(CLEANUP => 1);
    my $ca2 =
        APNIC::RPKI::Publication::CA->new(
            openssl => $openssl,
            ca_path => $ca2_dir
        );
    $ca2->initialise('test2', 1);

    my $req = $ca2->get_ca_request('test2');
    my $ca_cert = $ca1->sign_ca_request($req);
    $ca2->install_ca_certificate($ca_cert);
    $ca2->cycle();

    my $cms = $ca2->sign_cms('asdf');
    my $cert = '-----BEGIN X509 CERTIFICATE-----'."\n".
               $ca2->get_ca_pem()."\n".
               '-----END X509 CERTIFICATE-----';
    my $res = eval { $openssl->verify_cms($cms, $cert) };
    ok((not $@), 'Verified CMS successfully');
    diag $@ if $@;
    is($res, 'asdf', 'Decoded CMS successfully');
}

1;

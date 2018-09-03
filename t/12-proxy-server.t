#!/usr/bin/perl

use warnings;
use strict;

use File::Temp qw(tempdir);
use IO::Capture::Stderr;
use HTTP::Status qw(:constants);

use APNIC::RPKI::Publication::Proxy::Server;

use Test::More tests => 27;

my $server;

# Server setup.
{
    my $db_dir = tempdir(CLEANUP => 1);
    mkdir $db_dir.'/ca' or die $!;

    my %default_args = (
        port     => 0,
        hostname => 'test',
        handle   => 'qwer',
        db_path  => $db_dir
    );

    $server =
        APNIC::RPKI::Publication::Proxy::Server->new(%default_args);
    ok($server, 'Created new proxy server');

    $server->_save();

    $server =
        APNIC::RPKI::Publication::Proxy::Server->new(%default_args);
    ok($server, 'Created new proxy server after save');
}

# Logging.
{
    my $c = IO::Capture::Stderr->new();
    $c->start();
    $server->_log('test');
    $c->stop();
    my @lines = $c->read();
    is(@lines, 1, 'Got one line of standard error after logging');
    like($lines[0], qr/^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] test$/,
        'Log has correct format');
}

# Initialisation and basic operations.
{
    my $res = $server->_bpki_cycle_post();
    is($res->code(), HTTP_INTERNAL_SERVER_ERROR,
        'Cannot cycle BPKI when BPKI not initialised');

    $res = $server->_publisher_get();
    is($res->code(), HTTP_INTERNAL_SERVER_ERROR,
        'Cannot get publisher XML when BPKI not initialised');

    $res = $server->_client_post();
    is($res->code(), HTTP_INTERNAL_SERVER_ERROR,
        'Cannot register clients when BPKI not initialised');

    $res = $server->_bpki_init_post();
    is($res->code(), HTTP_OK,
        'BPKI initialised successfully');

    $res = $server->_bpki_init_post();
    is($res->code(), HTTP_INTERNAL_SERVER_ERROR,
        'BPKI cannot be initialised twice');

    $res = $server->_bpki_cycle_post();
    is($res->code(), HTTP_OK,
        'Cycling is successful after initialisation');

    $res = $server->_publisher_get();
    is($res->code(), HTTP_OK,
        'Getting publisher XML is successful after initialisation');
}

# SIA construction/validation.
{
    $server->{'repository_data'}->{'sia_base'} = 'rsync://testhost/base/';
    my $base = $server->_get_sia_base('base');
    is($base, 'rsync://testhost/base/',
        'If handle matches directory name, SIA is unchanged');
    my $customer = $server->_get_sia_base('customer');
    is($customer, 'rsync://testhost/base/customer/',
        'If handle does not match directory name, handle is appended');

    # List requests.

    my $request_xml = <<EOF;
   <msg
       type="query"
       version="4"
       xmlns="http://www.hactrn.net/uris/rpki/publication-spec/">
     <list/>
   </msg>
EOF

    my $error =
        $server->_validate_publication_request("base", undef,
                                               $request_xml);
    ok((not $error), 'Validated list request');

    $error =
        $server->_validate_publication_request("anything", undef,
                                               $request_xml);
    ok((not $error), 'Validated list request (handle is irrelevant)');

    # Publication requests.

    $request_xml = <<EOF;
   <msg
       type="query"
       version="4"
       xmlns="http://www.hactrn.net/uris/rpki/publication-spec/">
     <publish uri="asdf">asdf</publish>
   </msg>
EOF

    my $c = IO::Capture::Stderr->new();
    $c->start();
    $error =
        $server->_validate_publication_request("base", undef,
                                               $request_xml);
    $c->stop();
    ok($error, 'Request failed validation');
    my @lines = $c->read();
    is(@lines, 1, 'One error logged');
    like($lines[0], qr/Client \(base\) attempting publication for unauthorised URL \(asdf\)/,
        'Got correct log message');

    $request_xml = <<EOF;
   <msg
       type="query"
       version="4"
       xmlns="http://www.hactrn.net/uris/rpki/publication-spec/">
     <publish uri="rsync://testhost/base/object">asdf</publish>
   </msg>
EOF

    $error =
        $server->_validate_publication_request("base", undef,
                                               $request_xml);
    ok((not $error), 'Validated publication request');

    $request_xml = <<EOF;
   <msg
       type="query"
       version="4"
       xmlns="http://www.hactrn.net/uris/rpki/publication-spec/">
     <publish uri="rsync://testhost/base/object/subobject">asdf</publish>
   </msg>
EOF

    $c->start();
    $error =
        $server->_validate_publication_request("base", undef,
                                               $request_xml);
    $c->stop();
    ok($error, 'Request failed validation (subdirectories not permitted)');
    @lines = $c->read();
    is(@lines, 1, 'One error logged');
    like($lines[0], qr/Client \(base\) attempting publication for unauthorised URL/,
        'Got correct log message');

    $c->start();
    $error =
        $server->_validate_publication_request("object", undef,
                                               $request_xml);
    $c->stop();
    ok((not $error), 'Validated publication request (non-base)');

    # Response tests.

    my $response_xml = <<EOF;
    <msg type="reply"
         version="4"
         xmlns="http://www.hactrn.net/uris/rpki/publication-spec/">
      <list hash="asdf" uri="rsync://testhost/base/object.cer" />
      <list hash="asdf" uri="rsync://testhost/base/object/object.cer" />
    </msg>
EOF

    my $res = $server->_adjust_publication_response("base", $response_xml);
    like($res, qr!"rsync://testhost/base/object.cer"!,
        'Object belonging to client 1 is returned in client 1 list');
    unlike($res, qr!"rsync://testhost/base/object/object.cer"!,
        'Object belonging to client 2 is not returned in client 1 list');

    $res = $server->_adjust_publication_response("object", $response_xml);
    unlike($res, qr!"rsync://testhost/base/object.cer"!,
        'Object belonging to client 1 is not returned in client 2 list');
    like($res, qr!"rsync://testhost/base/object/object.cer"!,
        'Object belonging to client 2 is returned in client 2 list');

}

chdir '/tmp';

1;

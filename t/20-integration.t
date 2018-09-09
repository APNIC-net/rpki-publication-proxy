#!/usr/bin/perl

use warnings;
use strict;

use Data::Dumper;
use File::Slurp qw(read_file);
use File::Temp qw(tempdir);
use HTTP::Status qw(:constants);
use LWP::UserAgent;

use APNIC::RPKI::Publication::Proxy::Server;
use APNIC::RPKI::Publication::Utils qw(canonicalise_pem);

use lib 't/lib';
use APNIC::RPKI::Publication::Server;

use Test::More tests => 16;

my $DEBUG = 0;
my $shutdown = 1;

my $proxy_pid = fork();
if (not $proxy_pid) {
    $shutdown = 0;
    my $log_path = File::Temp->new();
    my $server =
        APNIC::RPKI::Publication::Proxy::Server->new(
            ($DEBUG ? () : (log_path => $log_path->filename()))
        );
    $server->run();
}

my $publication_pid = fork();
if (not $publication_pid) {
    $shutdown = 0;
    my $log_path = File::Temp->new();
    my $server =
        APNIC::RPKI::Publication::Server->new(
            ($DEBUG ? () : (log_path => $log_path->filename()))
        );
    $server->run();
}

sub exit_test
{
    kill 'TERM', $proxy_pid;
    kill 'TERM', $publication_pid;
    waitpid $proxy_pid, 0;
    waitpid $publication_pid, 0;
}

my $host             = '127.0.0.1';
my $proxy_base       = "http://$host:8080";
my $publication_base = "http://$host:8081";

{
    my $ua = LWP::UserAgent->new();

    my $req = HTTP::Request->new(POST => "$proxy_base/bpki-init");
    my $res = $ua->request($req);
    ok($res->is_success(), 'Created CA successfully');

    $req = HTTP::Request->new(POST => "$proxy_base/bpki-cycle");
    $res = $ua->request($req);
    ok($res->is_success(), 'Created EE certificate successfully');

    $req = HTTP::Request->new(GET => "$proxy_base/publisher");
    $res = $ua->request($req);
    ok($res->is_success(), 'Got publication request');
    my $pub_request = $res->content();

    $req = HTTP::Request->new(POST => "$publication_base/ca");
    $res = $ua->request($req);
    ok($res->is_success(), 'Created publication CA successfully');

    $req = HTTP::Request->new(POST => "$publication_base/ee");
    $res = $ua->request($req);
    ok($res->is_success(), 'Created publication EE certificate successfully');

    $req = HTTP::Request->new(POST => "$publication_base/client",
                              [], $pub_request);
    $res = $ua->request($req);
    ok($res->is_success(), 'Registered with publication server');

    $req = HTTP::Request->new(POST => "$proxy_base/repository",
                              [ 'Content-Type' => 'application/xml' ],
                              $res->content());
    $res = $ua->request($req);
    ok($res->is_success(), 'Processed repository response');

    my $openssl = APNIC::RPKI::Publication::OpenSSL->new();
    my $ca_dir = tempdir(CLEANUP => 1);
    my $ca =
        APNIC::RPKI::Publication::CA->new(
            ca_path => $ca_dir,
            openssl => $openssl,
        );
    $ca->initialise('testing');
    $ca->cycle();

    my $bpki_ta = $ca->get_ca_pem();

    my $client_request = <<EOF;
   <publisher_request
       xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/"
       version="1"
       tag="A0001"
       publisher_handle="Bob">
     <publisher_bpki_ta>
	$bpki_ta
     </publisher_bpki_ta>
   </publisher_request>
EOF

    $req = HTTP::Request->new(POST => "$proxy_base/client",
                              [ 'Content-Type' => 'application/xml' ],
                              $client_request);
    $res = $ua->request($req);
    ok($res->is_success(), 'Processed client request');

    my $content = $res->content();
    $content =~ s/\s//g;
    my ($ta_b64) = ($content =~
        /<repository_bpki_ta>(.*)<\/repository_bpki_ta>/s);
    if (not $ta_b64) {
        die "no ta";
    }
    $ta_b64 = canonicalise_pem($ta_b64);

    my $repo_ta =
        '-----BEGIN X509 CERTIFICATE-----'."\n".
        $ta_b64."\n".
        '-----END X509 CERTIFICATE-----';

    my $xml_list_query = <<EOF;
   <msg
       type="query"
       version="4"
       xmlns="http://www.hactrn.net/uris/rpki/publication-spec/">
     <list/>
   </msg>
EOF

    $req = HTTP::Request->new(POST => "$proxy_base/publication/Bob",
                              [ 'Content-Type' =>
                                    'application/rpki-publication' ],
                              $xml_list_query);
    $res = $ua->request($req);
    is($res->code(), HTTP_BAD_REQUEST,
        'Got "bad request" on invalid query');

    my $cms_list_query = $ca->sign_cms($xml_list_query);
    $req = HTTP::Request->new(POST => "$proxy_base/publication/Bob",
                              [ 'Content-Type' =>
                                    'application/rpki-publication' ],
                              $cms_list_query);
    $res = $ua->request($req);
    ok($res->is_success(), 'Proxied list request successfully');

    my $xml_list_response =
        $openssl->verify_cms($res->content(), $repo_ta);
    is($xml_list_response, '<msg xmlns="http://www.hactrn.net/uris/rpki/publication-spec/" type="reply" version="4"/>',
        'Got empty list response');

    my $xml_publish_query = <<EOF;
   <msg
       type="query"
       version="4"
       xmlns="http://www.hactrn.net/uris/rpki/publication-spec/">
     <publish uri="asdf">asdf</publish>
   </msg>
EOF

    my $cms_publish_query = $ca->sign_cms($xml_publish_query);
    $req = HTTP::Request->new(POST => "$proxy_base/publication/Bob",
                              [ 'Content-Type' =>
                                    'application/rpki-publication' ],
                              $cms_publish_query);
    $res = $ua->request($req);
    ok((not $res->is_success()),
        'Unable to publish object outside of handle directory');

    $xml_publish_query = <<EOF;
   <msg
       type="query"
       version="4"
       xmlns="http://www.hactrn.net/uris/rpki/publication-spec/">
     <publish uri="rsync://$host/rpki-pp/Bob/object.cer">asdf</publish>
   </msg>
EOF

    $cms_publish_query = $ca->sign_cms($xml_publish_query);
    $req = HTTP::Request->new(POST => "$proxy_base/publication/Bob",
                              [ 'Content-Type' =>
                                    'application/rpki-publication' ],
                              $cms_publish_query);
    $res = $ua->request($req);
    ok($res->is_success(), 'Proxied publication request successfully');

    my $xml_publish_response =
        $openssl->verify_cms($res->content(), $repo_ta);
    is($xml_publish_response, '<msg xmlns="http://www.hactrn.net/uris/rpki/publication-spec/" type="reply" version="4"><success/></msg>',
        'Got success response');

    $cms_list_query = $ca->sign_cms($xml_list_query);
    $req = HTTP::Request->new(POST => "$proxy_base/publication/Bob",
                              [ 'Content-Type' =>
                                    'application/rpki-publication' ],
                              $cms_list_query);
    $res = $ua->request($req);
    ok($res->is_success(), 'Proxied list request successfully');

    $xml_list_response =
        $openssl->verify_cms($res->content(), $repo_ta);
    like($xml_list_response, qr!<msg.*<list hash=".*?" uri="rsync://$host/rpki-pp/Bob/object.cer"/></msg>!,
        'Got correct list response');

    kill 'TERM', $proxy_pid;
    kill 'TERM', $publication_pid;
    waitpid $proxy_pid, 0;
    waitpid $publication_pid, 0;

    exit_test();
    $shutdown = 0;
}

END {
    if ($shutdown) {
        exit_test();
    }
    exit 0;
}

1;

package APNIC::RPKI::Publication::Server;

use warnings;
use strict;

use Digest::SHA qw(sha256_hex);
use File::Slurp qw(read_file);
use File::Temp qw(tempdir);
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use MIME::Base64 qw(encode_base64 decode_base64);
use XML::LibXML;

use APNIC::RPKI::Publication::CA;
use APNIC::RPKI::Publication::Utils qw(canonicalise_pem);

our $VERSION = '0.1';

sub new
{
    my $class = shift;

    my %args = @_;
    my $self = \%args;

    if (not defined $self->{"port"}) {
        $self->{"port"} = 8081;
    }

    my $daemon = HTTP::Daemon->new(
        LocalPort => $self->{"port"},
        ReuseAddr => 1,
        ReusePort => 1
    );
    if (not $daemon) {
        die "Unable to start server: $!";
    }
    $self->{"hostname"} = '127.0.0.1';
    $self->{"port"} = $daemon->sockport();
    $self->{"daemon"} = $daemon;

    $self->{'repo_files'} = [];
    $self->{'repository_data'} = {};
    $self->{'clients'} = {};

    $self->{'openssl'} = APNIC::RPKI::Publication::OpenSSL->new();

    bless $self, $class;
    return $self;
}

sub _log
{
    my ($self, $message) = @_;

    my $prefix = '['.POSIX::strftime('%F %T', gmtime(time())).']';
    $message =~ s/\n//g;

    if ($self->{'log_path'}) {
        open my $fh, '>>', $self->{'log_path'} or die $!;
        print $fh "$prefix $message\n";
        close $fh;
    } else {
        print STDERR "$prefix $message\n";
    }

    return 1;
}

sub _get_sia_base
{
    my ($self, $handle) = @_;

    my $sia_base = $self->{'repository_data'}->{'sia_base'};
    $sia_base =~ s/\/$//;
    if ($sia_base =~ /\/$handle$/) {
        $sia_base .= "/";
    } else {
        $sia_base .= "/$handle/";
    }

    return $sia_base;
}

sub _success
{
    my ($self, $code, $data) = @_;

    my $response = HTTP::Response->new();
    $response->code($code);
    if ($data) {
        $response->content($data);
	$response->header("Content-Type" => "application/xml");
    }

    return $response;
}

sub _error
{
    my ($self, $code, $title, $detail, $ct) = @_;

    my $response = HTTP::Response->new();
    $response->code($code);
    if ($title) {
        my $data = "<problem>".
                       "<title>$title</title>".
                       ($detail ? "<detail>$detail</detail>" : "").
                   "</problem>";
        $response->content($data);
    }
    $response->header("Content-Type" => ($ct || "application/problem+xml"));

    return $response;
}

sub _ca_post
{
    my ($self, $c, $r) = @_;

    my $ca_path = tempdir(CLEANUP => 1);
    my $ca = APNIC::RPKI::Publication::CA->new(
        ca_path => $ca_path,
        openssl => $self->{'openssl'},
    );
    $ca->initialise('publication-server');
    $self->{'ca'} = $ca;

    my $bpki_ta = $ca->get_ca_pem();
    my $host = $self->{'hostname'};
    my $port = $self->{'port'};

    $self->{'repository_data'} = {
        service_uri        => "http://$host:$port/publication",
        sia_base           => "rsync://$host",
        rrdp_uri           => "https://$host",
        repository_bpki_ta => $bpki_ta,
    };

    return $self->_success(HTTP_OK);
}

sub _ee_post
{
    my ($self, $c, $r) = @_;

    my $ca = $self->{'ca'};
    $ca->issue_new_ee_certificate();
    $ca->issue_crl();

    return $self->_success(HTTP_OK);
}

sub _client_post
{
    my ($self, $c, $r) = @_;

    my $client_doc =
        XML::LibXML->load_xml(string => $r->content(),
                              { no_blanks => 1 });
    my $node = $client_doc->documentElement();

    my $handle = $node->getAttribute("publisher_handle");
    if ($self->{'clients'}->{$handle}) {
        return $self->_error(HTTP_INTERNAL_SERVER_ERROR,
                             "Client handle already in use.");
    }

    my $publisher_bpki_ta = $node->firstChild()->textContent();
    $publisher_bpki_ta = canonicalise_pem($publisher_bpki_ta);
    $self->{'clients'}->{$handle} = $publisher_bpki_ta;

    my $host     = $self->{'hostname'};
    my $port     = $self->{'port'};
    my $sia_base = $self->_get_sia_base($handle);
    my $rrdp_uri = $self->{'repository_data'}->{'rrdp_uri'};
    my $bpki_ta  = $self->{'ca'}->get_ca_pem();

    my $response = <<EOF;
   <repository_response
       xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/"
       version="1"
       service_uri="http://$host:$port/publication/$handle"
       publisher_handle="$handle"
       sia_base="$sia_base"
       rrdp_notification_uri="$rrdp_uri">
     <repository_bpki_ta>
        $bpki_ta
     </repository_bpki_ta>
   </repository_response>
EOF

    return $self->_success(HTTP_OK, $response);
}

sub _publication_post
{
    my ($self, $c, $r, $handle) = @_;

    my $client_bpki_ta = $self->{'clients'}->{$handle};
    if (not $client_bpki_ta) {
        return $self->_error(HTTP_NOT_FOUND);
    }
    my $client_bpki_ta_cert =
        '-----BEGIN X509 CERTIFICATE-----'."\n".
        $client_bpki_ta."\n".
        '-----END X509 CERTIFICATE-----';

    my $cms_client_request = $r->content();
    $self->_log("Publication protocol request ($handle): ".
                encode_base64($cms_client_request));

    my $openssl = $self->{'openssl'};
    my $xml_client_request =
        $openssl->verify_cms($cms_client_request,
                             $client_bpki_ta_cert);
    if (not $xml_client_request) {
        $self->_log("Unable to verify CMS from client: ".
                    encode_base64($cms_client_request));
        return $self->_error(HTTP_BAD_REQUEST);
    }

    my $doc = XML::LibXML->load_xml(string => $xml_client_request,
                                    { no_blanks => 1 });
    my $node = $doc->documentElement();

    my @child_nodes = $node->childNodes();
    my @responses;
    my $add_success = 0;
    for my $child_node (@child_nodes) {
        if ($child_node->localname() eq 'list') {
            for my $repo_file (@{$self->{'repo_files'}}) {
                my $hash = $repo_file->{'hash'};
                my $uri  = $repo_file->{'uri'};
                push @responses, "<list hash=\"$hash\" uri=\"$uri\" />";
            }
        } elsif ($child_node->localname() eq 'publish') {
            my $uri = $child_node->getAttribute("uri");
            my $content = $child_node->textContent();
            push @{$self->{'repo_files'}},
                 { hash => sha256_hex(decode_base64($content)),
                   uri  => $uri };
            $add_success = 1;
        }
    }

    my $xml_client_response =
        "<msg type=\"reply\" version=\"4\" ".
             "xmlns=\"http://www.hactrn.net/uris/rpki/publication-spec/\">".
            (@responses   ? (join "\n", @responses) : "").
            ($add_success ? "<success />" : "").
        "</msg>";

    my $cms_client_response = $self->{'ca'}->sign_cms($xml_client_response);
    if (not $cms_client_response) {
        die "Unable to generate CMS.";
    }

    return $self->_success(HTTP_OK, $cms_client_response);
}

sub run
{
    my ($self) = @_;

    $SIG{'TERM'} = sub { exit(0); };

    my $daemon = $self->{"daemon"};
    while (my $c = $daemon->accept()) {
        while (my $r = $c->get_request()) {
            my $method = $r->method();
            my $path = $r->uri()->path();
            $self->_log("$method $path");

            my $res;
            eval {
                if ($method eq 'POST') {
                    if ($path eq '/ca') {
                        $res = $self->_ca_post($c, $r);
                    } elsif ($path eq '/ee') {
                        $res = $self->_ee_post($c, $r);
                    } elsif ($path eq '/client') {
                        $res = $self->_client_post($c, $r);
                    } elsif ($path =~ /^\/publication\/(.*)$/) {
                        my $handle = $1;
                        $res = $self->_publication_post($c, $r, $handle);
                    }
                }
            };
            if (my $error = $@) {
                $self->_log("Unable to process request: $error");
                $c->send_response($self->_error(HTTP_INTERNAL_SERVER_ERROR));
            } elsif (not $res) {
                $self->_log("Unable to resolve request");
                $c->send_response($self->_error(HTTP_NOT_FOUND));
            } else {
                $c->send_response($res);
            }
        }
    }
}

1;

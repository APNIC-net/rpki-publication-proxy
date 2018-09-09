package APNIC::RPKI::Publication::Proxy::Server;

use warnings;
use strict;

use Data::Dumper;
use File::Slurp qw(read_file);
use File::Temp qw(tempdir);
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use LWP::UserAgent;
use MIME::Base64;
use POSIX qw();
use Storable;
use XML::LibXML;

use APNIC::RPKI::Publication::CA;
use APNIC::RPKI::Publication::OpenSSL;
use APNIC::RPKI::Publication::Utils qw(canonicalise_pem);
use constant CONTENT_TYPE => 'application/rpki-publication';

our $VERSION = '0.1';

sub new
{
    my $class = shift;

    my %args = @_;
    my $self = \%args;

    if (not defined $self->{'port'}) {
        $self->{'port'} = 8080;
    }
    if (not $self->{'hostname'}) {
        $self->{'hostname'} = "rpki-pp";
    }
    if (not $self->{'handle'}) {
        $self->{'handle'} = "rpki-pp";
    }
    if (not $self->{'db_path'}) {
        my $db_path = tempdir(CLEANUP => 0);
        mkdir $db_path.'/ca' or die $!;
        $self->{'db_path'} = $db_path;
    }
    my $db_path = $self->{'db_path'};

    my $daemon = HTTP::Daemon->new(
        LocalPort => $self->{'port'},
        ReuseAddr => 1,
        ReusePort => 1
    );
    if (not $daemon) {
        die "Unable to start server: $!";
    }
    $self->{'daemon'} = $daemon;

    my $openssl = APNIC::RPKI::Publication::OpenSSL->new();
    $self->{'openssl'} = $openssl;
    my $ca = APNIC::RPKI::Publication::CA->new(
        ca_path => $db_path.'/ca',
        openssl => $openssl,
    );
    $self->{'ca'} = $ca;

    if (-e $db_path.'/data') {
        my $data = retrieve($db_path.'/data');
        $self->{'repository_data'} = $data->{'repository_data'};
        $self->{'clients'}         = $data->{'clients'};
    }

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
    my ($self, $code, $data, $ct) = @_;

    my $response = HTTP::Response->new();
    $response->code($code);
    if ($data) {
        $response->content($data);
    }
    $response->header("Content-Type" => ($ct || CONTENT_TYPE()));

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

sub _bpki_init_post
{
    my ($self) = @_;

    my $ca = $self->{'ca'};
    if ($ca->is_initialised()) {
        return $self->_error(HTTP_INTERNAL_SERVER_ERROR,
                             "BPKI already initialised",
                             "BPKI can only be initialised once.");
    }

    $ca->initialise($self->{'handle'});
    $ca->cycle();

    $self->_save();

    return $self->_success(HTTP_OK);
}

sub _bpki_cycle_post
{
    my ($self) = @_;

    my $ca = $self->{'ca'};
    if (not $ca->is_initialised()) {
        return $self->_error(HTTP_INTERNAL_SERVER_ERROR,
                             "BPKI not initialised",
                             "BPKI must be initialised before cycling.");
    }

    $ca->cycle();

    return $self->_success(HTTP_OK);
}

sub _publisher_get
{
    my ($self) = @_;

    my $ca = $self->{'ca'};
    if (not $ca->is_initialised()) {
        return $self->_error(HTTP_INTERNAL_SERVER_ERROR,
                             "No BPKI initialised",
                             "BPKI must be initialised before ".
                             "retrieving publisher XML.");
    }

    my $bpki_ta = $ca->get_ca_pem();

    my $handle = $self->{'handle'};
    return $self->_success(HTTP_OK, <<EOF);
   <publisher_request
       xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/"
       version="1"
       publisher_handle="$handle">
     <publisher_bpki_ta>
        $bpki_ta
     </publisher_bpki_ta>
   </publisher_request>
EOF
}

sub _repository_post
{
    my ($self, $c, $r) = @_;

    my $repository_doc =
        XML::LibXML->load_xml(string => $r->content(),
                              { no_blanks => 1 });
    my $node = $repository_doc->documentElement();

    my $repository_bpki_ta = $node->firstChild()->textContent();
    if (not $repository_bpki_ta) {
        return $self->_error(HTTP_BAD_REQUEST,
                            'No repository_bpki_ta found.');
    }

    my $service_uri      = $node->getAttribute("service_uri");
    my $publisher_handle = $node->getAttribute("publisher_handle");
    my $sia_base         = $node->getAttribute("sia_base");
    my $rrdp_uri         = $node->getAttribute("rrdp_notification_uri");

    $repository_bpki_ta = canonicalise_pem($repository_bpki_ta);

    $self->{'repository_data'} = {
        service_uri        => $service_uri,
        publisher_handle   => $publisher_handle,
        sia_base           => $sia_base,
        rrdp_uri           => $rrdp_uri,
        repository_bpki_ta => $repository_bpki_ta
    };
    $self->_save();

    return $self->_success(HTTP_OK);
}

sub _client_post
{
    my ($self, $c, $r) = @_;

    my $ca = $self->{'ca'};
    if (not $ca->is_initialised()) {
        return $self->_error(HTTP_INTERNAL_SERVER_ERROR,
                             "No BPKI initialised",
                             "BPKI must be initialised before ".
                             "registering clients.");
    }

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

    my $hostname = $self->{'hostname'};
    my $port     = $self->{'port'};
    my $sia_base = $self->_get_sia_base($handle);
    my $rrdp_uri = $self->{'repository_data'}->{'rrdp_uri'};
    my $bpki_ta  = $ca->get_ca_pem();

    my $response = <<EOF;
   <repository_response
       xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/"
       version="1"
       service_uri="http://$hostname:$port/publication/$handle"
       publisher_handle="$handle"
       sia_base="$sia_base"
       rrdp_notification_uri="$rrdp_uri">
     <repository_bpki_ta>
	$bpki_ta
     </repository_bpki_ta>
   </repository_response>
EOF

    $self->_save();

    return $self->_success(HTTP_OK, $response);
}

sub _validate_publication_request
{
    my ($self, $handle, $ct, $content) = @_; 

    my $publication_doc =
        XML::LibXML->load_xml(string => $content,
                              { no_blanks => 1 });
    my $node = $publication_doc->documentElement();
    my $sia_base = $self->_get_sia_base($handle);

    my @child_nodes = $node->childNodes();
    for my $child_node (@child_nodes) {
        my $uri = $child_node->getAttribute("uri");
        if (not $uri) {
            next;
        }
        if ($uri !~ $sia_base) {
            $self->_log("Client ($handle) attempting publication ".
                        "for unauthorised URL ($uri)");
            return $self->_error(HTTP_BAD_REQUEST, undef, undef, $ct);
        }
        my ($rest) = ($uri =~ /^$sia_base(.*)/);
        if ($rest =~ /\//) {
            $self->_log("Client ($handle) attempting publication ".
                        "for unauthorised URL ($uri)");
            return $self->_error(HTTP_BAD_REQUEST, undef, undef, $ct);
        }
    }

    return;
}

sub _adjust_publication_response
{
    my ($self, $handle, $content) = @_;

    my $response_doc =
        XML::LibXML->load_xml(string => $content,
                              { no_blanks => 1 });
    my $node = $response_doc->documentElement();
    my $sia_base = $self->_get_sia_base($handle);

    my @child_nodes = $node->childNodes();
    for my $child_node (@child_nodes) {
        my $uri = $child_node->getAttribute("uri");
        if (not $uri) {
            next;
        }
        if ($uri !~ $sia_base) {
            $child_node->parentNode()->removeChild($child_node);
            next;
        }
        my ($rest) = ($uri =~ /^$sia_base(.*)/);
        if ($rest =~ /\//) {
            $child_node->parentNode()->removeChild($child_node);
            next;
        }
    }

    return $node->toString();
}

sub _publication_post
{
    my ($self, $c, $r, $handle) = @_;

    my $ca = $self->{'ca'};
    if (not $ca->is_initialised()) {
        return $self->_error(HTTP_INTERNAL_SERVER_ERROR,
                             "No BPKI initialised",
                             "BPKI must be initialised before publishing.");
    }

    my $ct = $r->header('Content-Type');

    my $client_bpki_ta = $self->{'clients'}->{$handle};
    if (not $client_bpki_ta) {
        return $self->_error(HTTP_NOT_FOUND, undef, undef, $ct);
    }
    my $client_bpki_ta_cert =
        '-----BEGIN X509 CERTIFICATE-----'."\n".
        $client_bpki_ta."\n".
        '-----END X509 CERTIFICATE-----';

    my $cms_client_request = $r->content();
    $self->_log("Publication protocol request ($handle): ".
                encode_base64($cms_client_request));

    my $openssl = $self->{'openssl'};
    my $xml_client_request = eval {
        $openssl->verify_cms($cms_client_request,
                             $client_bpki_ta_cert);
    };
    if (my $error = $@) {
        $self->_log("Unable to verify CMS from client: ".
                    encode_base64($cms_client_request).", ".
                    $error);
        return $self->_error(HTTP_BAD_REQUEST, undef, undef, $ct);
    }

    my $error = $self->_validate_publication_request($handle, $ct,
                                                     $xml_client_request);
    if ($error) {
        return $error;
    }

    my $cms_parent_request = $ca->sign_cms($xml_client_request);
    my $http_request =
        HTTP::Request->new(
            POST => $self->{'repository_data'}->{'service_uri'},
            [ 'Content-Type' => 'application/rpki-publication' ],
            $cms_parent_request
        );

    my $ua = LWP::UserAgent->new();
    my $http_response = $ua->request($http_request);

    if (not $http_response->is_success()) {
        $self->_log("Publication to parent repository failed: ".
                    Dumper($http_response));
        return $self->_error($http_response->code(), 'Error',
                             'Unable to publish to parent repository');
    }

    my $parent_bpki_ta_cert =
        '-----BEGIN X509 CERTIFICATE-----'."\n".
        $self->{'repository_data'}->{'repository_bpki_ta'}."\n".
        '-----END X509 CERTIFICATE-----';
    my $cms_parent_response = $http_response->content();
    my $xml_parent_response = eval {
        $openssl->verify_cms($cms_parent_response,
                             $parent_bpki_ta_cert);
    };
    if (my $error = $@) {
        $self->_log("Unable to decode response from parent repository: ".
                    encode_base64($cms_parent_response).", ".
                    $error);
        return $self->_error(HTTP_INTERNAL_SERVER_ERROR,
                             'Error', 'Error decoding parent response',
                             $ct);
    }

    $self->_log("Publication protocol response (unadjusted): ".
                $xml_parent_response);
    my $xml_client_response =
        $self->_adjust_publication_response($handle,
                                            $xml_parent_response);
    $self->_log("Publication protocol response (adjusted): ".
                $xml_client_response);

    my $cms_client_response =
        $self->{'ca'}->sign_cms($xml_client_response);

    return $self->_success(HTTP_OK, $cms_client_response, $ct);
}

sub _save
{
    my ($self) = @_;

    my $data = { repository_data => $self->{'repository_data'},
                 clients         => $self->{'clients'} };
    store $data, $self->{'db_path'}.'/data';
}

sub run
{
    my ($self) = @_;

    $SIG{'TERM'} = sub { exit(0); };

    my $d = $self->{'daemon'};
    while (my $c = $d->accept()) {
        while (my $r = $c->get_request()) {
            my $method = $r->method();
            my $path = $r->uri()->path();
            $self->_log("$method $path");

            my $res;
            eval {
                if ($method eq 'POST') {
                    if ($path eq '/bpki-init') {
                        $res = $self->_bpki_init_post($c, $r);
                    } elsif ($path eq '/bpki-cycle') {
                        $res = $self->_bpki_cycle_post($c, $r);
                    } elsif ($path eq '/repository') {
                        $res = $self->_repository_post($c, $r);
                    } elsif ($path eq '/client') {
                        $res = $self->_client_post($c, $r);
                    } elsif ($path =~ /^\/publication\/(.*)$/) {
                        my $handle = $1;
                        $res = $self->_publication_post($c, $r, $handle);
                    }
                } elsif ($method eq 'GET') {
                    if ($path eq '/publisher') {
                        $res = $self->_publisher_get($c, $r);
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

__END__

=head1 NAME

APNIC::RPKI::Publication::Proxy::Server

=head1 DESCRIPTION

An RPKI publication proxy.  Allows an RPKI CA operator to publish to a
single publication point on behalf of its child engines.  This is
useful when the publication point used by the CA does not implement
referrals, or when the CA would prefer to intermediate their child
engines' publication requests, for audit purposes or similar.

The endpoints provided by this server are documented in the README of
the repository.

=head1 CONSTRUCTOR

=over 4

=item B<new>

Takes a hash of arguments:

=over 8

=item hostname

The hostname on which the proxy will be accessible
to its clients.  Defaults to 'rpki-pp'.

=item port

The port to use for the server (defaults to 8080).

=item handle

A string identifying the publication proxy.  Used
in the BPKI CA subject name, and also as the
handle in the publication request issued by the
proxy.  Defaults to 'rpki-pp'.

=item db_path

The path to the proxy's database directory.  If
not provided, a new database directory will be
created.  This directory contains all the state
required by the application: BPKI CA, client BPKI
details, and publication point repository details.

=back

Returns a new instance of C<APNIC::RPKI::Publication::Proxy::Server>.

=back

=head1 PUBLIC METHODS

=over 4

=item B<run>

Run the server.  This method does not return.

=back

=head1 LICENSE AND COPYRIGHT

Copyright 2018 APNIC Pty Ltd.

The full text of the license can be found in the LICENSE.txt file included
with this module.

=cut

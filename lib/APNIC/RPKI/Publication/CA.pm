package APNIC::RPKI::Publication::CA;

use warnings;
use strict;

use File::Slurp qw(read_file
                   write_file);
use File::Temp qw(tempdir);
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use MIME::Base64;
use LWP::UserAgent;
use Storable;
use XML::LibXML;

use APNIC::RPKI::Publication::Utils qw(system_ad);

use constant CA_CONFIG => <<EOF;
[ default ]
ca                      = root-ca
dir                     = .

[ req ]
default_bits            = 2048
encrypt_key             = yes
default_md              = sha1
utf8                    = yes
string_mask             = utf8only
prompt                  = no
distinguished_name      = ca_dn
req_extensions          = ca_reqext

[ ca_dn ]
commonName              = "Simple Root CA"

[ ca_reqext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash

[ ca ]
default_ca              = root_ca

[ root_ca ]
certificate             = {dir}/ca/{ca}.crt
private_key             = {dir}/ca/{ca}/private/{ca}.key
new_certs_dir           = {dir}/ca/{ca}
serial                  = {dir}/ca/{ca}/db/{ca}.crt.srl
crlnumber               = {dir}/ca/{ca}/db/{ca}.crl.srl
database                = {dir}/ca/{ca}/db/{ca}.db
unique_subject          = no
default_days            = 3652
default_md              = sha1
policy                  = match_pol
email_in_dn             = no
preserve                = no
name_opt                = ca_default
cert_opt                = ca_default
copy_extensions         = none
x509_extensions         = signing_ca_ext
default_crl_days        = 365
crl_extensions          = crl_ext

[ match_pol ]
commonName              = supplied

[ any_pol ]
domainComponent         = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

[ root_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always

[ signing_ca_ext ]
keyUsage                = critical,digitalSignature
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
EOF

use constant EE_CSR_FILENAME  => 'ee.csr';
use constant EE_CERT_FILENAME => 'ee.crt';
use constant EE_KEY_FILENAME  => 'ee.key';
use constant CRL_FILENAME     => 'crl.pem';
use constant ID_CT_XML        => '1.2.840.113549.1.9.16.1.28';

our $DEBUG = 0;

our $VERSION = '0.1';

sub new
{
    my $class = shift;

    my %args = @_;
    my $self = \%args;
    bless $self, $class;

    if (not $self->{'ca_path'}) {
        die "'ca_path' argument must be provided.";
    }
    if (not $self->{'openssl'}) {
        $self->{'openssl'} = APNIC::RPKI::Publication::OpenSSL->new();
    }

    return $self;
}

sub _chdir_ca
{
    my ($self) = @_;

    chdir $self->{'ca_path'} or die $!;

    return 1;
}

sub _system
{
    my (@args) = @_;

    my $cmd = join " ", @args;

    return system_ad($cmd, $DEBUG);
}

sub is_initialised
{
    my ($self) = @_;

    $self->_chdir_ca();

    return (-e "ca.cnf");
}

sub initialise
{
    my ($self, $common_name, $key_only) = @_;

    $self->_chdir_ca();

    if ($self->is_initialised()) {
        die "CA has already been initialised.";
    }

    my $config = CA_CONFIG();
    my $ca_path = $self->{'ca_path'};
    $config =~ s/{dir}/$ca_path/g;
    $config =~ s/{ca}/ca/g;

    write_file('ca.cnf', $config);

    for my $dir (qw(newcerts ca ca/ca ca/ca/private ca/ca/db)) {
        mkdir $dir or die $!;
    }
    for my $file (qw(ca/ca/db/ca.db ca/ca/db/ca.db.attr index.txt)) {
        _system("touch $file");
    }
    for my $serial_file (qw(ca.crt.srl ca.crl.srl)) {
        write_file("ca/ca/db/$serial_file", "01");
    }

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl genrsa -out ca/ca/private/ca.key 2048");
    if (not $key_only) {
        _system("$openssl req -new -x509 -key ca/ca/private/ca.key -out ca/ca.crt -subj '/CN=$common_name'");
    }

    return 1;
}

sub get_ca_request
{
    my ($self, $common_name) = @_;

    $self->_chdir_ca();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl req -new -key ca/ca/private/ca.key -out ca/ca.req -subj '/CN=$common_name'");

    my $data = read_file('ca/ca.req');
    return $data;
}

sub sign_ca_request
{
    my ($self, $request) = @_;

    $self->_chdir_ca();

    my $ft_request = File::Temp->new();
    print $ft_request $request;
    $ft_request->flush();
    my $fn_request = $ft_request->filename();

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl ca -batch -config ca.cnf -extensions root_ca_ext ".
            "-out $fn_output ".
            "-in $fn_request -days 365");

    my $data = read_file($fn_output);
    return $data;
}

sub install_ca_certificate
{
    my ($self, $certificate) = @_;

    $self->_chdir_ca();

    my $ft_cert = File::Temp->new();
    print $ft_cert $certificate;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl x509 -in $fn_cert -out ca/ca.crt");

    return 1;
}

sub revoke_current_ee_certificate
{
    my ($self) = @_;

    $self->_chdir_ca();

    if (-e "ee.crt") {
        my $openssl = $self->{'openssl'}->get_openssl_path();
        _system("$openssl ca -batch -config ca.cnf ".
                "-revoke ".EE_CERT_FILENAME());
    }

    return 1;
}

sub issue_new_ee_certificate
{
    my ($self) = @_;

    $self->_chdir_ca();

    $self->revoke_current_ee_certificate();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl genrsa ".
            "-out ".EE_KEY_FILENAME()." 2048");
    _system("$openssl req -new ".
            "-key ".EE_KEY_FILENAME()." ".
            "-out ".EE_CSR_FILENAME()." ".
            "-subj '/CN=EE'");
    _system("$openssl ca -batch -config ca.cnf ".
            "-out ".EE_CERT_FILENAME()." ".
            "-in ".EE_CSR_FILENAME()." -days 365");

    return 1;
}

sub issue_crl
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl ca -batch -crlexts crl_ext -config ca.cnf -gencrl ".
            "-out ".CRL_FILENAME());

    return 1;
}

sub cycle
{
    my ($self) = @_;

    $self->issue_new_ee_certificate();
    $self->issue_crl();

    return 1;
}

sub sign_cms
{
    my ($self, $input) = @_;

    my $ft_input = File::Temp->new();
    print $ft_input $input;
    $ft_input->flush();
    my $fn_input = $ft_input->filename();

    my $ft_output= File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    my $res = _system("$openssl cms -sign -nodetach -binary -outform DER ".
                      "-keyid -md sha256 -econtent_type ".ID_CT_XML()." ".
                      "-signer ".EE_CERT_FILENAME()." ".
                      "-CRLfile ".CRL_FILENAME()." ".
                      "-inkey ".EE_KEY_FILENAME()." ".
                      "-in $fn_input -out $fn_output");

    return read_file($fn_output);
}

sub get_ca_pem
{
    my ($self) = @_;

    $self->_chdir_ca();

    my @lines = read_file('ca/ca.crt');

    pop @lines;
    shift @lines;

    my $bpki_ta = join '', @lines;
    chomp $bpki_ta;

    return $bpki_ta;
}

1;

__END__

=head1 NAME

APNIC::RPKI::Publication::CA

=head1 DESCRIPTION

A basic Certificate Authority module for use with the publication
proxy.  Provides for issuing a self-signed root certificate, as well
as CRLs and EE certificates under it.

=head1 CONSTRUCTOR

=over 4

=item B<new>

Takes a hash of arguments:

=over 8

=item ca_path

The path to the directory containing the CA state.
For a new CA, this should be an empty directory
created by the caller: the module will put the CA
state into that directory (see C<initialise>).

=item openssl

An instance of
C<APNIC::RPKI::Publication::OpenSSL>.  If not
provided, a default object will be created using a
default OpenSSL executable path, but note that the
executable must support the '-CRLfile' option to
the 'cms' command (see the OpenSSL patch in the
top-level of the repository) for this module to
work correctly.

=back

Returns a new instance of C<APNIC::RPKI::Publication::CA>.

=back

=head1 PUBLIC METHODS

=over 4

=item B<is_initialised>

Returns a boolean indicating whether this CA has been initialised.

=item B<initialise>

Takes a certificate common name and a flag indicating whether a
self-signed certificate should not be generated.  Initialises a new CA
using the C<ca_path> directory provided to the constructor.  If the
second argument is true, then the caller must use the
C<get_ca_request> and C<install_ca_certificate> methods to set up the
CA.

=item B<get_ca_request>

Returns the certificate signing request for this CA.

=item B<sign_ca_request>

Signs a certificate signing request from a CA, returning the
new certificate in PEM format.

=item B<install_ca_certificate>

Takes a CA certificate in PEM format, and installs that certificate as
the CA certificate for this CA.

=item B<revoke_current_ee_certificate>

Revokes the CA's current EE certificate, if the CA has one.

=item B<issue_new_ee_certificate>

Issues a new EE certificate.  Also revokes the CA's current EE
certificate, if the CA has one.  (A CA will have at most one current
(unrevoked, unexpired) EE certificate at any time.)

=item B<issue_crl>

Issues a new CRL.

=item B<cycle>

Issue a new EE certificate and issue a new CRL.  Per
C<issue_new_ee_certificate>, this will also revoke the CA's current EE
certificate, if the CA has one.

=item B<sign_cms>

Takes a scalar variable containing the content to be signed.  Signs
that content using the CA's EE certificate, and returns the raw CMS
data.

=item B<get_ca_pem>

Returns the CA certificate in PEM format as a single string, with
newlines, and without the header and footer.

=back

=head1 LICENSE AND COPYRIGHT

Copyright 2018 APNIC Pty Ltd.

The full text of the license can be found in the LICENSE.txt file
included with this module.

=cut

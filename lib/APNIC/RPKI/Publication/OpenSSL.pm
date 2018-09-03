package APNIC::RPKI::Publication::OpenSSL;

use warnings;
use strict;

use File::Slurp qw(read_file);
use File::Temp;

use APNIC::RPKI::Publication::Utils qw(system_ad);

our $VERSION = '0.1';

sub new
{
    my $class = shift;

    my %args = @_;
    my $self = \%args;

    if (not $self->{'path'}) {
        $self->{'path'} = "/usr/local/ssl/bin/openssl";
    }

    bless $self, $class;
    return $self;
}

sub get_openssl_path
{
    my ($self) = @_;

    return $self->{'path'};
}

sub verify_cms
{
    my ($self, $input, $ca_cert) = @_;

    my $ft_input = File::Temp->new();
    print $ft_input $input;
    $ft_input->flush();
    my $fn_input = $ft_input->filename();

    my $ft_ca = File::Temp->new();
    print $ft_ca $ca_cert;
    $ft_ca->flush();
    my $fn_ca = $ft_ca->filename();

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $openssl = $self->get_openssl_path();
    system_ad("$openssl cms -verify -inform DER ".
              "-in $fn_input ".
              "-CAfile $fn_ca ".
              "-out $fn_output",
              $self->{'debug'});

    return read_file($fn_output);
}

1;

__END__

=head1 NAME

APNIC::RPKI::Publication::OpenSSL

=head1 DESCRIPTION

Simple wrapper module for an OpenSSL executable.

=head1 CONSTRUCTOR

=over 4

=item B<new>

Takes a hash of arguments:

=over 8

=item path

The path to the OpenSSL executable.  Defaults to
C</usr/local/ssl/bin/openssl>.

=item debug

A boolean indicating whether stdout/stderr from
OpenSSL commands should not be suppressed.
Defaults to false.

=back

Returns a new instance of C<APNIC::RPKI::Publication::OpenSSL>.

=back

=head1 PUBLIC METHODS

=over 4

=item B<get_openssl_path>

Returns the path of the OpenSSL executable for this module.

=item B<verify_cms>

Takes a CMS object (scalar) and a CA certificate (PEM format as
scalar) as its arguments.  Attempts to verify the CMS against the CA
certificate.  Returns the decoded CMS on success, and dies with an
error message on failure.

=back

=head1 LICENSE AND COPYRIGHT

Copyright 2018 APNIC Pty Ltd.

The full text of the license can be found in the LICENSE.txt file
included with this module.

=cut

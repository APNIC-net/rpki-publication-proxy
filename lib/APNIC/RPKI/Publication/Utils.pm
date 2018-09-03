package APNIC::RPKI::Publication::Utils;

use warnings;
use strict;

use File::Slurp qw(read_file);
use File::Temp;

use Exporter qw(import);

our @EXPORT_OK = qw(canonicalise_pem
                    system_ad);

sub canonicalise_pem
{
    my ($pem) = @_;

    $pem =~ s/\s*//g;
    $pem =~ s/(.{1,60})/$1\n/gs;
    chomp $pem;

    return $pem;
}

sub system_ad
{
    my ($cmd, $debug) = @_;

    my $res = system($cmd.($debug ? "" : " >/dev/null 2>&1"));
    if ($res != 0) {
        die "Unable to execute command.";
    }

    return 1;
}

1;

__END__

=head1 NAME

APNIC::RPKI::Publication::Utils

=head1 DESCRIPTION

Utility functions.

=head1 PUBLIC FUNCTIONS

=over 4

=item B<canonicalise_pem>

Takes a string of base46-encoded data.  Removes all newlines, and then
adds a newline after every 60th character, so that the result (once
a header and footer is added) can be used with OpenSSL.

=item B<system_ad>

A wrapper around C<system> that dies with an error message if the
command does not execute successfully.

=back

=head1 LICENSE AND COPYRIGHT

Copyright 2018 APNIC Pty Ltd.

The full text of the license can be found in the LICENSE.txt file
included with this module.

=cut

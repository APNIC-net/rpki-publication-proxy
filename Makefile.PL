use strict;
use warnings;

use ExtUtils::MakeMaker;
use ExtUtils::MakeMaker::Config;

my $output = WriteMakefile(
    NAME           => 'APNIC::RPKI::Publication::Proxy::Server',
    AUTHOR         => 'Software <software@apnic.net>',
    LICENSE        => 'bsd',
    VERSION_FROM   => 'lib/APNIC/RPKI/Publication/Proxy/Server.pm',
    META_MERGE     => {
        resources => {
            repository => 'https://github.com/APNIC-net/rpki-publication-proxy'
        }
    },
    EXE_FILES      => [ qw(bin/rpki-publication-proxy-server) ],
    PREREQ_PM      => { 'Test::More'             => 0,
                        'HTTP::Daemon'           => 0,
                        'YAML'                   => 0,
                        'LWP::UserAgent'         => 0,
                        'List::MoreUtils'        => 0,
                        'IO::Capture::Stderr'    => 0, }
);

1;

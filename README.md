## rpki-publication-proxy

A proxy server that allows an RPKI CA operator to publish to a single
publication point on behalf of its child engines.  This is useful when
the publication point used by the CA does not implement referrals, or
when the CA would prefer to intermediate their child engines'
publication requests, for audit purposes or similar.

### Build

    docker build -t apnic/rpki-publication-proxy .

### Parameters (environment variables)

 - HOSTNAME: the hostname on which the proxy will be accessible to its
   clients (defaults to 'rpki-pp').
 - PORT: the port to use for the server (defaults to 8080).
 - HANDLE: a string identifying the publication proxy, used in the
   BPKI CA subject name and as the handle in the publication request
   issued by the proxy (defaults to 'rpki-pp').
 - DBPATH: the path to the proxy's database directory.  If not
   provided, a new database directory will be created.  This directory
   contains all the state required by the application: BPKI CA, client
   BPKI details, and publication point repository details.

### Endpoints

 - `POST /bpki-init`: set up a local BPKI CA and EE certificate for
   the proxy to use.  This must be run manually when the proxy is
   being initialised.
 - `POST /bpki-cycle`: revoke the previous EE certificate, issue a new
   one, and issue a new CRL.  This must be run periodically (at least
   yearly, at the moment, after the initial call to `bpki-init`).
 - `GET /publisher`: get the publication request XML for this
   publication proxy.  This should be passed to the publication point,
   which will return repository response XML.
 - `POST /repository`: takes the repository response XML retrieved
   from the publication point (provided as post data) and initialises
   the proxy's internal state accordingly.
 - `POST /client`: takes publication request XML (provided as post
   data) and returns repository response XML that child engines can
   use for publication.  Those publication requests will be proxied to
   the publication point that was configured via `POST /repository`.

There is an additional publication endpoint, but unlike the endpoints
above, there is no need to call the publication endpoint manually: the
clients that use the proxy learn about the publication endpoint from
the repository response XML returned by `POST /client`.

### References

 - [RFC 8181: A Publication Protocol for the Resource Public Key Infrastructure (RPKI)](https://tools.ietf.org/html/rfc8181)
 - [RFC 8183: An Out-of-Band Setup Protocol for Resource Public Key Infrastructure (RPKI) Production Services](https://tools.ietf.org/html/rfc8183)

### License

See LICENSE.txt.

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

#### Administrative (internal)

 - `POST /admin/bpki-init`
    - Takes no parameters.  Sets up a local BPKI CA and EE certificate
      for the proxy to use.  This must be run manually when the proxy
      is initialised: the proxy will respond with HTTP errors to all
      other types of request until this has happened.

 - `POST /admin/bpki-cycle`
    - Takes no parameters.  Revokes the previous EE certificate,
      issues a new one, and issues a new CRL.  This must be run
      periodically (at least yearly, at the moment, after the initial
      call to `/admin/bpki-init`).

 - `GET /admin/publisher`
    - Takes no parameters.  Returns the publication request XML
      ([section 5.2.3 of RFC 8183](https://tools.ietf.org/html/rfc8183#section-5.2.3)) for this publication proxy.
      This XML should be passed to the upstream publication point, which
      will return repository response XML ([section 5.2.4 of RFC 8183](https://tools.ietf.org/html/rfc8183#section-5.2.4)).

 - `POST /admin/repository`
    - Takes as POST data the repository response XML ([section 5.2.4 of RFC 8183](https://tools.ietf.org/html/rfc8183#section-5.2.4))
      retrieved from the publication point, and initialises the proxy's internal state accordingly.

 - `POST /admin/client`
    - Takes as POST data the publication request XML ([section 5.2.3 of RFC 8183](https://tools.ietf.org/html/rfc8183#section-5.2.3))
      for a child engine, and returns the repository
      response XML ([section 5.2.4 of RFC 8183](https://tools.ietf.org/html/rfc8183#section-5.2.4)) for that engine.
      The `publisher_handle` must be unique per proxy instance: the
      proxy will return an error message if the handle is already in
      use.

#### User (external)

 - `POST /publication/{publisher_handle}`
    - The endpoint used by a publication client to make publication
      protocol ([RFC 8181](https://tools.ietf.org/html/rfc8181))
      requests.  The URL for this endpoint is
      included within the client-specific repository response XML (see
      `POST /admin/client`).

### References

 - [RFC 8181: A Publication Protocol for the Resource Public Key Infrastructure (RPKI)](https://tools.ietf.org/html/rfc8181)
 - [RFC 8183: An Out-of-Band Setup Protocol for Resource Public Key Infrastructure (RPKI) Production Services](https://tools.ietf.org/html/rfc8183)

### License

See [LICENSE](./LICENSE).

These public test fixtures contain a P-256 localhost server key, its certificate,
and a test CA certificate. They are not account credentials and must never be
used outside tests. The server certificate is valid from 2020 through 2120 and
has only `localhost` in its SAN. The CA signing key is not retained.

The fixtures were generated once with OpenSSL. Tests use the same pure-Rust
provider as the native adapter and require no OpenSSL, ring, AWS-LC or external
network access. Tests add the test CA to a private client configuration while
keeping certificate and hostname verification enabled.

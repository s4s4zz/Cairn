# CP0 provisional synthetic labels

These labels are a contract fixture, not human-adjudicated vendor gold.

The config-first review identifies three entrypoints: the `web.xml` servlet
mapping, the XML action binding and the JSP request expression. The code-first
review follows `PlatformRequest` input through the authorization and tenant
guards into `SyntheticAction.execute`, then to the concatenated SQL string
accepted by `PlatformSql.queryForText`.

The one expected finding is high-severity SQL injection. Its required evidence
is entrypoint, input, guard, call-chain and sink. It is not marked dynamically
reproducible because the fixture has no executable vendor-style runtime.

Coverage units correspond one-for-one with the eleven entries in
`fixture-matrix-v1.json`. Fingerprints are SHA-256 over the stable logical names
recorded in `synthetic-gold-v1.json`, never over compiler-specific line numbers.

# Componenta Auth JWT

JWT access tokens with rotating opaque refresh-token families for Componenta
Auth 4.

Version 2 requires `componenta/auth ^4.0.0`, `componenta/auth-http ^2.0.0`,
`componenta/identity ^1.1.1` and `componenta/clock ^1.2.0`.

JWTs preserve the AuthenticationEvidence that established the token.
Refresh families persist the same bounded evidence snapshot, so refresh cannot
silently raise authentication assurance.

Refresh-token reuse compromises and revokes the complete family.

`Claims` owns its top-level custom-claim map, including directly referenced
input entries. Custom claim names may be numeric strings; their PHP array-key
representation is preserved across signing and parsing. Nested values are
borrowed, so keep nested objects and references unchanged until signing.

Refresh grants have two independent lifetimes: an inactivity-style per-token
TTL and an absolute family TTL. Rotation may shorten a successor to the family
deadline but never extends that deadline. This bounds how long an old
AuthenticationEvidence snapshot can be propagated without fresh authentication.

## JWT header validation

The built-in HMAC and RSA signers support no critical JOSE extensions. They
reject any token containing a `crit` header, including malformed or empty
values, as required when those extensions cannot be processed. Unknown
noncritical extension headers remain permitted. See
[RFC 7515, section 4.1.11](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11).

## Required admission checks

`RefreshHandler` requires one `AuthenticationGuardInterface $guard` as its
last constructor argument. Inject the same
account-admission policy used for session issuance and other login mechanisms.
There is no default allow implementation; compose multiple checks in the
application's guard when necessary.

All fallible work after a successful refresh rotation, including the second
identity/guard check, is within the compensation scope. On exception, the
unpublished successor is revoked. Revocation-store failure must be treated as
an infrastructure error; it is not successful revocation. This does not change
the lifetime/revocation semantics of already issued stateless access tokens.

HMAC and RSA signer debug output includes the algorithm and a redaction marker;
it does not traverse the internal signing configuration or expose key material.

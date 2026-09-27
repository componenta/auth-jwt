# Componenta Auth JWT

JWT access tokens with rotating opaque refresh-token families for Componenta
Auth 3.

Auth 3 JWTs preserve the AuthenticationEvidence that established the token.
Refresh families persist the same bounded evidence snapshot, so refresh cannot
silently raise authentication assurance.

Refresh-token reuse compromises and revokes the complete family.

Refresh grants have two independent lifetimes: an inactivity-style per-token
TTL and an absolute family TTL. Rotation may shorten a successor to the family
deadline but never extends that deadline. This bounds how long an old
AuthenticationEvidence snapshot can be propagated without fresh authentication.

## Security integration migration (Auth 3 development)

`RefreshHandler` now requires one `AuthenticationGuardInterface $guard` as its
last constructor argument instead of optional variadic guards. Inject the same
account-admission policy used for session issuance and other login mechanisms.
There is no default allow implementation; compose multiple checks in the
application's guard when necessary.

All fallible work after a successful refresh rotation, including the second
identity/guard check, is within the compensation scope. On exception, the
unpublished successor is revoked. Revocation-store failure must be treated as
an infrastructure error; it is not successful revocation. This does not change
the lifetime/revocation semantics of already issued stateless access tokens.

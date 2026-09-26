# Componenta Auth JWT

JWT access tokens with rotating opaque refresh-token families for Componenta
Auth 3.

Auth 3 JWTs preserve the AuthenticationEvidence that established the token.
Refresh families persist the same bounded evidence snapshot, so refresh cannot
silently raise authentication assurance.

Refresh-token reuse compromises and revokes the complete family.

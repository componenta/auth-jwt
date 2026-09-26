<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

/**
 * Signs and verifies JWT tokens.
 *
 * Abstracts the underlying signing algorithm (HMAC, RSA, etc.)
 * so that strategies and handlers are algorithm-agnostic.
 */
interface SignerInterface
{
    /**
     * Creates a signed JWT string from claims.
     */
    public function sign(Claims $claims): string;

    /**
     * Parses and verifies a JWT string.
     *
     * Returns null if the token is malformed or
     * the signature is invalid.
     *
     * Does NOT check expiry - caller is responsible
     * for comparing Claims::$expiresAt with current time.
     */
    public function parse(
        #[\SensitiveParameter]
        string $token,
    ): ?Claims;
}

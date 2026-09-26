<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

/** Configuration of one explicit access-token validation profile. */
final readonly class JwtConfig
{
    private const int MAX_ACCESS_TTL = 86400;
    private const int MAX_REFRESH_TTL = 31536000;

    public int $refreshFamilyTtl;

    public function __construct(
        public string $issuer,
        public string $audience,
        public string $type = 'at+jwt',
        public int $accessTtl = 900,
        public int $refreshTtl = 604800,
        public int $clockSkew = 30,
        ?int $refreshFamilyTtl = null,
    ) {
        $this->refreshFamilyTtl = $refreshFamilyTtl ?? $this->refreshTtl;
        foreach (['issuer' => $this->issuer, 'audience' => $this->audience, 'type' => $this->type] as $name => $value) {
            if ($value === '' || strlen($value) > 2048 || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
                throw new \InvalidArgumentException(sprintf('JWT %s must be a bounded non-empty string.', $name));
            }
        }

        if ($this->accessTtl < 1 || $this->accessTtl > self::MAX_ACCESS_TTL) {
            throw new \InvalidArgumentException(sprintf(
                'Access TTL must be between 1 and %d seconds.',
                self::MAX_ACCESS_TTL,
            ));
        }

        if ($this->refreshTtl < 1 || $this->refreshTtl > self::MAX_REFRESH_TTL) {
            throw new \InvalidArgumentException(sprintf(
                'Refresh TTL must be between 1 and %d seconds.',
                self::MAX_REFRESH_TTL,
            ));
        }

        if (
            $this->refreshFamilyTtl < $this->refreshTtl
            || $this->refreshFamilyTtl > self::MAX_REFRESH_TTL
        ) {
            throw new \InvalidArgumentException(sprintf(
                'Refresh family TTL must be between refreshTtl and %d seconds.',
                self::MAX_REFRESH_TTL,
            ));
        }

        if ($this->clockSkew < 0 || $this->clockSkew > 300) {
            throw new \InvalidArgumentException('JWT clock skew must be between 0 and 300 seconds.');
        }
    }
}

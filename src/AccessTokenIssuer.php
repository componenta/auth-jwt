<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Http\BearerCredential;
use Componenta\Clock\Clock;
use Componenta\Identity\IdentityInterface;
use Psr\Clock\ClockInterface;

final readonly class AccessTokenIssuer
{
    public function __construct(
        private SignerInterface $signer,
        private JwtConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    /** @param array<string, mixed> $custom */
    public function issue(
        IdentityInterface $identity,
        AuthenticationEvidence $evidence,
        array $custom = [],
    ): string {
        $now = $this->clock->now()->getTimestamp();
        $token = $this->signer->sign(new Claims(
            subject: $identity->uuid->toString(),
            issuedAt: $now,
            expiresAt: $now + $this->config->accessTtl,
            issuer: $this->config->issuer,
            audience: $this->config->audience,
            type: $this->config->type,
            custom: JwtEvidence::inject($custom, $evidence),
        ));
        BearerCredential::assertValid($token);

        return $token;
    }
}

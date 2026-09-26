<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Http\Extractor\BearerPayload;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Jwt\Denied\AccessTokenExpired;
use Componenta\Auth\Jwt\Denied\InvalidAccessToken;
use Componenta\Clock\Clock;
use Componenta\Identity\Uuid;
use Psr\Clock\ClockInterface;

final readonly class JwtStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private SignerInterface $signer,
        private IdentityProviderInterface $identities,
        private JwtConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    #[\Override]
    public function supports(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): bool {
        return $payload instanceof BearerPayload;
    }

    #[\Override]
    public function attempt(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): AuthenticationResult {
        if (!$payload instanceof BearerPayload) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        $claims = $this->signer->parse($payload->token);

        if ($claims === null || !$this->matchesProfile($claims)) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        $now = $this->clock->now()->getTimestamp();
        $skew = $this->config->clockSkew;

        if ($claims->expiresAt <= $now - $skew) {
            return new AuthenticationResult(new AccessTokenExpired());
        }

        if (
            $claims->issuedAt > $now + $skew
            || ($claims->notBefore !== null
                && $claims->notBefore > $now + $skew)
            || $claims->expiresAt <= $claims->issuedAt
            || $claims->expiresAt - $claims->issuedAt
                > $this->config->accessTtl
        ) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        $evidence = JwtEvidence::extract($claims);

        if ($evidence === null) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        try {
            $subjectId = Uuid::fromString($claims->subject);
        } catch (\InvalidArgumentException) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        $identity = $this->identities->findByUuid($subjectId);

        if ($identity === null || !$subjectId->equals($identity->uuid)) {
            return new AuthenticationResult(new InvalidAccessToken());
        }

        return new AuthenticationResult(
            subject: $identity,
            evidence: $evidence,
        );
    }

    private function matchesProfile(Claims $claims): bool
    {
        return hash_equals($this->config->issuer, $claims->issuer)
            && hash_equals($this->config->audience, $claims->audience)
            && hash_equals($this->config->type, $claims->type);
    }
}

<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Jwt\Denied\InvalidRefreshToken;
use Componenta\Auth\Jwt\Denied\RefreshTokenExpired;
use Componenta\Auth\Jwt\Denied\TokenFamilyCompromised;
use Componenta\Clock\Clock;
use Componenta\Identity\UuidInterface;
use Psr\Clock\ClockInterface;

final readonly class RefreshTokenManager
{
    public function __construct(
        private RefreshTokenStoreInterface $store,
        private RefreshTokenGenerator $generator,
        private JwtConfig $config,
        private ClockInterface $clock = new Clock(),
    ) {}

    public function issue(
        UuidInterface $subjectId,
        AuthenticationEvidence $evidence,
    ): RefreshToken {
        $token = new RefreshToken(
            id: $this->generator->generate(),
            subjectId: $subjectId,
            familyId: $this->generator->generate(),
            evidence: $evidence,
            expiresAt: $this->now() + $this->config->refreshTtl,
        );
        $this->store->storeInitial($token);

        return $token;
    }

    public function findActiveContext(
        #[\SensitiveParameter]
        string $tokenId,
    ): ?RefreshTokenContext {
        if (!RefreshToken::validIdentifier($tokenId)) {
            return null;
        }

        return $this->store->findActiveContext($tokenId, $this->now());
    }

    public function rotate(
        #[\SensitiveParameter]
        string $tokenId,
    ): RefreshToken|DeniedReasonInterface {
        if (!RefreshToken::validIdentifier($tokenId)) {
            return new InvalidRefreshToken();
        }

        $now = $this->now();
        $successorId = $this->generator->generate();
        $successorExpiresAt = $now + $this->config->refreshTtl;
        $result = $this->store->rotateAtomically(
            $tokenId,
            $successorId,
            $successorExpiresAt,
            $now,
        );

        return match ($result->status) {
            RefreshTokenRotationStatus::Rotated => $this->successor(
                $result,
                $successorId,
                $successorExpiresAt,
            ),
            RefreshTokenRotationStatus::Invalid => new InvalidRefreshToken(),
            RefreshTokenRotationStatus::Expired => new RefreshTokenExpired(),
            RefreshTokenRotationStatus::Reused => new TokenFamilyCompromised(),
        };
    }

    public function revoke(
        #[\SensitiveParameter]
        string $tokenId,
    ): void {
        if (RefreshToken::validIdentifier($tokenId)) {
            $this->store->revoke($tokenId, $this->now());
        }
    }

    public function revokeAllForSubject(UuidInterface $subjectId): void
    {
        $this->store->revokeAllForSubject($subjectId, $this->now());
    }

    private function successor(
        RefreshTokenRotationResult $result,
        string $expectedId,
        int $expectedExpiresAt,
    ): RefreshToken {
        $token = $result->token
            ?? throw new \LogicException(
                'Rotated refresh result must contain successor.',
            );

        if (
            !hash_equals($expectedId, $token->id)
            || $token->expiresAt !== $expectedExpiresAt
            || $token->revoked
        ) {
            throw new \LogicException(
                'Refresh store returned an invalid successor.',
            );
        }

        return $token;
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}

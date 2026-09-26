<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Identity\UuidInterface;

interface RefreshTokenStoreInterface
{
    public function storeInitial(
        #[\SensitiveParameter]
        RefreshToken $token,
    ): void;

    public function findActiveContext(
        #[\SensitiveParameter]
        string $tokenId,
        int $now,
    ): ?RefreshTokenContext;

    public function rotateAtomically(
        #[\SensitiveParameter]
        string $presentedTokenId,
        #[\SensitiveParameter]
        string $successorTokenId,
        int $successorExpiresAt,
        int $now,
    ): RefreshTokenRotationResult;

    public function revoke(
        #[\SensitiveParameter]
        string $tokenId,
        int $revokedAt,
    ): void;

    public function revokeAllForSubject(
        UuidInterface $subjectId,
        int $revokedAt,
    ): void;
}

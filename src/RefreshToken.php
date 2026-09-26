<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Identity\UuidInterface;

final readonly class RefreshToken implements \JsonSerializable
{
    public bool $revoked;

    public function __construct(
        #[\SensitiveParameter]
        public string $id,
        public UuidInterface $subjectId,
        #[\SensitiveParameter]
        public string $familyId,
        public AuthenticationEvidence $evidence,
        public int $expiresAt,
        public int $familyExpiresAt,
        public ?int $revokedAt = null,
    ) {
        if (!self::validIdentifier($this->id)) {
            throw new \InvalidArgumentException('Refresh token ID is invalid.');
        }

        if (!self::validIdentifier($this->familyId)) {
            throw new \InvalidArgumentException(
                'Refresh token family ID is invalid.',
            );
        }

        if (
            $this->expiresAt < 1
            || $this->familyExpiresAt < $this->expiresAt
        ) {
            throw new \InvalidArgumentException(
                'Refresh token expiry must be positive and bounded by its family.',
            );
        }

        if ($this->revokedAt !== null && $this->revokedAt < 1) {
            throw new \InvalidArgumentException(
                'Refresh token revocation time must be positive.',
            );
        }

        $this->revoked = $this->revokedAt !== null;
    }

    /** @return array{id: string, subjectId: string, familyId: string, evidence: array{methods: non-empty-list<string>, capabilities: list<string>}, expiresAt: int, familyExpiresAt: int, revokedAt: int|null, revoked: bool} */
    public function __debugInfo(): array
    {
        return [
            'id' => '[REDACTED]',
            'subjectId' => $this->subjectId->toString(),
            'familyId' => '[REDACTED]',
            'evidence' => $this->evidence->__debugInfo(),
            'expiresAt' => $this->expiresAt,
            'familyExpiresAt' => $this->familyExpiresAt,
            'revokedAt' => $this->revokedAt,
            'revoked' => $this->revoked,
        ];
    }

    /** @return array{id: string, subjectId: string, familyId: string, evidence: array{methods: non-empty-list<string>, capabilities: list<string>}, expiresAt: int, revokedAt: int|null, revoked: bool} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    public function isExpired(int $now): bool
    {
        return $this->expiresAt <= $now;
    }

    public static function validIdentifier(string $value): bool
    {
        return preg_match('/\A[a-f0-9]{64}\z/D', $value) === 1;
    }
}

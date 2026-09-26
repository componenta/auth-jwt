<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

final readonly class DatabaseRefreshTokenStoreConfig
{
    public function __construct(
        public string $tokenTable = 'auth_refresh_tokens',
        public string $familyTable = 'auth_refresh_token_families',
        public string $tokenHashColumn = 'token_hash',
        public string $familyIdColumn = 'family_id',
        public string $subjectIdColumn = 'subject_uuid',
        public string $expiresAtColumn = 'expires_at',
        public string $consumedAtColumn = 'consumed_at',
        public string $revokedAtColumn = 'revoked_at',
        public string $familyExpiresAtColumn = 'expires_at',
        public string $evidenceColumn = 'evidence',
        public string $familyRevokedAtColumn = 'revoked_at',
        public string $compromisedAtColumn = 'compromised_at',
        public string $lockNonceColumn = 'lock_nonce',
    ) {
        foreach ([
            'tokenTable' => $this->tokenTable,
            'familyTable' => $this->familyTable,
            'tokenHashColumn' => $this->tokenHashColumn,
            'familyIdColumn' => $this->familyIdColumn,
            'subjectIdColumn' => $this->subjectIdColumn,
            'expiresAtColumn' => $this->expiresAtColumn,
            'consumedAtColumn' => $this->consumedAtColumn,
            'revokedAtColumn' => $this->revokedAtColumn,
            'familyExpiresAtColumn' => $this->familyExpiresAtColumn,
            'evidenceColumn' => $this->evidenceColumn,
            'familyRevokedAtColumn' => $this->familyRevokedAtColumn,
            'compromisedAtColumn' => $this->compromisedAtColumn,
            'lockNonceColumn' => $this->lockNonceColumn,
        ] as $name => $identifier) {
            if (preg_match('/\A[A-Za-z_][A-Za-z0-9_.]*\z/D', $identifier) !== 1) {
                throw new \InvalidArgumentException(sprintf(
                    '%s must be a valid trusted SQL identifier.',
                    $name,
                ));
            }
        }

        if ($this->tokenTable === $this->familyTable) {
            throw new \InvalidArgumentException(
                'Refresh token and family tables must be different.',
            );
        }
    }
}

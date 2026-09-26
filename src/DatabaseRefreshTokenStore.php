<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;

/**
 * SQL refresh-grant store with family-level serialization.
 *
 * The family row is the serialization point. Every rotation mutates a random
 * lock nonce before inspecting token state, so concurrent rotations for the
 * same family are ordered without dialect-specific SELECT ... FOR UPDATE.
 * Bearer token IDs are persisted only as SHA-256 hashes.
 */
final readonly class DatabaseRefreshTokenStore implements RefreshTokenStoreInterface
{
    private const int LOCK_NONCE_BYTES = 16;

    public function __construct(
        #[\SensitiveParameter]
        private DatabaseInterface $database,
        private DatabaseRefreshTokenStoreConfig $config = new DatabaseRefreshTokenStoreConfig(),
    ) {}

    #[\Override]
    public function storeInitial(
        #[\SensitiveParameter]
        RefreshToken $token,
    ): void {
        if ($token->revoked) {
            throw new \InvalidArgumentException(
                'An initial refresh token must be active.',
            );
        }

        $this->database->transaction(function (
            #[\SensitiveParameter]
            DatabaseInterface $database,
        ) use ($token): void {
            $database
                ->insert($this->config->familyTable)
                ->values([
                    $this->config->familyIdColumn => $token->familyId,
                    $this->config->subjectIdColumn => $token->subjectId->toString(),
                    $this->config->familyExpiresAtColumn => $token->familyExpiresAt,
                    $this->config->evidenceColumn => self::encodeEvidence(
                        $token->evidence,
                    ),
                    $this->config->familyRevokedAtColumn => null,
                    $this->config->compromisedAtColumn => null,
                    $this->config->lockNonceColumn => self::lockNonce(),
                ])
                ->run();

            $database
                ->insert($this->config->tokenTable)
                ->values([
                    $this->config->tokenHashColumn => self::hashToken($token->id),
                    $this->config->familyIdColumn => $token->familyId,
                    $this->config->subjectIdColumn => $token->subjectId->toString(),
                    $this->config->expiresAtColumn => $token->expiresAt,
                    $this->config->consumedAtColumn => null,
                    $this->config->revokedAtColumn => null,
                ])
                ->run();
        });
    }

    #[\Override]
    public function findActiveContext(
        #[\SensitiveParameter]
        string $tokenId,
        int $now,
    ): ?RefreshTokenContext {
        if (!self::validIdentifier($tokenId)) {
            return null;
        }

        if ($now < 1) {
            throw new \InvalidArgumentException(
                'Refresh lookup time must be positive.',
            );
        }

        $token = $this->findToken(
            $this->database,
            self::hashToken($tokenId),
        );

        if ($token === null) {
            return null;
        }

        if (
            self::nullableIntValue($token, $this->config->consumedAtColumn) !== null
            || self::nullableIntValue($token, $this->config->revokedAtColumn) !== null
            || self::intValue($token, $this->config->expiresAtColumn) <= $now
        ) {
            return null;
        }

        $familyId = self::stringValue(
            $token,
            $this->config->familyIdColumn,
        );
        $family = $this->findFamily($this->database, $familyId);

        if ($family === null) {
            return null;
        }

        if (
            self::nullableIntValue($family, $this->config->familyRevokedAtColumn) !== null
            || self::nullableIntValue($family, $this->config->compromisedAtColumn) !== null
            || self::intValue(
                $family,
                $this->config->familyExpiresAtColumn,
            ) <= $now
        ) {
            return null;
        }

        $subjectId = self::uuidValue(
            $family,
            $this->config->subjectIdColumn,
        );
        $tokenSubjectId = self::uuidValue(
            $token,
            $this->config->subjectIdColumn,
        );

        if (!$subjectId->equals($tokenSubjectId)) {
            throw new \UnexpectedValueException(
                'Refresh token subject does not match its family.',
            );
        }

        return new RefreshTokenContext(
            $subjectId,
            self::decodeEvidence(
                self::stringValue($family, $this->config->evidenceColumn),
            ),
        );
    }

    #[\Override]
    public function rotateAtomically(
        #[\SensitiveParameter]
        string $presentedTokenId,
        #[\SensitiveParameter]
        string $successorTokenId,
        int $successorExpiresAt,
        int $now,
    ): RefreshTokenRotationResult {
        if (!self::validIdentifier($presentedTokenId)) {
            return RefreshTokenRotationResult::invalid();
        }

        if (!self::validIdentifier($successorTokenId)) {
            throw new \InvalidArgumentException(
                'Successor refresh token ID is invalid.',
            );
        }

        if ($now < 1 || $successorExpiresAt <= $now) {
            throw new \InvalidArgumentException(
                'Refresh rotation timestamps are invalid.',
            );
        }

        $presentedHash = self::hashToken($presentedTokenId);
        $candidate = $this->findToken($this->database, $presentedHash);

        if ($candidate === null) {
            return RefreshTokenRotationResult::invalid();
        }

        $familyId = self::stringValue(
            $candidate,
            $this->config->familyIdColumn,
        );

        return $this->database->transaction(
            function (
                #[\SensitiveParameter]
                DatabaseInterface $database,
            ) use (
                $presentedHash,
                $successorTokenId,
                $successorExpiresAt,
                $now,
                $familyId,
            ): RefreshTokenRotationResult {
                $blocked = $this->claimActiveFamily($database, $familyId);

                if ($blocked !== null) {
                    return match ($blocked) {
                        RefreshTokenRotationStatus::Reused => RefreshTokenRotationResult::reused(),
                        RefreshTokenRotationStatus::Invalid => RefreshTokenRotationResult::invalid(),
                        default => throw new \LogicException(
                            'Unexpected refresh-family claim status.',
                        ),
                    };
                }

                $family = $this->findFamily($database, $familyId);

                if ($family === null) {
                    throw new \UnexpectedValueException(
                        'Refresh token references a missing family.',
                    );
                }

                $token = $this->findToken($database, $presentedHash);

                if ($token === null) {
                    // Bounded housekeeping may prune a bearer after its own
                    // expiry while rotation waits for family serialization.
                    // Missing credential state always fails closed.
                    return RefreshTokenRotationResult::invalid();
                }

                if (
                    self::stringValue($token, $this->config->familyIdColumn)
                    !== $familyId
                ) {
                    throw new \UnexpectedValueException(
                        'Refresh token family changed during rotation.',
                    );
                }

                if (
                    self::intValue($token, $this->config->expiresAtColumn)
                    <= $now
                ) {
                    return RefreshTokenRotationResult::expired();
                }

                if (self::nullableIntValue(
                    $token,
                    $this->config->consumedAtColumn,
                ) !== null) {
                    $this->compromiseFamily($database, $familyId, $now);

                    return RefreshTokenRotationResult::reused();
                }

                if (self::nullableIntValue(
                    $token,
                    $this->config->revokedAtColumn,
                ) !== null) {
                    return RefreshTokenRotationResult::invalid();
                }

                $affected = $database
                    ->update($this->config->tokenTable)
                    ->where($this->config->tokenHashColumn, $presentedHash)
                    ->where($this->config->consumedAtColumn, null)
                    ->where($this->config->revokedAtColumn, null)
                    ->where($this->config->expiresAtColumn, '>', $now)
                    ->values([
                        $this->config->consumedAtColumn => $now,
                        $this->config->revokedAtColumn => $now,
                    ])
                    ->run();

                if ($affected !== 1) {
                    throw new \UnexpectedValueException(
                        'Refresh token could not be claimed after its family was locked.',
                    );
                }

                $subjectId = self::uuidValue(
                    $family,
                    $this->config->subjectIdColumn,
                );
                $tokenSubjectId = self::uuidValue(
                    $token,
                    $this->config->subjectIdColumn,
                );

                if (!$subjectId->equals($tokenSubjectId)) {
                    throw new \UnexpectedValueException(
                        'Refresh token subject does not match its family.',
                    );
                }

                $familyExpiresAt = self::intValue(
                    $family,
                    $this->config->familyExpiresAtColumn,
                );

                if ($familyExpiresAt <= $now) {
                    return RefreshTokenRotationResult::expired();
                }

                $actualSuccessorExpiresAt = min(
                    $successorExpiresAt,
                    $familyExpiresAt,
                );

                $database
                    ->insert($this->config->tokenTable)
                    ->values([
                        $this->config->tokenHashColumn => self::hashToken(
                            $successorTokenId,
                        ),
                        $this->config->familyIdColumn => $familyId,
                        $this->config->subjectIdColumn => $subjectId->toString(),
                        $this->config->expiresAtColumn => $actualSuccessorExpiresAt,
                        $this->config->consumedAtColumn => null,
                        $this->config->revokedAtColumn => null,
                    ])
                    ->run();

                return RefreshTokenRotationResult::rotated(new RefreshToken(
                    id: $successorTokenId,
                    subjectId: $subjectId,
                    familyId: $familyId,
                    evidence: self::decodeEvidence(
                        self::stringValue(
                            $family,
                            $this->config->evidenceColumn,
                        ),
                    ),
                    expiresAt: $actualSuccessorExpiresAt,
                    familyExpiresAt: $familyExpiresAt,
                ));
            },
        );
    }

    #[\Override]
    public function revoke(
        #[\SensitiveParameter]
        string $tokenId,
        int $revokedAt,
    ): void {
        if (!self::validIdentifier($tokenId)) {
            return;
        }

        if ($revokedAt < 1) {
            throw new \InvalidArgumentException(
                'Refresh token revocation time must be positive.',
            );
        }

        $tokenHash = self::hashToken($tokenId);
        $candidate = $this->findToken($this->database, $tokenHash);

        if ($candidate === null) {
            return;
        }

        $familyId = self::stringValue(
            $candidate,
            $this->config->familyIdColumn,
        );

        $this->database->transaction(
            function (
                #[\SensitiveParameter]
                DatabaseInterface $database,
            ) use (
                $familyId,
                $revokedAt,
            ): void {
                $affected = $database
                    ->update($this->config->familyTable)
                    ->where($this->config->familyIdColumn, $familyId)
                    ->where($this->config->familyRevokedAtColumn, null)
                    ->where($this->config->compromisedAtColumn, null)
                    ->values([
                        $this->config->familyRevokedAtColumn => $revokedAt,
                        $this->config->lockNonceColumn => self::lockNonce(),
                    ])
                    ->run();

                if ($affected !== 1) {
                    $family = $this->findFamily($database, $familyId);

                    if ($family === null) {
                        // A concurrent housekeeper may have already removed an
                        // expired family after this token was initially read.
                        return;
                    }

                    return;
                }

                $database
                    ->update($this->config->tokenTable)
                    ->where($this->config->familyIdColumn, $familyId)
                    ->where($this->config->revokedAtColumn, null)
                    ->values([
                        $this->config->revokedAtColumn => $revokedAt,
                    ])
                    ->run();
            },
        );
    }

    #[\Override]
    public function revokeAllForSubject(
        UuidInterface $subjectId,
        int $revokedAt,
    ): void {
        if ($revokedAt < 1) {
            throw new \InvalidArgumentException(
                'Refresh token revocation time must be positive.',
            );
        }

        $subject = $subjectId->toString();

        $this->database->transaction(
            function (
                #[\SensitiveParameter]
                DatabaseInterface $database,
            ) use (
                $subject,
                $revokedAt,
            ): void {
                $database
                    ->update($this->config->familyTable)
                    ->where($this->config->subjectIdColumn, $subject)
                    ->where($this->config->familyRevokedAtColumn, null)
                    ->values([
                        $this->config->familyRevokedAtColumn => $revokedAt,
                        $this->config->lockNonceColumn => self::lockNonce(),
                    ])
                    ->run();

                $database
                    ->update($this->config->tokenTable)
                    ->where($this->config->subjectIdColumn, $subject)
                    ->where($this->config->revokedAtColumn, null)
                    ->values([
                        $this->config->revokedAtColumn => $revokedAt,
                    ])
                    ->run();
            },
        );
    }

    /**
     * Returns null when the family is claimed for rotation, otherwise the
     * terminal status that blocked the claim.
     */
    private function claimActiveFamily(
        #[\SensitiveParameter]
        DatabaseInterface $database,
        #[\SensitiveParameter]
        string $familyId,
    ): ?RefreshTokenRotationStatus {
        $affected = $database
            ->update($this->config->familyTable)
            ->where($this->config->familyIdColumn, $familyId)
            ->where($this->config->familyRevokedAtColumn, null)
            ->where($this->config->compromisedAtColumn, null)
            ->values([
                $this->config->lockNonceColumn => self::lockNonce(),
            ])
            ->run();

        if ($affected === 1) {
            return null;
        }

        $family = $this->findFamily($database, $familyId);

        if ($family === null) {
            // Cleanup can win the family serialization race after the
            // presented token was read but before rotation claimed the family.
            return RefreshTokenRotationStatus::Invalid;
        }

        if (self::nullableIntValue(
            $family,
            $this->config->compromisedAtColumn,
        ) !== null) {
            return RefreshTokenRotationStatus::Reused;
        }

        if (self::nullableIntValue(
            $family,
            $this->config->familyRevokedAtColumn,
        ) !== null) {
            return RefreshTokenRotationStatus::Invalid;
        }

        throw new \UnexpectedValueException(
            'Refresh token family could not be serialized.',
        );
    }

    private function compromiseFamily(
        #[\SensitiveParameter]
        DatabaseInterface $database,
        #[\SensitiveParameter]
        string $familyId,
        int $now,
    ): void {
        $database
            ->update($this->config->familyTable)
            ->where($this->config->familyIdColumn, $familyId)
            ->where($this->config->compromisedAtColumn, null)
            ->values([
                $this->config->compromisedAtColumn => $now,
                $this->config->lockNonceColumn => self::lockNonce(),
            ])
            ->run();

        $database
            ->update($this->config->tokenTable)
            ->where($this->config->familyIdColumn, $familyId)
            ->where($this->config->revokedAtColumn, null)
            ->values([
                $this->config->revokedAtColumn => $now,
            ])
            ->run();
    }

    /** @return array<array-key, mixed>|null */
    private function findToken(
        #[\SensitiveParameter]
        DatabaseInterface $database,
        #[\SensitiveParameter]
        string $tokenHash,
    ): ?array {
        $query = $database->select()->withDriver(
            $database->getDriver(DatabaseInterface::WRITE),
            $database->getPrefix(),
        );

        $row = $query
            ->from($this->config->tokenTable)
            ->where($this->config->tokenHashColumn, $tokenHash)
            ->run()
            ->fetch();

        return is_array($row) ? $row : null;
    }

    /** @return array<array-key, mixed>|null */
    private function findFamily(
        #[\SensitiveParameter]
        DatabaseInterface $database,
        #[\SensitiveParameter]
        string $familyId,
    ): ?array {
        $query = $database->select()->withDriver(
            $database->getDriver(DatabaseInterface::WRITE),
            $database->getPrefix(),
        );

        $row = $query
            ->from($this->config->familyTable)
            ->where($this->config->familyIdColumn, $familyId)
            ->run()
            ->fetch();

        return is_array($row) ? $row : null;
    }

    private static function encodeEvidence(
        AuthenticationEvidence $evidence,
    ): string {
        return json_encode(
            [
                'methods' => $evidence->methods,
                'capabilities' => $evidence->capabilities,
            ],
            JSON_THROW_ON_ERROR,
        );
    }

    private static function decodeEvidence(
        #[\SensitiveParameter]
        string $json,
    ): AuthenticationEvidence {
        $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);

        if (
            !is_array($data)
            || !isset($data['methods'])
            || !is_array($data['methods'])
            || !isset($data['capabilities'])
            || !is_array($data['capabilities'])
        ) {
            throw new \UnexpectedValueException(
                'Persisted refresh authentication evidence is invalid.',
            );
        }

        $methods = array_values(array_filter($data['methods'], 'is_string'));
        $capabilities = array_values(array_filter(
            $data['capabilities'],
            'is_string',
        ));

        if (
            $methods === []
            || count($methods) !== count($data['methods'])
            || count($capabilities) !== count($data['capabilities'])
        ) {
            throw new \UnexpectedValueException(
                'Persisted refresh authentication evidence is invalid.',
            );
        }

        /** @var non-empty-list<string> $methods */
        /** @var list<string> $capabilities */
        return new AuthenticationEvidence($methods, $capabilities);
    }

    private static function lockNonce(): string
    {
        return bin2hex(random_bytes(self::LOCK_NONCE_BYTES));
    }

    private static function hashToken(
        #[\SensitiveParameter]
        string $tokenId,
    ): string {
        return hash('sha256', $tokenId);
    }

    private static function validIdentifier(
        #[\SensitiveParameter]
        string $value,
    ): bool {
        return preg_match('/\A[a-f0-9]{64,128}\z/D', $value) === 1
            && strlen($value) % 2 === 0;
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(
        #[\SensitiveParameter]
        array $row,
        string $key,
    ): string {
        $value = $row[$key] ?? null;

        if (!is_string($value) && !is_int($value)) {
            throw new \UnexpectedValueException(sprintf(
                'Database column "%s" must contain a string-compatible value.',
                $key,
            ));
        }

        return (string) $value;
    }

    /** @param array<array-key, mixed> $row */
    private static function intValue(
        #[\SensitiveParameter]
        array $row,
        string $key,
    ): int {
        $value = $row[$key] ?? null;

        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            throw new \UnexpectedValueException(sprintf(
                'Database column "%s" must contain an integer.',
                $key,
            ));
        }

        return (int) $value;
    }

    /** @param array<array-key, mixed> $row */
    private static function nullableIntValue(
        #[\SensitiveParameter]
        array $row,
        string $key,
    ): ?int {
        if (!array_key_exists($key, $row) || $row[$key] === null) {
            return null;
        }

        return self::intValue($row, $key);
    }

    /** @param array<array-key, mixed> $row */
    private static function uuidValue(
        #[\SensitiveParameter]
        array $row,
        string $key,
    ): UuidInterface {
        try {
            return Uuid::fromString(self::stringValue($row, $key));
        } catch (\InvalidArgumentException $exception) {
            throw new \UnexpectedValueException(
                sprintf('Database column "%s" must contain a valid UUID.', $key),
                previous: $exception,
            );
        }
    }
}

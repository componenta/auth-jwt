<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Jwt\RefreshToken;
use Componenta\Auth\Jwt\RefreshTokenRotationStatus;
use Componenta\Auth\Jwt\Tests\Support\SqliteDatabaseFixture;
use Componenta\Identity\Uuid;
use PHPUnit\Framework\TestCase;

final class RefreshTokenStoreTest extends TestCase
{
    public function testRotationPreservesEvidenceAndReplayCompromisesFamily(): void
    {
        self::requireSqlite();
        $store = new DatabaseRefreshTokenStore(
            SqliteDatabaseFixture::create(),
        );
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $evidence = new AuthenticationEvidence(
            ['webauthn'],
            ['user_verified', 'phishing_resistant'],
        );
        $initial = new RefreshToken(
            id: str_repeat('a', 64),
            subjectId: $subject,
            familyId: str_repeat('b', 64),
            evidence: $evidence,
            expiresAt: 1500,
            familyExpiresAt: 2000,
        );
        $store->storeInitial($initial);

        $context = $store->findActiveContext($initial->id, 1000);
        self::assertNotNull($context);
        self::assertSame($evidence->methods, $context->evidence->methods);

        $rotated = $store->rotateAtomically(
            $initial->id,
            str_repeat('c', 64),
            3000,
            1001,
        );

        self::assertSame(
            RefreshTokenRotationStatus::Rotated,
            $rotated->status,
        );
        self::assertSame(
            $evidence->capabilities,
            $rotated->token?->evidence->capabilities,
        );
        self::assertSame(2000, $rotated->token?->expiresAt);
        self::assertSame(2000, $rotated->token?->familyExpiresAt);

        $replay = $store->rotateAtomically(
            $initial->id,
            str_repeat('d', 64),
            4000,
            1002,
        );

        self::assertSame(
            RefreshTokenRotationStatus::Reused,
            $replay->status,
        );
        self::assertNull(
            $store->findActiveContext(str_repeat('c', 64), 1003),
        );
    }

    public function testExpiredFamilyCannotBeExtendedByRotation(): void
    {
        self::requireSqlite();
        $store = new DatabaseRefreshTokenStore(
            SqliteDatabaseFixture::create(),
        );
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $initial = new RefreshToken(
            id: str_repeat('a', 64),
            subjectId: $subject,
            familyId: str_repeat('b', 64),
            evidence: new AuthenticationEvidence(['password']),
            expiresAt: 1500,
            familyExpiresAt: 1500,
        );
        $store->storeInitial($initial);

        self::assertNull($store->findActiveContext($initial->id, 1500));
        self::assertSame(
            RefreshTokenRotationStatus::Expired,
            $store->rotateAtomically(
                $initial->id,
                str_repeat('c', 64),
                3000,
                1500,
            )->status,
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}

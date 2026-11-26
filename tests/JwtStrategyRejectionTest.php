<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests;

use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\Context;
use Componenta\Auth\Http\Extractor\BearerPayload;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Jwt\Claims;
use Componenta\Auth\Jwt\Denied\InvalidAccessToken;
use Componenta\Auth\Jwt\HmacSigner;
use Componenta\Auth\Jwt\JwtConfig;
use Componenta\Auth\Jwt\JwtEvidence;
use Componenta\Auth\Jwt\JwtStrategy;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class JwtStrategyRejectionTest extends TestCase
{
    private const string SUBJECT = '018f6d5d-3f7a-7a9b-8c2f-123456789abc';

    /** @return iterable<string, array{bool}> */
    public static function unverifiedTokens(): iterable
    {
        yield 'signed with another key' => [false];
        yield 'malformed JWT' => [true];
    }

    #[DataProvider('unverifiedTokens')]
    public function testUnverifiedTokenIsRejectedBeforeIdentityLookup(bool $malformed): void
    {
        $signer = new HmacSigner(str_repeat('s', 32));
        $token = $malformed
            ? 'not-a-jwt'
            : (new HmacSigner(str_repeat('x', 32)))->sign(self::claims());

        self::assertNull($signer->parse($token));
        $this->assertRejectedBeforeIdentityLookup($token, $signer);
    }

    /** @return iterable<string, array{string, string, string}> */
    public static function otherProfiles(): iterable
    {
        yield 'another issuer' => ['https://other.example', 'api', 'at+jwt'];
        yield 'another audience' => ['https://issuer.example', 'another-api', 'at+jwt'];
        yield 'another token type' => ['https://issuer.example', 'api', 'id+jwt'];
    }

    #[DataProvider('otherProfiles')]
    public function testOtherProfileIsRejectedBeforeIdentityLookup(
        string $issuer,
        string $audience,
        string $type,
    ): void {
        $signer = new HmacSigner(str_repeat('s', 32));
        $token = $signer->sign(self::claims($issuer, $audience, $type));

        $this->assertRejectedBeforeIdentityLookup($token, $signer);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function invalidEvidence(): iterable
    {
        yield 'missing methods' => [[JwtEvidence::CAPABILITIES_CLAIM => []]];
        yield 'missing capabilities' => [[JwtEvidence::METHODS_CLAIM => ['password']]];
        yield 'empty methods' => [[
            JwtEvidence::METHODS_CLAIM => [],
            JwtEvidence::CAPABILITIES_CLAIM => [],
        ]];
        yield 'non-array methods' => [[
            JwtEvidence::METHODS_CLAIM => 'password',
            JwtEvidence::CAPABILITIES_CLAIM => [],
        ]];
        yield 'non-string capability' => [[
            JwtEvidence::METHODS_CLAIM => ['password'],
            JwtEvidence::CAPABILITIES_CLAIM => [true],
        ]];
        yield 'invalid method identifier' => [[
            JwtEvidence::METHODS_CLAIM => ['bad method'],
            JwtEvidence::CAPABILITIES_CLAIM => [],
        ]];
    }

    /** @param array<string, mixed> $custom */
    #[DataProvider('invalidEvidence')]
    public function testInvalidEvidenceIsRejectedBeforeIdentityLookup(array $custom): void
    {
        $signer = new HmacSigner(str_repeat('s', 32));
        $token = $signer->sign(self::claims(custom: $custom));

        $this->assertRejectedBeforeIdentityLookup($token, $signer);
    }

    public function testIdentityProviderCannotSubstituteAnotherSubject(): void
    {
        $subject = Uuid::fromString(self::SUBJECT);
        $otherIdentity = new readonly class(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abd'),
        ) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $identities = $this->createMock(IdentityProviderInterface::class);
        $identities->expects(self::once())
            ->method('findByUuid')
            ->with(self::callback(
                static fn(UuidInterface $uuid): bool => $uuid->equals($subject),
            ))
            ->willReturn($otherIdentity);
        $signer = new HmacSigner(str_repeat('s', 32));
        $token = $signer->sign(self::claims());

        $result = (new JwtStrategy(
            $signer,
            $identities,
            self::config(),
            new FrozenClock(1000, 'UTC'),
        ))->attempt(new BearerPayload($token), new Context());

        self::assertDenied($result);
    }

    private function assertRejectedBeforeIdentityLookup(string $token, HmacSigner $signer): void
    {
        $identities = $this->createMock(IdentityProviderInterface::class);
        $identities->expects(self::never())->method('findByUuid');

        $result = (new JwtStrategy(
            $signer,
            $identities,
            self::config(),
            new FrozenClock(1000, 'UTC'),
        ))->attempt(new BearerPayload($token), new Context());

        self::assertDenied($result);
    }

    private static function assertDenied(AuthenticationResult $result): void
    {
        self::assertInstanceOf(InvalidAccessToken::class, $result->subject);
        self::assertNotInstanceOf(IdentityInterface::class, $result->subject);
        self::assertNull($result->evidence);
    }

    private static function config(): JwtConfig
    {
        return new JwtConfig('https://issuer.example', 'api');
    }

    /** @param array<string, mixed>|null $custom */
    private static function claims(
        string $issuer = 'https://issuer.example',
        string $audience = 'api',
        string $type = 'at+jwt',
        ?array $custom = null,
    ): Claims {
        return new Claims(
            subject: self::SUBJECT,
            issuedAt: 900,
            expiresAt: 1500,
            issuer: $issuer,
            audience: $audience,
            type: $type,
            custom: $custom ?? [
                JwtEvidence::METHODS_CLAIM => ['password'],
                JwtEvidence::CAPABILITIES_CLAIM => [],
            ],
        );
    }
}

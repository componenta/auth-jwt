<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Context;
use Componenta\Auth\Http\Extractor\BearerPayload;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Jwt\AccessTokenIssuer;
use Componenta\Auth\Jwt\HmacSigner;
use Componenta\Auth\Jwt\JwtConfig;
use Componenta\Auth\Jwt\JwtStrategy;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;

final class JwtStrategyTest extends TestCase
{
    public function testAccessTokenRoundTripsAuthenticationEvidence(): void
    {
        $clock = new FrozenClock(1000, 'UTC');
        $config = new JwtConfig(
            issuer: 'https://issuer.example',
            audience: 'api',
        );
        $signer = new HmacSigner(str_repeat('s', 32));
        $identity = new JwtIdentityFixture();
        $evidence = new AuthenticationEvidence(
            ['webauthn'],
            ['user_verified', 'phishing_resistant'],
        );
        $token = (new AccessTokenIssuer($signer, $config, $clock))
            ->issue($identity, $evidence);
        $provider = $this->createStub(IdentityProviderInterface::class);
        $provider->method('findByUuid')->willReturn($identity);

        $result = (new JwtStrategy(
            $signer,
            $provider,
            $config,
            $clock,
        ))->attempt(new BearerPayload($token), new Context());

        self::assertSame($identity, $result->subject);
        self::assertSame($evidence->methods, $result->evidence?->methods);
        self::assertSame(
            $evidence->capabilities,
            $result->evidence?->capabilities,
        );
    }
}

final class JwtIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}

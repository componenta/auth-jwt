<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Jwt\AccessTokenIssuer;
use Componenta\Auth\Jwt\DatabaseRefreshTokenStore;
use Componenta\Auth\Jwt\HmacSigner;
use Componenta\Auth\Jwt\JwtConfig;
use Componenta\Auth\Jwt\RefreshHandler;
use Componenta\Auth\Jwt\RefreshTokenGenerator;
use Componenta\Auth\Jwt\RefreshTokenManager;
use Componenta\Auth\Jwt\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class RefreshHandlerFailureTest extends TestCase
{
    public function testExceptionFromFinalGuardRevokesTheUnpublishedSuccessor(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock(1000, 'UTC');
        $config = new JwtConfig(issuer: 'https://issuer.example', audience: 'api');
        $store = new DatabaseRefreshTokenStore($database);
        $tokens = new RefreshTokenManager($store, new RefreshTokenGenerator(), $config, $clock);
        $identity = new class((new UuidFactory())->generate()) implements IdentityInterface {
            public function __construct(public readonly UuidInterface $uuid) {}
        };
        $identities = $this->createStub(IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);
        $guard = new class implements AuthenticationGuardInterface {
            public int $calls = 0;
            public function check(IdentityInterface $identity, AuthenticationEvidence $evidence): ?DeniedReasonInterface
            {
                if (++$this->calls === 2) {
                    throw new \RuntimeException('The final admission check failed.');
                }
                return null;
            }
        };
        $responses = new Psr17Factory();
        $denials = $this->createStub(DeniedResponseFactoryInterface::class);
        $initial = $tokens->issue($identity->uuid, new AuthenticationEvidence(['password']));
        $handler = new RefreshHandler($tokens, $identities, new AccessTokenIssuer(new HmacSigner(str_repeat('s', 32)), $config, $clock), $config, $denials, $responses, $guard);

        try {
            $handler->handle((new ServerRequest('POST', 'https://issuer.example/refresh'))->withParsedBody(['refresh_token' => $initial->id]));
            self::fail('The guard failure must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The final admission check failed.', $exception->getMessage());
        }

        self::assertSame(2, $guard->calls);
        self::assertSame(0, $database->select()->from('auth_refresh_tokens')->where('revoked_at', null)->where('consumed_at', null)->count(), 'No unpublished refresh credential may remain active.');
    }
}

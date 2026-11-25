<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
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
use Componenta\Auth\Jwt\TokenPairResponse;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamInterface;

final class TokenResponsePublicationTest extends TestCase
{
    /** @return iterable<string, array{string, string}> */
    public static function publications(): iterable
    {
        foreach (['issue', 'refresh'] as $operation) {
            foreach (['complete', 'partial', 'stalled', 'throwing'] as $stream) {
                yield $operation . '-' . $stream => [$operation, $stream];
            }
        }
    }

    #[DataProvider('publications')]
    public function testCompletePublicationOrRevocation(string $operation, string $mode): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock(1000, 'UTC');
        $config = new JwtConfig(issuer: 'https://issuer.example', audience: 'api');
        $store = new DatabaseRefreshTokenStore($database);
        $tokens = new RefreshTokenManager($store, new RefreshTokenGenerator(), $config, $clock);
        $identity = new readonly class((new UuidFactory())->generate()) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $evidence = new AuthenticationEvidence(['password']);
        $access = new AccessTokenIssuer(new HmacSigner(str_repeat('s', 32)), $config, $clock);
        $sink = new class {
            public string $body = '';
            public int $calls = 0;
        };
        $failure = new \RuntimeException('Synthetic response stream failed.');
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(
            static function (string $bytes) use ($mode, $sink, $failure): int {
                if (++$sink->calls > 1) {
                    if ($mode === 'stalled') {
                        return 0;
                    }
                    if ($mode === 'throwing') {
                        throw $failure;
                    }
                }
                $written = $mode === 'complete' ? strlen($bytes) : min(7, strlen($bytes));
                $sink->body .= substr($bytes, 0, $written);

                return $written;
            },
        );
        $stream->method('__toString')->willReturnCallback(static fn(): string => $sink->body);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn(new Response(200, [], $stream));

        if ($operation === 'issue') {
            $publisher = new TokenPairResponse($access, $tokens, $config, $responses);
            $publish = static fn() => $publisher->create($identity, $evidence);
        } else {
            $identities = $this->createStub(IdentityProviderInterface::class);
            $identities->method('findByUuid')->willReturn($identity);
            $guard = $this->createStub(AuthenticationGuardInterface::class);
            $guard->method('check')->willReturn(null);
            $initial = $tokens->issue($identity->uuid, $evidence);
            $handler = new RefreshHandler(
                $tokens,
                $identities,
                $access,
                $config,
                $this->createStub(DeniedResponseFactoryInterface::class),
                $responses,
                $guard,
            );
            $request = (new ServerRequest('POST', 'https://issuer.example/refresh'))
                ->withParsedBody(['refresh_token' => $initial->id]);
            $publish = static fn() => $handler->handle($request);
        }

        if (in_array($mode, ['stalled', 'throwing'], true)) {
            $failureObserved = null;
            try {
                $publish();
            } catch (\RuntimeException $exception) {
                $failureObserved = $exception;
            }
            self::assertInstanceOf(\RuntimeException::class, $failureObserved,
                'A truncated token response must not be published as success.');
            if ($mode === 'throwing') {
                self::assertSame($failure, $failureObserved);
            } else {
                self::assertStringContainsString('token response', $failureObserved->getMessage());
            }
            self::assertSame(0, $database->select()->from('auth_refresh_tokens')
                ->where('revoked_at', null)->where('consumed_at', null)->count());

            return;
        }

        $response = $publish();
        self::assertJson((string) $response->getBody());
        $body = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('Bearer', $body['token_type']);
        self::assertNotNull($tokens->findActiveContext($body['refresh_token']));
        self::assertSame(1, $database->select()->from('auth_refresh_tokens')
            ->where('revoked_at', null)->where('consumed_at', null)->count());
        self::assertStringContainsString('no-store', $response->getHeaderLine('Cache-Control'));
    }
}

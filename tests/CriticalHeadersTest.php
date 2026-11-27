<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests;

use Componenta\Auth\Context;
use Componenta\Auth\Http\Extractor\BearerPayload;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Jwt\Denied\InvalidAccessToken;
use Componenta\Auth\Jwt\HmacSigner;
use Componenta\Auth\Jwt\JwtConfig;
use Componenta\Auth\Jwt\JwtStrategy;
use Componenta\Auth\Jwt\RsaSigner;
use Componenta\Auth\Jwt\SignerInterface;
use Componenta\Clock\FrozenClock;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CriticalHeadersTest extends TestCase
{
    private const string SUBJECT = '018f6d5d-3f7a-7a9b-8c2f-123456789abc';
    private const string EXTENSION = 'urn:componenta:test:required';

    /** @var array{string, string}|null */
    private static ?array $rsaKeys = null;

    /** @return iterable<string, array{string, array<string, mixed>, bool}> */
    public static function headers(): iterable
    {
        foreach (['HS256', 'RS256'] as $algorithm) {
            yield $algorithm . ' ordinary token' => [$algorithm, [], true];
            yield $algorithm . ' optional unknown extension' => [
                $algorithm, [self::EXTENSION => true], true,
            ];
            yield $algorithm . ' unsupported critical extension' => [
                $algorithm, ['crit' => [self::EXTENSION], self::EXTENSION => true], false,
            ];
            yield $algorithm . ' empty critical list' => [$algorithm, ['crit' => []], false];
            yield $algorithm . ' null critical list' => [$algorithm, ['crit' => null], false];
            yield $algorithm . ' non-array critical list' => [
                $algorithm, ['crit' => self::EXTENSION, self::EXTENSION => true], false,
            ];
        }
    }

    /** @param array<string, mixed> $headers */
    #[DataProvider('headers')]
    public function testSignersRequireSupportedCriticalHeaderSemantics(
        string $algorithm,
        array $headers,
        bool $accepted,
    ): void {
        [$signer, $token] = self::signedToken($algorithm, $headers);

        $claims = $signer->parse($token);

        if (!$accepted) {
            self::assertNull($claims, 'A valid signature does not authorize ignoring a critical extension.');

            return;
        }

        self::assertNotNull($claims);
        self::assertSame(self::SUBJECT, $claims->subject);
        self::assertSame(1000, $claims->issuedAt);
        self::assertSame(1100, $claims->expiresAt);
    }

    public function testUnsupportedCriticalExtensionIsRejectedBeforeIdentityLookup(): void
    {
        [$signer, $token] = self::signedToken('HS256', [
            'crit' => [self::EXTENSION],
            self::EXTENSION => true,
        ]);
        $identities = $this->createMock(IdentityProviderInterface::class);
        $identities->expects(self::never())->method('findByUuid');
        $strategy = new JwtStrategy(
            $signer,
            $identities,
            new JwtConfig('https://issuer.example', 'api'),
            new FrozenClock(1000, 'UTC'),
        );

        $result = $strategy->attempt(new BearerPayload($token), new Context());

        self::assertInstanceOf(InvalidAccessToken::class, $result->subject);
        self::assertNull($result->evidence);
    }

    /**
     * Build independently signed compact JWS fixtures, including headers that
     * the package's Claims-only issuer intentionally does not expose.
     *
     * @param array<string, mixed> $extraHeaders
     * @return array{SignerInterface, string}
     */
    private static function signedToken(string $algorithm, array $extraHeaders): array
    {
        $headers = ['alg' => $algorithm, 'typ' => 'at+jwt', ...$extraHeaders];
        $claims = [
            'sub' => self::SUBJECT,
            'iat' => 1000,
            'exp' => 1100,
            'iss' => 'https://issuer.example',
            'aud' => 'api',
            'componenta_auth_methods' => ['password'],
            'componenta_auth_capabilities' => [],
        ];
        $input = self::base64Url(json_encode($headers, JSON_THROW_ON_ERROR))
            . '.' . self::base64Url(json_encode($claims, JSON_THROW_ON_ERROR));

        if ($algorithm === 'HS256') {
            $secret = str_repeat('test-jwt-key', 4);
            $signer = new HmacSigner($secret);
            $signature = hash_hmac('sha256', $input, $secret, true);
        } else {
            [$public, $private] = self::rsaKeys();
            $signer = new RsaSigner($public);
            $signature = '';

            if (!openssl_sign($input, $signature, $private, OPENSSL_ALGO_SHA256)) {
                throw new \RuntimeException('Could not sign the RSA test fixture.');
            }
        }

        return [$signer, $input . '.' . self::base64Url($signature)];
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** @return array{string, string} */
    private static function rsaKeys(): array
    {
        if (self::$rsaKeys !== null) {
            return self::$rsaKeys;
        }

        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if (!$key instanceof \OpenSSLAsymmetricKey) {
            throw new \RuntimeException('Could not generate the RSA test key.');
        }

        $private = '';
        if (!openssl_pkey_export($key, $private) || $private === '') {
            throw new \RuntimeException('Could not export the RSA test key.');
        }

        $details = openssl_pkey_get_details($key);
        $public = is_array($details) ? ($details['key'] ?? null) : null;

        if (!is_string($public) || $public === '') {
            throw new \RuntimeException('Could not read the RSA test public key.');
        }

        return self::$rsaKeys = [$public, $private];
    }
}

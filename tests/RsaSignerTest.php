<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests;

use Componenta\Auth\Jwt\RsaSigner;
use PHPUnit\Framework\TestCase;

final class RsaSignerTest extends TestCase
{
    public function testRejectsWeakRsaKey(): void
    {
        [$public, $private] = self::keyPair(1024);

        $this->expectException(\InvalidArgumentException::class);

        new RsaSigner($public, $private);
    }

    public function testRejectsMismatchedRsaKeyPair(): void
    {
        [, $private] = self::keyPair(2048);
        [$otherPublic] = self::keyPair(2048);

        $this->expectException(\InvalidArgumentException::class);

        new RsaSigner($otherPublic, $private);
    }

    public function testAcceptsMatchingStrongRsaKeyPair(): void
    {
        [$public, $private] = self::keyPair(2048);

        self::assertInstanceOf(
            RsaSigner::class,
            new RsaSigner($public, $private),
        );
    }

    /** @return array{non-empty-string, non-empty-string} */
    private static function keyPair(int $bits): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $bits,
        ]);

        if (!$key instanceof \OpenSSLAsymmetricKey) {
            throw new \RuntimeException('Could not generate RSA key.');
        }

        $private = '';
        if (!openssl_pkey_export($key, $private) || $private === '') {
            throw new \RuntimeException('Could not export RSA private key.');
        }

        $details = openssl_pkey_get_details($key);
        $public = is_array($details) ? ($details['key'] ?? null) : null;

        if (!is_string($public) || $public === '') {
            throw new \RuntimeException('Could not export RSA public key.');
        }

        /** @var non-empty-string $public */
        /** @var non-empty-string $private */
        return [$public, $private];
    }
}

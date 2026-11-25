<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests;

use Componenta\Auth\Jwt\HmacSigner;
use PHPUnit\Framework\TestCase;

final class SignerRedactionTest extends TestCase
{
    public function testHmacDebugOutputDoesNotExposeSigningKey(): void
    {
        $secret = str_repeat('private-test-key', 3);
        $signer = new HmacSigner($secret);

        ob_start();
        try {
            var_dump($signer);
            $debug = ob_get_contents();
        } finally {
            ob_end_clean();
        }

        self::assertIsString($debug);
        self::assertStringNotContainsString($secret, $debug);
    }
}

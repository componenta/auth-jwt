<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests;

use Componenta\Auth\Jwt\Claims;
use Componenta\Auth\Jwt\HmacSigner;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClaimsTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function numericNames(): iterable
    {
        yield 'zero' => ['0'];
        yield 'positive integer' => ['42'];
    }

    #[DataProvider('numericNames')]
    public function testNumericClaimNamesRoundTripThroughHmac(string $name): void
    {
        $claims = new Claims('subject', 1000, 1100, 'issuer', 'audience', custom: [$name => 'value']);
        $signer = new HmacSigner(str_repeat('test', 8));

        $parsed = $signer->parse($signer->sign($claims));

        self::assertNotNull($parsed);
        self::assertSame('value', $parsed->custom[$name]);
    }
}

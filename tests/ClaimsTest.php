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
    public function testCustomClaimMapDetachesDirectCallerReferences(): void
    {
        $scope = 'read';
        $claims = new Claims('subject', 1000, 1100, 'issuer', 'audience', custom: ['scope' => &$scope]);
        $scope = 'write';
        $exported = $claims->custom;
        $exported['scope'] = 'admin';
        $signer = new HmacSigner(str_repeat('test', 8));

        $parsed = $signer->parse($signer->sign($claims));

        self::assertSame('read', $claims->custom['scope']);
        self::assertNotNull($parsed);
        self::assertSame('read', $parsed->custom['scope']);
    }

}

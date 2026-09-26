<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Psr\Http\Message\ResponseInterface;

final class TokenResponseHeaders
{
    private function __construct() {}

    public static function apply(
        #[\SensitiveParameter]
        ResponseInterface $response,
    ): ResponseInterface {
        return self::noStore($response)
            ->withHeader('Content-Type', 'application/json');
    }

    public static function applyEmpty(
        #[\SensitiveParameter]
        ResponseInterface $response,
    ): ResponseInterface {
        return self::noStore($response)
            ->withoutHeader('Content-Type');
    }

    private static function noStore(
        #[\SensitiveParameter]
        ResponseInterface $response,
    ): ResponseInterface {
        return $response
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}

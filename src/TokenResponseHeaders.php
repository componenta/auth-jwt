<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\Http\CredentialResponseHeaders;
use Psr\Http\Message\ResponseInterface;

final class TokenResponseHeaders
{
    private function __construct() {}

    public static function apply(
        #[\SensitiveParameter]
        ResponseInterface $response,
    ): ResponseInterface {
        return CredentialResponseHeaders::apply($response)
            ->withHeader('Content-Type', 'application/json');
    }

    public static function applyEmpty(
        #[\SensitiveParameter]
        ResponseInterface $response,
    ): ResponseInterface {
        return CredentialResponseHeaders::apply($response)
            ->withoutHeader('Content-Type');
    }
}

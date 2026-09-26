<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

final class RefreshTokenGenerator
{
    public function generate(): string
    {
        return bin2hex(random_bytes(32));
    }
}

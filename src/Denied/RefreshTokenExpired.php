<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Denied;

use Componenta\Auth\DeniedReasonInterface;

final class RefreshTokenExpired implements DeniedReasonInterface
{
    public string $code { get => 'refresh_token_expired'; }

    /** @var array<string, mixed> */
    public array $attributes { get => []; }
}

<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Denied;

use Componenta\Auth\DeniedReasonInterface;

final class InvalidAccessToken implements DeniedReasonInterface
{
    public string $code { get => 'invalid_access_token'; }

    /** @var array<string, mixed> */
    public array $attributes { get => []; }
}

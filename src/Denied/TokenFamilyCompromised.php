<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Denied;

use Componenta\Auth\DeniedReasonInterface;

final class TokenFamilyCompromised implements DeniedReasonInterface
{
    public string $code { get => 'token_family_compromised'; }

    /** @var array<string, mixed> */
    public array $attributes { get => []; }
}

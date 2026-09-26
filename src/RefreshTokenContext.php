<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Identity\UuidInterface;

final readonly class RefreshTokenContext
{
    public function __construct(
        public UuidInterface $subjectId,
        public AuthenticationEvidence $evidence,
    ) {}
}

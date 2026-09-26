<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

final readonly class RefreshTokenRotationResult
{
    private function __construct(
        public RefreshTokenRotationStatus $status,
        public ?RefreshToken $token = null,
    ) {}

    public static function rotated(RefreshToken $token): self
    {
        return new self(RefreshTokenRotationStatus::Rotated, $token);
    }

    public static function invalid(): self
    {
        return new self(RefreshTokenRotationStatus::Invalid);
    }

    public static function expired(): self
    {
        return new self(RefreshTokenRotationStatus::Expired);
    }

    public static function reused(): self
    {
        return new self(RefreshTokenRotationStatus::Reused);
    }
}

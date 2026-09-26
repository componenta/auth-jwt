<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use JsonException;
use Lcobucci\JWT\Token\RegisteredClaims;

final readonly class Claims
{
    /** @param array<string, mixed> $custom */
    public function __construct(
        public string $subject,
        public int $issuedAt,
        public int $expiresAt,
        public string $issuer,
        public string $audience,
        public string $type = 'at+jwt',
        public ?int $notBefore = null,
        public array $custom = [],
    ) {
        foreach ([
            'subject' => $this->subject,
            'issuer' => $this->issuer,
            'audience' => $this->audience,
            'type' => $this->type,
        ] as $name => $value) {
            if (
                $value === ''
                || strlen($value) > 2048
                || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
            ) {
                throw new \InvalidArgumentException(sprintf(
                    'JWT %s must be a bounded non-empty string.',
                    $name,
                ));
            }
        }

        if ($this->expiresAt <= $this->issuedAt) {
            throw new \InvalidArgumentException('JWT expiration must be later than issued-at.');
        }

        if ($this->notBefore !== null && $this->notBefore >= $this->expiresAt) {
            throw new \InvalidArgumentException(
                'JWT not-before time must precede expiration.',
            );
        }


        try {
            $customJson = json_encode($this->custom, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new \InvalidArgumentException(
                'Custom JWT claims must be JSON-serializable.',
                previous: $exception,
            );
        }

        if (strlen($customJson) > 16384) {
            throw new \InvalidArgumentException(
                'Custom JWT claims must not exceed 16384 JSON bytes.',
            );
        }

        foreach ($this->custom as $name => $_) {
            if (
                $name === ''
                || strlen($name) > 128
                || preg_match('/[\x00-\x1F\x7F]/', $name) === 1
                || in_array($name, RegisteredClaims::ALL, true)
            ) {
                throw new \InvalidArgumentException(sprintf(
                    'Custom claim "%s" is invalid or reserved.',
                    $name,
                ));
            }
        }
    }
}

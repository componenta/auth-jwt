<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\AuthenticationEvidence;

final class JwtEvidence
{
    public const string METHODS_CLAIM = 'componenta_auth_methods';
    public const string CAPABILITIES_CLAIM = 'componenta_auth_capabilities';

    private function __construct() {}

    /**
     * @param array<string, mixed> $custom
     * @return array<string, mixed>
     */
    public static function inject(
        array $custom,
        AuthenticationEvidence $evidence,
    ): array {
        if (
            array_key_exists(self::METHODS_CLAIM, $custom)
            || array_key_exists(self::CAPABILITIES_CLAIM, $custom)
        ) {
            throw new \InvalidArgumentException(
                'JWT authentication-evidence claims are reserved.',
            );
        }

        $custom[self::METHODS_CLAIM] = $evidence->methods;
        $custom[self::CAPABILITIES_CLAIM] = $evidence->capabilities;

        return $custom;
    }

    public static function extract(Claims $claims): ?AuthenticationEvidence
    {
        $methods = $claims->custom[self::METHODS_CLAIM] ?? null;
        $capabilities = $claims->custom[self::CAPABILITIES_CLAIM] ?? null;

        if (!is_array($methods) || !is_array($capabilities)) {
            return null;
        }

        $validMethods = array_values(array_filter($methods, 'is_string'));
        $validCapabilities = array_values(array_filter(
            $capabilities,
            'is_string',
        ));

        if (
            $validMethods === []
            || count($validMethods) !== count($methods)
            || count($validCapabilities) !== count($capabilities)
        ) {
            return null;
        }

        try {
            /** @var non-empty-list<string> $validMethods */
            /** @var list<string> $validCapabilities */
            return new AuthenticationEvidence(
                $validMethods,
                $validCapabilities,
            );
        } catch (\InvalidArgumentException) {
            return null;
        }
    }
}

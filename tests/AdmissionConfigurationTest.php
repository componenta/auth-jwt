<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests;

use Componenta\Auth\Jwt\RefreshHandler;
use Componenta\Auth\AuthenticationGuardInterface;
use PHPUnit\Framework\TestCase;

final class AdmissionConfigurationTest extends TestCase
{
    public function testTheSharedAdmissionGuardIsRequiredAndCannotBeSilentlyOmitted(): void
    {
        $parameters = (new \ReflectionMethod(RefreshHandler::class, '__construct'))->getParameters();
        $guard = $parameters[array_key_last($parameters)];
        self::assertSame(AuthenticationGuardInterface::class, (string) $guard->getType());
        self::assertFalse($guard->isOptional(), 'Credential issuance requires an explicit shared admission guard.');
        self::assertFalse($guard->isVariadic());
    }
}

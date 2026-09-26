<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class RevokeHandler implements RequestHandlerInterface
{
    public function __construct(
        private RefreshTokenManager $refreshTokens,
        private ResponseFactoryInterface $responses,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $body = $request->getParsedBody();
        $tokenId = is_array($body) ? ($body['refresh_token'] ?? null) : null;

        if (is_string($tokenId)) {
            $this->refreshTokens->revoke($tokenId);
        }

        return TokenResponseHeaders::applyEmpty(
            $this->responses->createResponse(200),
        );
    }
}

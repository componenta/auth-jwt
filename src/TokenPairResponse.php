<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

final readonly class TokenPairResponse
{
    public function __construct(
        private AccessTokenIssuer $accessTokens,
        private RefreshTokenManager $refreshTokens,
        private JwtConfig $config,
        private ResponseFactoryInterface $responses,
    ) {}

    public function create(
        IdentityInterface $identity,
        AuthenticationEvidence $evidence,
    ): ResponseInterface {
        $accessToken = $this->accessTokens->issue($identity, $evidence);
        $response = $this->responses->createResponse(200);
        $refresh = $this->refreshTokens->issue($identity->uuid, $evidence);

        try {
            $response->getBody()->write(json_encode([
                'access_token' => $accessToken,
                'refresh_token' => $refresh->id,
                'token_type' => 'Bearer',
                'expires_in' => $this->config->accessTtl,
            ], JSON_THROW_ON_ERROR));

            return TokenResponseHeaders::apply($response);
        } catch (\Throwable $exception) {
            $this->refreshTokens->revoke($refresh->id);
            throw $exception;
        }
    }
}

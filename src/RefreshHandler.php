<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Jwt\Denied\InvalidRefreshToken;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class RefreshHandler implements RequestHandlerInterface
{
    public function __construct(
        private RefreshTokenManager $refreshTokens,
        private IdentityProviderInterface $identities,
        private AccessTokenIssuer $accessTokens,
        private JwtConfig $config,
        private DeniedResponseFactoryInterface $deniedResponses,
        private ResponseFactoryInterface $responses,
        private AuthenticationGuardInterface $guard,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $body = $request->getParsedBody();
        $tokenId = is_array($body) ? ($body['refresh_token'] ?? null) : null;

        if (
            !is_string($tokenId)
            || !RefreshToken::validIdentifier($tokenId)
        ) {
            return $this->invalid();
        }

        $context = $this->refreshTokens->findActiveContext($tokenId);

        if ($context === null) {
            $result = $this->refreshTokens->rotate($tokenId);

            if ($result instanceof DeniedReasonInterface) {
                return TokenResponseHeaders::apply(
                    $this->deniedResponses->create($result),
                );
            }

            $this->refreshTokens->revoke($result->id);

            return $this->invalid();
        }

        $identity = $this->identities->findByUuid($context->subjectId);

        if (
            $identity === null
            || !$identity->uuid->equals($context->subjectId)
        ) {
            $this->refreshTokens->revoke($tokenId);

            return $this->invalid();
        }

        $denial = $this->guard->check($identity, $context->evidence);

        if ($denial !== null) {
            $this->refreshTokens->revoke($tokenId);

            return TokenResponseHeaders::apply(
                $this->deniedResponses->create($denial),
            );
        }

        $accessToken = $this->accessTokens->issue(
            $identity,
            $context->evidence,
        );
        $response = $this->responses->createResponse(200);
        $rotated = $this->refreshTokens->rotate($tokenId);

        if ($rotated instanceof DeniedReasonInterface) {
            return TokenResponseHeaders::apply(
                $this->deniedResponses->create($rotated),
            );
        }

        // Every operation after rotation belongs to the compensation scope,
        // including identity/guard checks and denial-response construction.
        try {
            if (
                !$rotated->subjectId->equals($context->subjectId)
                || $rotated->evidence->methods !== $context->evidence->methods
                || $rotated->evidence->capabilities
                    !== $context->evidence->capabilities
            ) {
                $this->refreshTokens->revoke($rotated->id);

                return $this->invalid();
            }

            $currentIdentity = $this->identities->findByUuid(
                $rotated->subjectId,
            );

            if (
                $currentIdentity === null
                || !$currentIdentity->uuid->equals($rotated->subjectId)
            ) {
                $this->refreshTokens->revoke($rotated->id);

                return $this->invalid();
            }

            $denial = $this->guard->check($currentIdentity, $rotated->evidence);

            if ($denial !== null) {
                $this->refreshTokens->revoke($rotated->id);

                return TokenResponseHeaders::apply(
                    $this->deniedResponses->create($denial),
                );
            }

            $response->getBody()->write(json_encode([
                'access_token' => $accessToken,
                'refresh_token' => $rotated->id,
                'token_type' => 'Bearer',
                'expires_in' => $this->config->accessTtl,
            ], JSON_THROW_ON_ERROR));

            return TokenResponseHeaders::apply($response);
        } catch (\Throwable $exception) {
            $this->refreshTokens->revoke($rotated->id);
            throw $exception;
        }
    }

    private function invalid(): ResponseInterface
    {
        return TokenResponseHeaders::apply(
            $this->deniedResponses->create(new InvalidRefreshToken()),
        );
    }
}

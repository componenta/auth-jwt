<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Componenta\Auth\Http\BearerCredential;
use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

final readonly class RsaSigner implements SignerInterface
{
    private Configuration $configuration;
    private bool $canSign;

    public function __construct(
        string $publicKey,
        #[\SensitiveParameter]
        ?string $privateKey = null,
        #[\SensitiveParameter]
        string $passphrase = '',
        string $algorithm = 'RS256',
    ) {
        if ($publicKey === '') {
            throw new \InvalidArgumentException('Public key must not be empty.');
        }

        $signer = self::resolveSigner($algorithm);
        $publicDetails = self::publicKeyDetails($publicKey);

        if ($privateKey !== null) {
            $privateDetails = self::privateKeyDetails(
                $privateKey,
                $passphrase,
            );
            self::assertMatchingKeyPair(
                $publicDetails,
                $privateDetails,
            );
        }

        $verificationKey = self::resolveKey($publicKey);
        $signingKey = $privateKey !== null
            ? self::resolveKey($privateKey, $passphrase)
            : $verificationKey;
        $this->configuration = Configuration::forAsymmetricSigner(
            $signer,
            $signingKey,
            $verificationKey,
        );
        $this->canSign = $privateKey !== null;
    }

    #[\Override]
    public function sign(Claims $claims): string
    {
        if (!$this->canSign) {
            throw new \LogicException('Cannot sign without a private key.');
        }

        /** @var non-empty-string $subject */
        $subject = $claims->subject;
        /** @var non-empty-string $issuer */
        $issuer = $claims->issuer;
        /** @var non-empty-string $audience */
        $audience = $claims->audience;

        $builder = $this->configuration->builder()
            ->withHeader('typ', $claims->type)
            ->relatedTo($subject)
            ->issuedBy($issuer)
            ->permittedFor($audience)
            ->issuedAt(new DateTimeImmutable('@' . $claims->issuedAt))
            ->expiresAt(new DateTimeImmutable('@' . $claims->expiresAt));

        if ($claims->notBefore !== null) {
            $builder = $builder->canOnlyBeUsedAfter(
                new DateTimeImmutable('@' . $claims->notBefore),
            );
        }

        foreach ($claims->custom as $name => $value) {
            if ($name === '' || in_array($name, RegisteredClaims::ALL, true)) {
                throw new \InvalidArgumentException(sprintf(
                    'Custom claim "%s" cannot replace a registered claim.',
                    $name,
                ));
            }

            /** @var non-empty-string $name */
            $builder = $builder->withClaim($name, $value);
        }

        $token = $builder
            ->getToken($this->configuration->signer(), $this->configuration->signingKey())
            ->toString();
        BearerCredential::assertValid($token);

        return $token;
    }

    #[\Override]
    public function parse(
        #[\SensitiveParameter]
        string $token,
    ): ?Claims {
        if (!BearerCredential::isValid($token)) {
            return null;
        }

        /** @var non-empty-string $token */
        try {
            $parsed = $this->configuration->parser()->parse($token);

            if (!$parsed instanceof UnencryptedToken) {
                return null;
            }

            (new SignedWith(
                $this->configuration->signer(),
                $this->configuration->verificationKey(),
            ))->assert($parsed);

            return $this->extractClaims($parsed);
        } catch (\Throwable) {
            return null;
        }
    }

    private function extractClaims(UnencryptedToken $token): ?Claims
    {
        $claims = $token->claims();
        $subject = $claims->get(RegisteredClaims::SUBJECT);
        $issuedAt = $claims->get(RegisteredClaims::ISSUED_AT);
        $expiresAt = $claims->get(RegisteredClaims::EXPIRATION_TIME);
        $issuer = $claims->get(RegisteredClaims::ISSUER);
        $audience = $claims->get(RegisteredClaims::AUDIENCE);
        $notBefore = $claims->get(RegisteredClaims::NOT_BEFORE);
        $type = $token->headers()->get('typ');

        if (
            !is_string($subject) || $subject === ''
            || !$issuedAt instanceof DateTimeImmutable
            || !$expiresAt instanceof DateTimeImmutable
            || !is_string($issuer) || $issuer === ''
            || !is_array($audience) || count($audience) !== 1
            || !is_string($audience[0] ?? null) || $audience[0] === ''
            || ($notBefore !== null && !$notBefore instanceof DateTimeImmutable)
            || !is_string($type) || $type === ''
        ) {
            return null;
        }

        $custom = [];
        foreach ($claims->all() as $name => $value) {
            if (!in_array($name, RegisteredClaims::ALL, true)) {
                $custom[$name] = $value;
            }
        }

        try {
            return new Claims(
                subject: $subject,
                issuedAt: $issuedAt->getTimestamp(),
                expiresAt: $expiresAt->getTimestamp(),
                issuer: $issuer,
                audience: $audience[0],
                type: $type,
                notBefore: $notBefore?->getTimestamp(),
                custom: $custom,
            );
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function publicKeyDetails(string $key): array
    {
        $resource = @openssl_pkey_get_public($key);

        if (!$resource instanceof \OpenSSLAsymmetricKey) {
            throw new \InvalidArgumentException(
                'RSA public key is invalid.',
            );
        }

        return self::rsaDetails($resource, 'public');
    }

    /**
     * @return array<string, mixed>
     */
    private static function privateKeyDetails(
        #[\SensitiveParameter]
        string $key,
        #[\SensitiveParameter]
        string $passphrase,
    ): array {
        $resource = @openssl_pkey_get_private($key, $passphrase);

        if (!$resource instanceof \OpenSSLAsymmetricKey) {
            throw new \InvalidArgumentException(
                'RSA private key is invalid or the passphrase is incorrect.',
            );
        }

        return self::rsaDetails($resource, 'private');
    }

    /**
     * @return array<string, mixed>
     */
    private static function rsaDetails(
        \OpenSSLAsymmetricKey $key,
        string $kind,
    ): array {
        $details = openssl_pkey_get_details($key);

        if (
            !is_array($details)
            || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA
            || !is_int($details['bits'] ?? null)
            || $details['bits'] < 2048
            || !is_array($details['rsa'] ?? null)
            || !is_string($details['rsa']['n'] ?? null)
            || !is_string($details['rsa']['e'] ?? null)
        ) {
            throw new \InvalidArgumentException(sprintf(
                'RSA %s key must be an RSA key of at least 2048 bits.',
                $kind,
            ));
        }

        return $details;
    }

    /**
     * @param array<string, mixed> $public
     * @param array<string, mixed> $private
     */
    private static function assertMatchingKeyPair(
        array $public,
        array $private,
    ): void {
        $publicRsa = $public['rsa'];
        $privateRsa = $private['rsa'];

        if (
            !is_array($publicRsa)
            || !is_array($privateRsa)
            || !is_string($publicRsa['n'] ?? null)
            || !is_string($publicRsa['e'] ?? null)
            || !is_string($privateRsa['n'] ?? null)
            || !is_string($privateRsa['e'] ?? null)
            || !hash_equals($publicRsa['n'], $privateRsa['n'])
            || !hash_equals($publicRsa['e'], $privateRsa['e'])
        ) {
            throw new \InvalidArgumentException(
                'RSA public and private keys do not form a matching key pair.',
            );
        }
    }

    private static function resolveKey(
        #[\SensitiveParameter]
        string $key,
        #[\SensitiveParameter]
        string $passphrase = '',
    ): InMemory {
        if ($key === '') {
            throw new \InvalidArgumentException('RSA key must not be empty.');
        }

        /** @var non-empty-string $key */
        return str_starts_with($key, 'file://')
            ? InMemory::file($key, $passphrase)
            : InMemory::plainText($key, $passphrase);
    }

    private static function resolveSigner(string $algorithm): Rsa
    {
        return match ($algorithm) {
            'RS256' => new Rsa\Sha256(),
            'RS384' => new Rsa\Sha384(),
            'RS512' => new Rsa\Sha512(),
            default => throw new \InvalidArgumentException(sprintf(
                'Unsupported RSA algorithm: %s. Supported: RS256, RS384, RS512',
                $algorithm,
            )),
        };
    }
}

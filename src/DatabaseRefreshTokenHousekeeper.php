<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt;

use Cycle\Database\DatabaseInterface;

/** Bounded cleanup for expired refresh-token history and terminal families. */
final readonly class DatabaseRefreshTokenHousekeeper
{
    private const int LOCK_NONCE_BYTES = 16;
    private const int MAX_CLEANUP_LIMIT = 10000;

    public function __construct(
        #[\SensitiveParameter]
        private DatabaseInterface $database,
        private DatabaseRefreshTokenStoreConfig $config = new DatabaseRefreshTokenStoreConfig(),
    ) {}

    /** Removes bounded expired history and returns the number of family rows removed. */
    public function cleanup(int $now, int $limit = 1000): int
    {
        if ($now < 1) {
            throw new \InvalidArgumentException(
                'Refresh cleanup time must be positive.',
            );
        }

        if ($limit < 1 || $limit > self::MAX_CLEANUP_LIMIT) {
            throw new \InvalidArgumentException(sprintf(
                'Refresh cleanup limit must be between 1 and %d.',
                self::MAX_CLEANUP_LIMIT,
            ));
        }

        $this->pruneExpiredHistory($now, $limit);

        $query = $this->database
            ->select($this->config->familyIdColumn)
            ->withDriver(
                $this->database->getDriver(DatabaseInterface::WRITE),
                $this->database->getPrefix(),
            );

        $rows = $query
            ->from($this->config->familyTable)
            ->where($this->config->familyExpiresAtColumn, '<=', $now)
            ->orderBy($this->config->familyExpiresAtColumn, 'ASC')
            ->orderBy($this->config->familyIdColumn, 'ASC')
            ->limit($limit)
            ->run()
            ->fetchAll();
        $familyIds = [];

        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $familyId = $row[$this->config->familyIdColumn] ?? null;
            if (is_string($familyId) && $familyId !== '') {
                $familyIds[] = $familyId;
            }
        }

        if ($familyIds === []) {
            return 0;
        }

        return $this->database->transaction(
            function (
                #[\SensitiveParameter]
                DatabaseInterface $database,
            ) use ($familyIds, $now): int {
                $deleted = 0;

                foreach ($familyIds as $familyId) {
                    $claimed = $database
                        ->update($this->config->familyTable)
                        ->where($this->config->familyIdColumn, $familyId)
                        ->where($this->config->familyExpiresAtColumn, '<=', $now)
                        ->values([
                            $this->config->lockNonceColumn => self::lockNonce(),
                        ])
                        ->run();

                    if ($claimed !== 1) {
                        continue;
                    }

                    $query = $database->select($this->config->familyIdColumn)->withDriver(
                        $database->getDriver(DatabaseInterface::WRITE),
                        $database->getPrefix(),
                    );

                    $active = $query
                        ->from($this->config->tokenTable)
                        ->where($this->config->familyIdColumn, $familyId)
                        ->where($this->config->expiresAtColumn, '>', $now)
                        ->limit(1)
                        ->run()
                        ->fetch();

                    if (is_array($active)) {
                        throw new \UnexpectedValueException(
                            'Refresh family retention deadline precedes an active token expiry.',
                        );
                    }

                    if ($this->familyHasTokenRows($database, $familyId)) {
                        continue;
                    }

                    $deleted += $database
                        ->delete($this->config->familyTable)
                        ->where($this->config->familyIdColumn, $familyId)
                        ->where($this->config->familyExpiresAtColumn, '<=', $now)
                        ->run();
                }

                return $deleted;
            },
        );
    }

    private function pruneExpiredHistory(int $now, int $limit): void
    {
        $query = $this->database
            ->select([
                $this->config->tokenHashColumn,
                $this->config->familyIdColumn,
            ])
            ->withDriver(
                $this->database->getDriver(DatabaseInterface::WRITE),
                $this->database->getPrefix(),
            );

        $rows = $query
            ->from($this->config->tokenTable)
            ->where($this->config->expiresAtColumn, '<=', $now)
            ->orderBy($this->config->expiresAtColumn, 'ASC')
            ->orderBy($this->config->familyIdColumn, 'ASC')
            ->orderBy($this->config->tokenHashColumn, 'ASC')
            ->limit($limit)
            ->run()
            ->fetchAll();

        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $tokenHash = self::stringValue($row, $this->config->tokenHashColumn);
            $familyId = self::stringValue($row, $this->config->familyIdColumn);

            $this->database->transaction(
                function (
                    #[\SensitiveParameter]
                    DatabaseInterface $database,
                ) use ($tokenHash, $familyId, $now): void {
                    $claimed = $database
                        ->update($this->config->familyTable)
                        ->where($this->config->familyIdColumn, $familyId)
                        ->values([
                            $this->config->lockNonceColumn => self::lockNonce(),
                        ])
                        ->run();

                    if ($claimed !== 1) {
                        return;
                    }

                    $database
                        ->delete($this->config->tokenTable)
                        ->where($this->config->tokenHashColumn, $tokenHash)
                        ->where($this->config->familyIdColumn, $familyId)
                        ->where($this->config->expiresAtColumn, '<=', $now)
                        ->run();
                },
            );
        }
    }

    private function familyHasTokenRows(
        #[\SensitiveParameter]
        DatabaseInterface $database,
        #[\SensitiveParameter]
        string $familyId,
    ): bool {
        $query = $database->select($this->config->tokenHashColumn)->withDriver(
            $database->getDriver(DatabaseInterface::WRITE),
            $database->getPrefix(),
        );

        return is_array(
            $query
                ->from($this->config->tokenTable)
                ->where($this->config->familyIdColumn, $familyId)
                ->limit(1)
                ->run()
                ->fetch(),
        );
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(
        #[\SensitiveParameter]
        array $row,
        string $key,
    ): string {
        $value = $row[$key] ?? null;

        if (!is_string($value) && !is_int($value)) {
            throw new \UnexpectedValueException(sprintf(
                'Database column "%s" must contain a string-compatible value.',
                $key,
            ));
        }

        return (string) $value;
    }

    private static function lockNonce(): string
    {
        return bin2hex(random_bytes(self::LOCK_NONCE_BYTES));
    }
}

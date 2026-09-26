<?php

declare(strict_types=1);

namespace Componenta\Auth\Jwt\Tests\Support;

use Cycle\Database\Config\DatabaseConfig;
use Cycle\Database\Config\SQLiteDriverConfig;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\DatabaseManager;

final class SqliteDatabaseFixture
{
    public static function create(): DatabaseInterface
    {
        $database = (new DatabaseManager(new DatabaseConfig([
            'databases' => ['default' => ['connection' => 'sqlite']],
            'connections' => ['sqlite' => new SQLiteDriverConfig()],
        ])))->database('default');
        $database->execute('PRAGMA foreign_keys = ON');
        $schema = file_get_contents(
            dirname(__DIR__, 2) . '/resources/schema/sqlite.sql',
        );

        if (!is_string($schema)) {
            throw new \RuntimeException('JWT refresh schema is unavailable.');
        }

        foreach (array_filter(array_map('trim', explode(';', $schema))) as $sql) {
            $database->execute($sql);
        }

        return $database;
    }
}

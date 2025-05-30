# Doctrine DBAL Adapter for Casbin

[![PHPUnit](https://github.com/php-casbin/dbal-adapter/actions/workflows/phpunit.yml/badge.svg)](https://github.com/php-casbin/dbal-adapter/actions/workflows/phpunit.yml)
[![Coverage Status](https://coveralls.io/repos/github/php-casbin/dbal-adapter/badge.svg)](https://coveralls.io/github/php-casbin/dbal-adapter)
[![Latest Stable Version](https://poser.pugx.org/casbin/dbal-adapter/v/stable)](https://packagist.org/packages/casbin/dbal-adapter)
[![Total Downloads](https://poser.pugx.org/casbin/dbal-adapter/downloads)](https://packagist.org/packages/casbin/dbal-adapter)
[![License](https://poser.pugx.org/casbin/dbal-adapter/license)](https://packagist.org/packages/casbin/dbal-adapter)

Doctrine [DBAL](https://github.com/doctrine/dbal) Adapter for [PHP-Casbin](https://github.com/php-casbin/php-casbin), [Casbin](https://casbin.org/) is a powerful and efficient open-source access control library.

The following database vendors are currently supported:

- MySQL
- Oracle
- Microsoft SQL Server
- PostgreSQL
- SAP Sybase SQL Anywhere
- SQLite
- Drizzle

### Installation

Via [Composer](https://getcomposer.org/).

```
composer require casbin/dbal-adapter
```

### Basic Usage (Without Redis Caching)

This section describes how to use the adapter with a direct database connection, without leveraging Redis for caching.

You can initialize the adapter by passing either a Doctrine DBAL connection parameter array or an existing `Doctrine\DBAL\Connection` instance to the `Adapter::newAdapter()` method or the `Adapter` constructor.

**Example:**

```php
require_once './vendor/autoload.php';

use Casbin\Enforcer;
use CasbinAdapter\DBAL\Adapter as DatabaseAdapter;
use Doctrine\DBAL\DriverManager; // Required if creating a new connection object

// Option 1: Using DBAL connection parameters array
$dbConnectionParams = [
    // Supported drivers: pdo_mysql, pdo_sqlite, pdo_pgsql, pdo_oci, pdo_sqlsrv, 
    // mysqli, sqlanywhere, sqlsrv, ibm_db2, drizzle_pdo_mysql
    'driver' => 'pdo_mysql',
    'host' => '127.0.0.1',
    'dbname' => 'casbin_db', // Your database name
    'user' => 'root',
    'password' => '',
    'port' => '3306', // Optional, defaults to driver's standard port
    // 'policy_table_name' => 'casbin_rules', // Optional, defaults to 'casbin_rule'
];

// Initialize the Adapter with the DBAL parameters array (without Redis)
$adapter = DatabaseAdapter::newAdapter($dbConnectionParams);
// Alternatively, using the constructor:
// $adapter = new DatabaseAdapter($dbConnectionParams);

// Option 2: Using an existing Doctrine DBAL Connection instance
// $dbalConnection = DriverManager::getConnection($dbConnectionParams);
// $adapter = DatabaseAdapter::newAdapter($dbalConnection);
// Or using the constructor:
// $adapter = new DatabaseAdapter($dbalConnection);


$e = new Enforcer('path/to/model.conf', $adapter);

$sub = "alice"; // the user that wants to access a resource.
$obj = "data1"; // the resource that is going to be accessed.
$act = "read"; // the operation that the user performs on the resource.

if ($e->enforce($sub, $obj, $act) === true) {
    // permit alice to read data1
} else {
    // deny the request, show an error
}
```

### Usage with Redis Caching

To improve performance and reduce database load, the adapter supports caching policy data using [Redis](https://redis.io/). When enabled, Casbin policies will be fetched from Redis if available, falling back to the database if the cache is empty.

To enable Redis caching, provide a Redis configuration array as the second argument when initializing the adapter. The first argument remains your Doctrine DBAL connection (either a parameters array or a `Connection` object).

**Redis Configuration Options:**

*   `host` (string): Hostname or IP address of the Redis server. Default: `'127.0.0.1'`.
*   `port` (int): Port number of the Redis server. Default: `6379`.
*   `password` (string, nullable): Password for Redis authentication. Default: `null`.
*   `database` (int): Redis database index. Default: `0`.
*   `ttl` (int): Cache Time-To-Live in seconds. Policies stored in Redis will expire after this duration. Default: `3600` (1 hour).
*   `prefix` (string): Prefix for all Redis keys created by this adapter. Default: `'casbin_policies:'`.

**Example:**

```php
require_once './vendor/autoload.php';

use Casbin\Enforcer;
use CasbinAdapter\DBAL\Adapter as DatabaseAdapter;
use Doctrine\DBAL\DriverManager; // Required if creating a new connection object

// Database connection parameters (can be an array or a Connection object)
$dbConnectionParams = [
    'driver' => 'pdo_mysql',
    'host' => '127.0.0.1',
    'dbname' => 'casbin_db',
    'user' => 'root',
    'password' => '',
    'port' => '3306',
];
// Example with DBAL connection object:
// $dbalConnection = DriverManager::getConnection($dbConnectionParams);

// Redis configuration
$redisConfig = [
    'host' => '127.0.0.1',      // Optional, defaults to '127.0.0.1'
    'port' => 6379,             // Optional, defaults to 6379
    'password' => null,         // Optional, defaults to null
    'database' => 0,            // Optional, defaults to 0
    'ttl' => 7200,              // Optional, Cache policies for 2 hours (default is 3600)
    'prefix' => 'myapp_casbin:' // Optional, Custom prefix (default is 'casbin_policies:')
];

// Initialize adapter with DB parameters array and Redis configuration
$adapter = DatabaseAdapter::newAdapter($dbConnectionParams, $redisConfig);
// Or, using a DBAL Connection object:
// $adapter = DatabaseAdapter::newAdapter($dbalConnection, $redisConfig);
// Alternatively, using the constructor:
// $adapter = new DatabaseAdapter($dbConnectionParams, $redisConfig);

$e = new Enforcer('path/to/model.conf', $adapter);

// ... rest of your Casbin usage
```

#### Cache Preheating

The adapter provides a `preheatCache()` method to proactively load all policies from the database and store them in the Redis cache. This can be useful during application startup or as part of a scheduled task to ensure the cache is warm, reducing latency on initial policy checks.

**Example:**

```php
if ($adapter->preheatCache()) {
    // Cache preheating was successful
    echo "Casbin policy cache preheated successfully.\n";
} else {
    // Cache preheating failed (e.g., Redis not available or DB error)
    echo "Casbin policy cache preheating failed.\n";
}
```

#### Cache Invalidation

The cache is designed to be automatically invalidated when policy-modifying methods are called on the adapter (e.g., `addPolicy()`, `removePolicy()`, `savePolicy()`, etc.). Currently, this primarily clears the cache key for all policies (`{$prefix}all_policies`).

**Important Note:** The automatic invalidation for *filtered policies* (policies loaded via `loadFilteredPolicy()`) is limited. Due to the way `predis/predis` client works and to avoid using performance-detrimental commands like `KEYS *` in production environments, the adapter does not automatically delete cache entries for specific filters by pattern. If you rely heavily on `loadFilteredPolicy` and make frequent policy changes, consider a lower TTL for your Redis cache or implement a more sophisticated cache invalidation strategy for filtered results outside of this adapter if needed. The main `{$prefix}all_policies` cache is cleared on any policy change, which means subsequent calls to `loadPolicy()` will refresh from the database and update this general cache.

### Getting Help

- [php-casbin](https://github.com/php-casbin/php-casbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).
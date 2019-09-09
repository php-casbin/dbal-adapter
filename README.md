# Doctrine DBAL Adapter for Casbin

[![Build Status](https://travis-ci.org/php-casbin/dbal-adapter.svg?branch=master)](https://travis-ci.org/php-casbin/dbal-adapter)
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

### Usage

```php

require_once './vendor/autoload.php';

use Casbin\Enforcer;
use CasbinAdapter\DBAL\Adapter as DatabaseAdapter;

$config = [
    // Either 'driver' with one of the following values:
    // pdo_mysql,pdo_sqlite,pdo_pgsql,pdo_oci (unstable),pdo_sqlsrv,pdo_sqlsrv,
    // mysqli,sqlanywhere,sqlsrv,ibm_db2 (unstable),drizzle_pdo_mysql
    'driver' => 'pdo_mysql',
    'host' => '127.0.0.1',
    'dbname' => 'test',
    'user' => 'root',
    'password' => '',
    'port' => '3306',
];

$adapter = DatabaseAdapter::newAdapter($config);

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

### Getting Help

- [php-casbin](https://github.com/php-casbin/php-casbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).
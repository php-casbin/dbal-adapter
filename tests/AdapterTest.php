<?php

namespace CasbinAdapter\DBAL\Tests;

use Casbin\Enforcer;
use Casbin\Model\Model;
use CasbinAdapter\DBAL\Adapter as DatabaseAdapter;
use PHPUnit\Framework\TestCase;
use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\DriverManager;

class AdapterTest extends TestCase
{
    protected $config = [];

    protected function initConfig()
    {
        $this->config = [
            'driver' => 'pdo_mysql', // ibm_db2, pdo_sqlsrv, pdo_mysql, pdo_pgsql, pdo_sqlite
            'host' => $this->env('DB_HOST', '127.0.0.1'),
            'dbname' => $this->env('DB_DATABASE', 'casbin'),
            'user' => $this->env('DB_USERNAME', 'root'),
            'password' => $this->env('DB_PASSWORD', ''),
            'port' => $this->env('DB_PORT', 3306),
        ];
    }

    protected function initDb(DatabaseAdapter $adapter)
    {
        $tableName = $adapter->policyTableName;
        $conn = $adapter->getConnection();
        $queryBuilder = $conn->createQueryBuilder();
        $queryBuilder->delete($tableName)->where('1 = 1')->execute();

        $data = [
            ['p_type' => 'p', 'v0' => 'alice', 'v1' => 'data1', 'v2' => 'read'],
            ['p_type' => 'p', 'v0' => 'bob', 'v1' => 'data2', 'v2' => 'write'],
            ['p_type' => 'p', 'v0' => 'data2_admin', 'v1' => 'data2', 'v2' => 'read'],
            ['p_type' => 'p', 'v0' => 'data2_admin', 'v1' => 'data2', 'v2' => 'write'],
            ['p_type' => 'g', 'v0' => 'alice', 'v1' => 'data2_admin'],
        ];
        foreach ($data as $row) {
            $queryBuilder->insert($tableName)->values(array_combine(array_keys($row), array_fill(0, count($row), '?')))->setParameters(array_values($row))->execute();
        }
    }

    protected function getEnforcer()
    {
        $this->initConfig();
        $adapter = DatabaseAdapter::newAdapter($this->config);

        $this->initDb($adapter);
        $model = Model::newModelFromString(
            <<<'EOT'
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
EOT
        );

        return new Enforcer($model, $adapter);
    }

    public function testLoadPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testAddPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('eve', 'data3', 'read'));

        $e->addPermissionForUser('eve', 'data3', 'read');
        $this->assertTrue($e->enforce('eve', 'data3', 'read'));
    }

    public function testSavePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data4', 'read'));

        $model = $e->getModel();
        $model->clearPolicy();
        $model->addPolicy('p', 'p', ['alice', 'data4', 'read']);

        $adapter = $e->getAdapter();
        $adapter->savePolicy($model);
        $this->assertTrue($e->enforce('alice', 'data4', 'read'));
    }

    public function testRemovePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
        $e->addPermissionForUser('alice', 'data5', 'read');
        $this->assertTrue($e->enforce('alice', 'data5', 'read'));
        $e->deletePermissionForUser('alice', 'data5', 'read');
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
    }

    public function testRemoveFilteredPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $e->removeFilteredPolicy(1, 'data1');
        $this->assertFalse($e->enforce('alice', 'data1', 'read'));

        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e->removeFilteredPolicy(1, 'data2', 'read');

        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e->removeFilteredPolicy(2, 'write');

        $this->assertFalse($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
    }

    protected function env($key, $default = null)
    {
        $value = getenv($key);
        if (is_null($default)) {
            return $value;
        }

        return false === $value ? $default : $value;
    }
}

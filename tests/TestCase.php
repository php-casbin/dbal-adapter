<?php


namespace CasbinAdapter\DBAL\Tests;


use Casbin\Enforcer;
use Casbin\Model\Model;
use CasbinAdapter\DBAL\Adapter;
use CasbinAdapter\DBAL\Adapter as DatabaseAdapter;

class TestCase extends \PHPUnit\Framework\TestCase
{
    protected $config = [];

    protected $adapter;

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
        $query = $queryBuilder->delete($tableName)->where('1 = 1');
        method_exists($query, "executeQuery") ? $query->executeQuery() : $query->execute();

        $data = [
            ['p_type' => 'p', 'v0' => 'alice', 'v1' => 'data1', 'v2' => 'read'],
            ['p_type' => 'p', 'v0' => 'bob', 'v1' => 'data2', 'v2' => 'write'],
            ['p_type' => 'p', 'v0' => 'data2_admin', 'v1' => 'data2', 'v2' => 'read'],
            ['p_type' => 'p', 'v0' => 'data2_admin', 'v1' => 'data2', 'v2' => 'write'],
            ['p_type' => 'g', 'v0' => 'alice', 'v1' => 'data2_admin'],
        ];
        foreach ($data as $row) {
            $query = $queryBuilder->insert($tableName)->values(array_combine(array_keys($row), array_fill(0, count($row), '?')))->setParameters(array_values($row));
            method_exists($query, "executeQuery") ? $query->executeQuery() : $query->execute();
        }
    }

    protected function getEnforcer(): Enforcer
    {
        $this->initConfig();
        $adapter = DatabaseAdapter::newAdapter($this->config);
        return $this->getEnforcerWithAdapter($adapter);
    }

    protected function getEnforcerWithAdapter(Adapter $adapter): Enforcer
    {
        $this->adapter = $adapter;
        $this->initDb($this->adapter);
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

        return new Enforcer($model, $this->adapter);
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
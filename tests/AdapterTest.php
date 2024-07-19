<?php

namespace CasbinAdapter\DBAL\Tests;

use CasbinAdapter\DBAL\Adapter as DatabaseAdapter;
use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception;
use Doctrine\DBAL\Logging\Middleware as LoggingMiddleware;

class AdapterTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testUpdateFilteredPolicies()
    {
        $this->initConfig();
        $connConfig = new Configuration();
        $this->configureLogger($connConfig);
        $conn = DriverManager::getConnection(
            $this->config,
            $connConfig
        );
        $adapter = DatabaseAdapter::newAdapter($conn);
        $conn->delete($adapter->policyTableName, ["1" => "1"]);
        $conn->insert($adapter->policyTableName, ["p_type" => "p", "v0" => "alice", "v1" => "data", "v2" => "read", "v3" => "allow"]);
        $conn->insert($adapter->policyTableName, ["p_type" => "p", "v0" => "alice", "v1" => "data1", "v2" => "write", "v3" => "allow"]);
        $conn->insert($adapter->policyTableName, ["p_type" => "p", "v0" => "bob", "v1" => "data", "v2" => "write", "v3" => "allow"]);
        $conn->insert($adapter->policyTableName, ["p_type" => "p", "v0" => "bob", "v1" => "data1", "v2" => "read", "v3" => "allow"]);

        $newPolicies = [
            ["alice", "data", "read", "allow"],
            ["bob", "data", "read", "allow"]
        ];
        $oldRules = $adapter->updateFilteredPolicies("p", "p", $newPolicies, 1, "data", null, "allow");
        $this->assertEquals([
            ["p", "alice", "data", "read", "allow"],
            ["p", "bob", "data", "write", "allow"]
        ], $oldRules);

        $query = $conn->createQueryBuilder()->from($adapter->policyTableName)->where('p_type = "p" and v1 = "data" and v3 = "allow"')->select("v0", "v1", "v2", "v3");
        $stmt = method_exists($query, "executeQuery") ? $query->executeQuery() : $query->execute();
        $result = method_exists($stmt, 'fetchAssociative') ? $stmt->fetchAllAssociative() : $stmt->fetchAll();

        $result = array_map([$adapter, "filterRule"], $result);

        $this->assertEquals($newPolicies, $result);
    }

    /**
     *
     * @param \Doctrine\DBAL\Configuration $connConfig
     * @return void
     */
    private function configureLogger($connConfig)
    {
        // Doctrine < 4.0
        if(method_exists($connConfig, "setSQLLogger")) {
            $connConfig->setSQLLogger(new DebugStackLogger());
        }
        // Doctrine >= 4.0
        else {
            $connConfig->setMiddlewares([
              new LoggingMiddleware(new PsrLogger())
            ]);
        }
    }
}

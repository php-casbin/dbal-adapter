<?php

namespace CasbinAdapter\DBAL\Tests;

use CasbinAdapter\DBAL\Adapter as DatabaseAdapter;
use CasbinAdapter\DBAL\Filter;
use Doctrine\DBAL\Query\Expression\CompositeExpression;
use Doctrine\DBAL\Query\QueryBuilder;

class AdapterTest extends TestCase
{
    public function testLoadPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testLoadFilteredPolicy()
    {
        $this->initConfig();
        $adapter = DatabaseAdapter::newAdapter($this->config);
        $adapter->setFiltered(true);
        $e = $this->getEnforcerWithAdapter($adapter);
        $this->assertEquals([], $e->getPolicy());

        // string
        $filter = "v0 = 'bob'";
        $e->loadFilteredPolicy($filter);
        $this->assertEquals([
            ['bob', 'data2', 'write']
        ], $e->getPolicy());

        // CompositeExpression
        $queryBuilder = new QueryBuilder($adapter->getConnection());
        $e->loadFilteredPolicy(
            $queryBuilder->expr()->in("v0", ['"alice", "bob"'])
        );
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
        ], $e->getPolicy());

        // Filter
        $filter = new Filter('v2 = ?', ['read']);
        $e->loadFilteredPolicy($filter);
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['data2_admin', 'data2', 'read'],
        ], $e->getPolicy());

        // Closure
        $e->loadFilteredPolicy(function (QueryBuilder &$queryBuilder) {
            $queryBuilder->where('v1 = :v1')->setParameter('v1', 'data1');
        });

        $this->assertEquals([
            ['alice', 'data1', 'read'],
        ], $e->getPolicy());
    }

    public function testAddPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('eve', 'data3', 'read'));

        $e->addPermissionForUser('eve', 'data3', 'read');
        $this->assertTrue($e->enforce('eve', 'data3', 'read'));
    }

    public function testAddPolicies()
    {
        $policies = [
            ['u1', 'd1', 'read'],
            ['u2', 'd2', 'read'],
            ['u3', 'd3', 'read'],
        ];
        $e = $this->getEnforcer();
        $e->clearPolicy();
        $this->initDb($this->adapter);
        $this->assertEquals([], $e->getPolicy());
        $e->addPolicies($policies);
        $this->assertEquals($policies, $e->getPolicy());
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

    public function testRemovePolicies()
    {
        $e = $this->getEnforcer();
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());

        $e->removePolicies([
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ]);

        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write']
        ], $e->getPolicy());
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

    public function testUpdatePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());

        $e->updatePolicy(
            ['alice', 'data1', 'read'],
            ['alice', 'data1', 'write']
        );

        $e->updatePolicy(
            ['bob', 'data2', 'write'],
            ['bob', 'data2', 'read']
        );

        $this->assertEquals([
            ['alice', 'data1', 'write'],
            ['bob', 'data2', 'read'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());
    }
}

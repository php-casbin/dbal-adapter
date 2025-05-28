<?php

declare(strict_types=1);

namespace CasbinAdapter\DBAL\Tests;

use CasbinAdapter\DBAL\Adapter;
use Casbin\Model\Model;
use Predis\Client as PredisClient;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Query\Expression\CompositeExpression; // For filtered policy test
use Casbin\Persist\Adapters\Filter; // For filtered policy test

class AdapterWithRedisTest extends TestCase
{
    protected PredisClient $redisDirectClient;
    protected array $redisConfig;
    protected string $redisTestPrefix = 'casbin_test_policies:';

    protected function setUp(): void
    {
        parent::setUp(); // Sets up in-memory SQLite connection from TestCase

        $redisHost = getenv('REDIS_HOST') ?: '127.0.0.1';
        $redisPort = (int)(getenv('REDIS_PORT') ?: 6379);
        // Use a different DB index for tests if possible, to avoid conflicts
        $redisDbIndex = (int)(getenv('REDIS_DB_INDEX') ?: 15); 

        $this->redisConfig = [
            'host' => $redisHost,
            'port' => $redisPort,
            'database' => $redisDbIndex,
            'prefix' => $this->redisTestPrefix,
            'ttl' => 300, 
        ];

        $this->redisDirectClient = new PredisClient([
            'scheme' => 'tcp',
            'host'   => $this->redisConfig['host'],
            'port'   => $this->redisConfig['port'],
        ]);
        // Select the test database
        $this->redisDirectClient->select($this->redisConfig['database']);
        
        $this->clearTestDataFromRedis();
    }

    protected function tearDown(): void
    {
        $this->clearTestDataFromRedis();
        if (isset($this->redisDirectClient)) {
            $this->redisDirectClient->disconnect();
        }
        parent::tearDown();
    }

    protected function clearTestDataFromRedis(): void
    {
        if (!isset($this->redisDirectClient)) {
            return;
        }
        $keys = $this->redisDirectClient->keys($this->redisTestPrefix . '*');
        if (!empty($keys)) {
            // Predis `keys` returns full key names. If the client has a prefix,
            // it's for commands like `get`, `set`. `del` can take full names.
            // Since $this->redisDirectClient is NOT configured with a prefix,
            // $keys will be the actual keys in Redis, and del($keys) is correct.
            $this->redisDirectClient->del($keys);
        }
    }
    
    protected function createModel(): Model
    {
        $model = new Model();
        $model->loadModelFromText(self::$modelText); // from TestCase
        return $model;
    }

    protected function getAdapterWithRedis(bool $connectRedis = true): Adapter
    {
        $dbalConfig = [ // Using the in-memory SQLite from parent TestCase
            'driver' => 'pdo_sqlite',
            'memory' => true, 
            'policy_table_name' => $this->policyTable,
        ];
        
        $redisConf = $connectRedis ? $this->redisConfig : null;
        // Important: Ensure the adapter's DB connection is fresh for each test needing it.
        // The parent::setUp() re-initializes $this->connection for the TestCase context.
        // If Adapter::newAdapter uses its own DriverManager::getConnection, it's fine.
        // The current Adapter constructor takes an array and creates its own connection.
        return Adapter::newAdapter($dbalConfig, $redisConf);
    }

    public function testAdapterWorksWithoutRedis(): void
    {
        $adapter = $this->getAdapterWithRedis(false);
        $this->assertNotNull($adapter, 'Adapter should be creatable without Redis config.');

        $model = $this->createModel();
        $adapter->addPolicy('p', 'p', ['role:admin', '/data1', 'write']);
        $adapter->loadPolicy($model);
        $this->assertTrue($model->hasPolicy('p', 'p', ['role:admin', '/data1', 'write']));

        $adapter->removePolicy('p', 'p', ['role:admin', '/data1', 'write']);
        $model = $this->createModel(); // Re-create model for fresh load
        $adapter->loadPolicy($model);
        $this->assertFalse($model->hasPolicy('p', 'p', ['role:admin', '/data1', 'write']));
    }

    public function testLoadPolicyCachesData(): void
    {
        $adapter = $this->getAdapterWithRedis();
        $model = $this->createModel();

        $adapter->addPolicy('p', 'p', ['alice', 'data1', 'read']); // Clears cache
        $adapter->addPolicy('p', 'p', ['bob', 'data2', 'write']);   // Clears cache again

        $cacheKey = $this->redisTestPrefix . 'all_policies';
        $this->assertEquals(0, $this->redisDirectClient->exists($cacheKey), "Cache key {$cacheKey} should be empty after addPolicy.");

        $adapter->loadPolicy($model); // DB query, populates cache
        $this->assertTrue($model->hasPolicy('p', 'p', ['alice', 'data1', 'read']));
        $this->assertEquals(1, $this->redisDirectClient->exists($cacheKey), "Cache key {$cacheKey} should exist after loadPolicy.");
        
        $cachedData = json_decode((string)$this->redisDirectClient->get($cacheKey), true);
        $this->assertCount(2, $cachedData);

        // "Disable" DB connection to ensure next load is from cache
        $adapter->getConnection()->close();

        $model2 = $this->createModel(); // Fresh model
        try {
            $adapter->loadPolicy($model2); // Should load from cache
            $this->assertTrue($model2->hasPolicy('p', 'p', ['alice', 'data1', 'read']), "Policy (alice) should be loaded from cache.");
            $this->assertTrue($model2->hasPolicy('p', 'p', ['bob', 'data2', 'write']), "Policy (bob) should be loaded from cache.");
        } catch (\Exception $e) {
            $this->fail("loadPolicy failed, likely tried to use closed DB connection. Error: " . $e->getMessage());
        }
    }

    public function testLoadFilteredPolicyCachesData(): void
    {
        $adapter = $this->getAdapterWithRedis();
        $model = $this->createModel();

        // Add policies (these calls will clear all_policies cache)
        $adapter->addPolicy('p', 'p', ['filter_user', 'data_f1', 'read']);
        $adapter->addPolicy('p', 'p', ['filter_user', 'data_f2', 'write']);
        $adapter->addPolicy('p', 'p', ['other_user', 'data_f3', 'read']);

        $filter = new Filter(['v0' => 'filter_user']);
        $filterRepresentation = json_encode(['predicates' => $filter->getPredicates(), 'params' => $filter->getParams()]);
        $expectedCacheKey = $this->redisTestPrefix . 'filtered_policies:' . md5($filterRepresentation);

        $this->assertEquals(0, $this->redisDirectClient->exists($expectedCacheKey), "Filtered cache key should initially be empty.");

        // Load filtered policy - should query DB and populate cache
        $adapter->loadFilteredPolicy($model, $filter);
        $this->assertTrue($model->hasPolicy('p', 'p', ['filter_user', 'data_f1', 'read']));
        $this->assertTrue($model->hasPolicy('p', 'p', ['filter_user', 'data_f2', 'write']));
        $this->assertFalse($model->hasPolicy('p', 'p', ['other_user', 'data_f3', 'read'])); // Not part of filter
        $this->assertEquals(1, $this->redisDirectClient->exists($expectedCacheKey), "Filtered cache key should exist after loadFilteredPolicy.");
        $cachedLines = json_decode((string)$this->redisDirectClient->get($expectedCacheKey), true);
        $this->assertCount(2, $cachedLines, "Filtered cache should contain 2 policy lines.");

        // "Disable" DB connection
        $adapter->getConnection()->close();

        $model2 = $this->createModel(); // Fresh model
        try {
            $adapter->loadFilteredPolicy($model2, $filter); // Should load from cache
            $this->assertTrue($model2->hasPolicy('p', 'p', ['filter_user', 'data_f1', 'read']));
            $this->assertTrue($model2->hasPolicy('p', 'p', ['filter_user', 'data_f2', 'write']));
        } catch (\Exception $e) {
            $this->fail("loadFilteredPolicy (from cache) failed. Error: " . $e->getMessage());
        }
        
        // Test with a different filter - should not hit cache, and DB is "disabled"
        $model3 = $this->createModel();
        $differentFilter = new Filter(['v0' => 'other_user']);
        try {
            $adapter->loadFilteredPolicy($model3, $differentFilter);
            // If the DB connection was truly unusable by the adapter for new queries,
            // and no cache for this new filter, this load should not add policies.
            // Or, if the adapter re-establishes connection, this test needs rethink.
            // Assuming closed connection is unusable for new queries by QueryBuilder:
            $this->assertCount(0, $model3->getPolicy('p', 'p'), "Model should be empty for a different filter if DB is down and no cache.");
        } catch (\Exception $e) {
            // This is the expected path if the adapter tries to use the closed connection
            $this->assertStringContainsStringIgnoringCase("closed", $e->getMessage(), "Exception should indicate connection issue for different filter.");
        }
    }

    public function testCacheInvalidationOnAddPolicy(): void
    {
        $adapter = $this->getAdapterWithRedis();
        $model = $this->createModel();
        $cacheKey = $this->redisTestPrefix . 'all_policies';

        // 1. Populate cache
        $adapter->addPolicy('p', 'p', ['initial_user', 'initial_data', 'read']); // Clears
        $adapter->loadPolicy($model); // Populates
        $this->assertEquals(1, $this->redisDirectClient->exists($cacheKey), "Cache should be populated by loadPolicy.");

        // 2. Add another policy (this should clear the cache)
        $adapter->addPolicy('p', 'p', ['new_user', 'new_data', 'write']);
        $this->assertEquals(0, $this->redisDirectClient->exists($cacheKey), "Cache should be invalidated after addPolicy.");
    }
    
    public function testCacheInvalidationOnSavePolicy(): void
    {
        $adapter = $this->getAdapterWithRedis();
        $model = $this->createModel();
        $cacheKey = $this->redisTestPrefix . 'all_policies';

        $adapter->addPolicy('p', 'p', ['initial_user', 'initial_data', 'read']);
        $adapter->loadPolicy($model);
        $this->assertEquals(1, $this->redisDirectClient->exists($cacheKey));

        // Create a new model state
        $modelSave = $this->createModel();
        $modelSave->addPolicy('p', 'p', ['user_for_save', 'data_for_save', 'act_for_save']);
        
        $adapter->savePolicy($modelSave); // This should clear the 'all_policies' cache
        $this->assertEquals(0, $this->redisDirectClient->exists($cacheKey), "Cache should be invalidated after savePolicy.");
    }


    public function testPreheatCachePopulatesCache(): void
    {
        $adapter = $this->getAdapterWithRedis();
        // Add some data directly to DB using a temporary adapter to simulate existing data
        $tempAdapter = $this->getAdapterWithRedis(false); // No redis for this one
        $tempAdapter->addPolicy('p', 'p', ['preheat_user', 'preheat_data', 'read']);
        
        $cacheKey = $this->redisTestPrefix . 'all_policies';
        $this->assertEquals(0, $this->redisDirectClient->exists($cacheKey), "Cache should be initially empty.");

        $result = $adapter->preheatCache();
        $this->assertTrue($result, "preheatCache should return true on success.");
        $this->assertEquals(1, $this->redisDirectClient->exists($cacheKey), "Cache should be populated by preheatCache.");
        
        $cachedData = json_decode((string)$this->redisDirectClient->get($cacheKey), true);
        $this->assertIsArray($cachedData);
        $this->assertCount(1, $cachedData, "Preheated cache should contain one policy.");
        $this->assertEquals('preheat_user', $cachedData[0]['v0'] ?? null);
    }
}

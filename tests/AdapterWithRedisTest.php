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
    protected \PHPUnit\Framework\MockObject\MockObject $redisDirectClient; // Changed type to MockObject
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

        // Create a mock for Predis\Client
        $this->redisDirectClient = $this->createMock(PredisClient::class);

        // Configure mock methods that are called in setUp/tearDown or by clearTestDataFromRedis
        $this->redisDirectClient->method('select')->willReturn(null); // Or $this if fluent
        $this->redisDirectClient->method('disconnect')->willReturn(null);
        
        // For clearTestDataFromRedis, initially make it a no-op or safe mock
        // This method will be further refactored as per requirements.
        $this->redisDirectClient->method('keys')->willReturn([]);
        $this->redisDirectClient->method('del')->willReturn(0);

        // The original select call is now handled by the mock configuration.
        // $this->redisDirectClient->select($this->redisConfig['database']); 
        
        $this->clearTestDataFromRedis(); // This will now use the mocked keys/del
    }

    protected function tearDown(): void
    {
        $this->clearTestDataFromRedis(); // Uses mocked keys/del
        if (isset($this->redisDirectClient)) {
            // disconnect() is already configured on the mock
            $this->redisDirectClient->disconnect();
        }
        parent::tearDown();
    }

    protected function clearTestDataFromRedis(): void
    {
        if (!isset($this->redisDirectClient)) {
            return;
        }
        // keys() and del() are now mocked and will behave as configured in setUp()
        $keys = $this->redisDirectClient->keys($this->redisTestPrefix . '*');
        if (!empty($keys)) {
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
        
        $redisOptions = null;
        if ($connectRedis) {
            // Pass the mock Redis client instance directly
            $redisOptions = $this->redisDirectClient;
        }
        
        // Important: Ensure the adapter's DB connection is fresh for each test needing it.
        // The parent::setUp() re-initializes $this->connection for the TestCase context.
        // If Adapter::newAdapter uses its own DriverManager::getConnection, it's fine.
        // The current Adapter constructor takes an array and creates its own connection.
        // Adapter::newAdapter now accepts a RedisClient instance or config array or null.
        return Adapter::newAdapter($dbalConfig, $redisOptions);
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

        // Define policies to be added
        $policy1 = ['alice', 'data1', 'read'];
        $policy2 = ['bob', 'data2', 'write'];
        
        // These addPolicy calls will also trigger 'del' on the cache, 
        // which is mocked in setUp to return 0. We can make this more specific if needed.
        $adapter->addPolicy('p', 'p', $policy1); 
        $adapter->addPolicy('p', 'p', $policy2);

        $cacheKey = $this->redisTestPrefix . 'all_policies';
        
        // Variable to store the data that should be cached
        $capturedCacheData = null;

        // --- Cache Miss Scenario ---
        $this->redisDirectClient
            ->expects($this->at(0)) // First call to the mock for 'exists'
            ->method('exists')
            ->with($cacheKey)
            ->willReturn(false);

        $this->redisDirectClient
            ->expects($this->once()) // Expect 'set' to be called once during the first loadPolicy
            ->method('set')
            ->with($cacheKey, $this->isType('string')) // Assert value is string (JSON)
            ->will($this->returnCallback(function ($key, $value) use (&$capturedCacheData) {
                $capturedCacheData = $value; // Capture the data that was set
                return true; // Mock what Predis set might return (e.g., true/OK status)
            }));
        
        // This call to loadPolicy should trigger DB query and populate cache
        $adapter->loadPolicy($model); 
        $this->assertTrue($model->hasPolicy('p', 'p', $policy1), "Policy 1 should be loaded after first loadPolicy");
        $this->assertTrue($model->hasPolicy('p', 'p', $policy2), "Policy 2 should be loaded after first loadPolicy");
        $this->assertNotNull($capturedCacheData, "Cache data should have been captured.");

        // Verify that the captured data contains the policies
        $decodedCapturedData = json_decode($capturedCacheData, true);
        $this->assertIsArray($decodedCapturedData);
        $this->assertCount(2, $decodedCapturedData, "Captured cache data should contain 2 policies.");
        // More specific checks on content can be added if necessary

        // --- Cache Hit Scenario ---
        // "Disable" DB connection to ensure next load is from cache
        $adapter->getConnection()->close();

        $this->redisDirectClient
            ->expects($this->at(1)) // Second call to the mock for 'exists'
            ->method('exists')
            ->with($cacheKey)
            ->willReturn(true);

        $this->redisDirectClient
            ->expects($this->once()) // Expect 'get' to be called once for the cache hit
            ->method('get')
            ->with($cacheKey)
            ->willReturn($capturedCacheData); // Return the data "cached" previously

        // `set` should not be called again in the cache hit scenario for loadPolicy.
        // The previous `expects($this->once())->method('set')` covers this, as it means exactly once for the whole test.
        // If we needed to be more specific about *when* set is not called, we could re-declare expectations.

        $model2 = $this->createModel(); // Fresh model
        try {
            $adapter->loadPolicy($model2); // Should load from cache
            $this->assertTrue($model2->hasPolicy('p', 'p', $policy1), "Policy (alice) should be loaded from cache.");
            $this->assertTrue($model2->hasPolicy('p', 'p', $policy2), "Policy (bob) should be loaded from cache.");
        } catch (\Exception $e) {
            $this->fail("loadPolicy failed, likely tried to use closed DB connection. Error: " . $e->getMessage());
        }
    }

    public function testLoadFilteredPolicyCachesData(): void
    {
        $adapter = $this->getAdapterWithRedis();
        $model = $this->createModel();

        $policyF1 = ['filter_user', 'data_f1', 'read'];
        $policyF2 = ['filter_user', 'data_f2', 'write'];
        $policyOther = ['other_user', 'data_f3', 'read'];

        // Add policies. These will trigger 'del' on the mock via invalidateCache.
        // The generic 'del' mock in setUp handles these.
        $adapter->addPolicy('p', 'p', $policyF1);
        $adapter->addPolicy('p', 'p', $policyF2);
        $adapter->addPolicy('p', 'p', $policyOther);

        $filter = new Filter(['v0' => 'filter_user']);
        $filterRepresentation = json_encode(['predicates' => $filter->getPredicates(), 'params' => $filter->getParams()]);
        $expectedCacheKey = $this->redisTestPrefix . 'filtered_policies:' . md5($filterRepresentation);
        
        $capturedCacheData = null;

        // --- Cache Miss Scenario ---
        $this->redisDirectClient
            ->expects($this->at(0)) // First 'exists' call for this specific key
            ->method('exists')
            ->with($expectedCacheKey)
            ->willReturn(false);

        $this->redisDirectClient
            ->expects($this->once())
            ->method('set')
            ->with($expectedCacheKey, $this->isType('string'))
            ->will($this->returnCallback(function ($key, $value) use (&$capturedCacheData) {
                $capturedCacheData = $value;
                return true;
            }));

        // Load filtered policy - should query DB and populate cache
        $adapter->loadFilteredPolicy($model, $filter);
        $this->assertTrue($model->hasPolicy('p', 'p', $policyF1));
        $this->assertTrue($model->hasPolicy('p', 'p', $policyF2));
        $this->assertFalse($model->hasPolicy('p', 'p', $policyOther)); // Not part of filter
        $this->assertNotNull($capturedCacheData, "Filtered cache data should have been captured.");
        $decodedCapturedData = json_decode($capturedCacheData, true);
        $this->assertCount(2, $decodedCapturedData, "Filtered cache should contain 2 policy lines.");

        // --- Cache Hit Scenario ---
        $adapter->getConnection()->close(); // "Disable" DB connection

        $this->redisDirectClient
            ->expects($this->at(1)) // Second 'exists' call for this specific key
            ->method('exists')
            ->with($expectedCacheKey)
            ->willReturn(true);

        $this->redisDirectClient
            ->expects($this->once())
            ->method('get')
            ->with($expectedCacheKey)
            ->willReturn($capturedCacheData);

        $model2 = $this->createModel(); // Fresh model
        try {
            $adapter->loadFilteredPolicy($model2, $filter); // Should load from cache
            $this->assertTrue($model2->hasPolicy('p', 'p', $policyF1));
            $this->assertTrue($model2->hasPolicy('p', 'p', $policyF2));
        } catch (\Exception $e) {
            $this->fail("loadFilteredPolicy (from cache) failed. Error: " . $e->getMessage());
        }
        
        // --- Test with a different filter (Cache Miss, DB Closed) ---
        $model3 = $this->createModel();
        $differentFilter = new Filter(['v0' => 'other_user']);
        $differentCacheKey = $this->redisTestPrefix . 'filtered_policies:' . md5(json_encode(['predicates' => $differentFilter->getPredicates(), 'params' => $differentFilter->getParams()]));

        $this->redisDirectClient
            ->expects($this->at(2)) // Third 'exists' call, for a different key
            ->method('exists')
            ->with($differentCacheKey)
            ->willReturn(false); // No cache for this different filter

        // set should not be called for this different filter because DB is closed
        // The previous ->expects($this->once())->method('set') for the first key handles this.
        // If we needed to be more explicit:
        // $this->redisDirectClient->expects($this->never())->method('set')->with($differentCacheKey, $this->anything());
        
        try {
            $adapter->loadFilteredPolicy($model3, $differentFilter);
            $this->assertCount(0, $model3->getPolicy('p', 'p'), "Model should be empty for a different filter if DB is down and no cache.");
        } catch (\Exception $e) {
            $this->assertStringContainsStringIgnoringCase("closed", $e->getMessage(), "Exception should indicate connection issue for different filter.");
        }
    }

    public function testCacheInvalidationOnAddPolicy(): void
    {
        $adapter = $this->getAdapterWithRedis();
        $model = $this->createModel();
        $allPoliciesCacheKey = $this->redisTestPrefix . 'all_policies';
        $filteredPoliciesPattern = $this->redisTestPrefix . 'filtered_policies:*';

        // 1. Populate cache (loadPolicy part)
        // Initial addPolicy clears cache (mocked del in setUp handles this)
        $adapter->addPolicy('p', 'p', ['initial_user', 'initial_data', 'read']); 

        $this->redisDirectClient
            ->expects($this->at(0)) // For loadPolicy
            ->method('exists')
            ->with($allPoliciesCacheKey)
            ->willReturn(false);
        $this->redisDirectClient
            ->expects($this->once()) // For loadPolicy
            ->method('set')
            ->with($allPoliciesCacheKey, $this->isType('string'))
            ->willReturn(true);

        $adapter->loadPolicy($model); // Populates 'all_policies'

        $this->redisDirectClient
            ->expects($this->at(1)) // After loadPolicy, before second addPolicy
            ->method('exists')
            ->with($allPoliciesCacheKey)
            ->willReturn(true); // Simulate cache is now populated for assertion below (if we were to assert)
                               // This expectation isn't strictly needed for the test's core logic on invalidation,
                               // but reflects the state. The crucial parts are 'del' and subsequent 'exists'.

        // 2. Add another policy (this should clear the cache)
        // Expect 'del' for all_policies key
        $this->redisDirectClient
            ->expects($this->at(2)) // Order for del of all_policies
            ->method('del')
            ->with([$allPoliciesCacheKey]) // Predis del can take an array of keys
            ->willReturn(1);

        // Expect 'keys' for filtered policies pattern, returning empty for simplicity now
        // (if actual filtered keys existed, this mock would need to return them)
        $this->redisDirectClient
            ->expects($this->at(3)) // Order for keys call
            ->method('keys')
            ->with($filteredPoliciesPattern)
            ->willReturn([]);
        // Since keys returns [], we don't expect a subsequent del for filtered keys.
        // If keys returned values, another ->expects('del')->with(...) would be needed.
        
        $adapter->addPolicy('p', 'p', ['new_user', 'new_data', 'write']);

        // After addPolicy, cache should be invalidated
        $this->redisDirectClient
            ->expects($this->at(4)) // After invalidating addPolicy
            ->method('exists')
            ->with($allPoliciesCacheKey)
            ->willReturn(false); // Simulate cache is now empty

        // To verify, we can try to load and check if 'exists' (mocked to false) is called again.
        // Or simply trust that the 'del' was called and 'exists' now returns false.
        // For this test, checking exists returns false is a good verification.
        $modelAfterInvalidation = $this->createModel();
        $adapter->loadPolicy($modelAfterInvalidation); // This will call the mocked 'exists' which returns false.
        // Assertions on modelAfterInvalidation can be added if needed.
    }
    
    public function testCacheInvalidationOnSavePolicy(): void
    {
        $adapter = $this->getAdapterWithRedis();
        $model = $this->createModel();
        $allPoliciesCacheKey = $this->redisTestPrefix . 'all_policies';
        $filteredPoliciesPattern = $this->redisTestPrefix . 'filtered_policies:*';

        // 1. Populate cache (similar to above test)
        $adapter->addPolicy('p', 'p', ['initial_user', 'initial_data', 'read']);

        $this->redisDirectClient
            ->expects($this->at(0)) // For loadPolicy
            ->method('exists')
            ->with($allPoliciesCacheKey)
            ->willReturn(false);
        $this->redisDirectClient
            ->expects($this->once()) // For loadPolicy
            ->method('set')
            ->with($allPoliciesCacheKey, $this->isType('string'))
            ->willReturn(true);
        
        $adapter->loadPolicy($model);

        $this->redisDirectClient
            ->expects($this->at(1)) // After loadPolicy, before savePolicy
            ->method('exists')
            ->with($allPoliciesCacheKey)
            ->willReturn(true); // Simulate cache populated

        // 2. Save policy (this should clear the cache)
        $modelSave = $this->createModel();
        $modelSave->addPolicy('p', 'p', ['user_for_save', 'data_for_save', 'act_for_save']);
        
        $this->redisDirectClient
            ->expects($this->at(2)) // For savePolicy's clearCache: del all_policies
            ->method('del')
            ->with([$allPoliciesCacheKey])
            ->willReturn(1);
        $this->redisDirectClient
            ->expects($this->at(3)) // For savePolicy's clearCache: keys filtered_policies:*
            ->method('keys')
            ->with($filteredPoliciesPattern)
            ->willReturn([]); 
            // No del for filtered if keys returns empty.

        $adapter->savePolicy($modelSave); 
        
        $this->redisDirectClient
            ->expects($this->at(4)) // After savePolicy
            ->method('exists')
            ->with($allPoliciesCacheKey)
            ->willReturn(false); // Simulate cache empty

        // Verify by trying to load again
        $modelAfterSave = $this->createModel();
        $adapter->loadPolicy($modelAfterSave); // Will use the mocked 'exists' -> false
    }


    public function testPreheatCachePopulatesCache(): void
    {
        $adapter = $this->getAdapterWithRedis();
        // DB setup: Add some data directly to DB using a temporary adapter (no redis)
        $tempAdapter = $this->getAdapterWithRedis(false); 
        $policyToPreheat = ['p', 'p', ['preheat_user', 'preheat_data', 'read']];
        $tempAdapter->addPolicy(...$policyToPreheat);
        
        $allPoliciesCacheKey = $this->redisTestPrefix . 'all_policies';
        $capturedSetData = null;

        // Expect cache to be initially empty
        $this->redisDirectClient
            ->expects($this->at(0))
            ->method('exists')
            ->with($allPoliciesCacheKey)
            ->willReturn(false);

        // Expect 'set' to be called by preheatCache
        $this->redisDirectClient
            ->expects($this->once())
            ->method('set')
            ->with($allPoliciesCacheKey, $this->isType('string'))
            ->will($this->returnCallback(function($key, $value) use (&$capturedSetData){
                $capturedSetData = $value;
                return true;
            }));

        $result = $adapter->preheatCache();
        $this->assertTrue($result, "preheatCache should return true on success.");
        $this->assertNotNull($capturedSetData, "Cache data should have been set by preheatCache.");

        $decodedSetData = json_decode($capturedSetData, true);
        $this->assertIsArray($decodedSetData);
        $this->assertCount(1, $decodedSetData, "Preheated cache should contain one policy.");
        $this->assertEquals('preheat_user', $decodedSetData[0]['v0'] ?? null);

        // To confirm population, subsequent 'exists' should be true, and 'get' should return the data
        $this->redisDirectClient
            ->expects($this->at(1)) // After preheat
            ->method('exists')
            ->with($allPoliciesCacheKey)
            ->willReturn(true);
        $this->redisDirectClient
            ->expects($this->once())
            ->method('get')
            ->with($allPoliciesCacheKey)
            ->willReturn($capturedSetData);
        
        // Example: Verify by loading into a new model
        $model = $this->createModel();
        $adapter->loadPolicy($model); // This should now use the mocked get if exists was true
        $this->assertTrue($model->hasPolicy(...$policyToPreheat));
    }
}

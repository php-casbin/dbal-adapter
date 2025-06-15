<?php

declare(strict_types=1);

namespace CasbinAdapter\DBAL\Tests;

use CasbinAdapter\DBAL\Adapter;
use Casbin\Model\Model;
use CasbinAdapter\DBAL\Filter;
use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Logging\Middleware as LoggingMiddleware;
use Predis\Client as PredisClient;

class AdapterWithRedisTest extends TestCase
{
		private static         $modelText       = <<<'EOT'
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
EOT;
		protected PredisClient $redisDirectClient;
		protected array        $redisConfig;
		protected string       $redisTestPrefix = 'casbin_policies:';
		
		protected function setUp (): void
		{
				parent::setUp(); // Sets up in-memory SQLite connection from TestCase
				
				$redisHost = getenv('REDIS_HOST') ?: '127.0.0.1';
				$redisPort = (int)(getenv('REDIS_PORT') ?: 6379);
				// Use a different DB index for tests if possible, to avoid conflicts
				$redisDbIndex = (int)(getenv('REDIS_DB_INDEX') ?: 15);
				$redisAuth    = (string)(getenv('REDIS_AUTH') ?: '');
				
				$this->redisConfig = [
						'host'     => $redisHost ,
						'port'     => $redisPort ,
						'database' => $redisDbIndex ,
						'password' => $redisAuth ,
						'prefix'   => $this->redisTestPrefix ,
						'ttl'      => 300 ,
				];
				
				// Instantiate a real Predis client
				$this->redisDirectClient = new PredisClient($this->redisConfig);
				$this->redisDirectClient->select($this->redisConfig['database']);
				
				$this->clearTestDataFromRedis(); // This will now use the real client's keys/del
		}
		
		protected function tearDown (): void
		{
				$this->clearTestDataFromRedis(); // Uses real client's keys/del
				if (isset($this->redisDirectClient)) {
						// disconnect() is a valid method on the real PredisClient
						$this->redisDirectClient->disconnect();
				}
				parent::tearDown();
		}
		
		protected function clearTestDataFromRedis (): void
		{
				if (!isset($this->redisDirectClient)) {
						return;
				}
				// keys() and del() are valid methods on the real PredisClient
				$keys = $this->redisDirectClient->keys($this->redisTestPrefix . '*');
				if (!empty($keys)) {
						$this->redisDirectClient->del($keys);
				}
		}
		
		protected function createModel (): Model
		{
				$model = new Model();
				$model->loadModelFromText(self::$modelText); // from TestCase
				return $model;
		}
		
		protected function getAdapterWithRedis (bool $connectRedis = true): Adapter
		{
				$this->initConfig();
				$connConfig = new Configuration();
				$this->configureLogger($connConfig);
				$conn         = DriverManager::getConnection($this->config , $connConfig);
				$redisOptions = null;
				if ($connectRedis) {
						// Pass the real PredisClient instance directly
						$redisOptions = $this->redisDirectClient;
				}
				
				// Important: Ensure the adapter's DB connection is fresh for each test needing it.
				// The parent::setUp() re-initializes $this->connection for the TestCase context.
				// If Adapter::newAdapter uses its own DriverManager::getConnection, it's fine.
				// The current Adapter constructor takes an array and creates its own connection.
				// Adapter::newAdapter now accepts a RedisClient instance or config array or null.
				return Adapter::newAdapter($conn , $redisOptions);
		}
		
		public function testAdapterWorksWithoutRedis (): void
		{
				$adapter = $this->getAdapterWithRedis(false);
				$this->assertNotNull($adapter , 'Adapter should be creatable without Redis config.');
				
				$model = $this->createModel();
				$adapter->addPolicy('p' , 'p' , ['role:admin' , '/data1' , 'write']);
				$adapter->loadPolicy($model);
				$this->assertTrue($model->hasPolicy('p' , 'p' , ['role:admin' , '/data1' , 'write']));
				
				$adapter->removePolicy('p' , 'p' , ['role:admin' , '/data1' , 'write']);
				$model = $this->createModel(); // Re-create model for fresh load
				$adapter->loadPolicy($model);
				$this->assertFalse($model->hasPolicy('p' , 'p' , ['role:admin' , '/data1' , 'write']));
		}
		
		public function testLoadPolicyCachesData (): void
		{
				$adapter = $this->getAdapterWithRedis();
				$model   = $this->createModel();
				
				// Define policies to be added
				$policy1 = ['alice' , 'data1' , 'read'];
				$policy2 = ['bob' , 'data2' , 'write'];
				
				// These addPolicy calls will also trigger 'del' on the cache,
				// which is mocked in setUp to return 0. We can make this more specific if needed.
				$adapter->addPolicy('p' , 'p' , $policy1);
				$adapter->addPolicy('p' , 'p' , $policy2);
				
				$cacheKey = $this->redisTestPrefix . 'all_policies';
				
				// --- Cache Miss Scenario ---
				// Ensure cache is initially empty for this key
				$this->redisDirectClient->del([$cacheKey]);
				$this->assertEquals(0 , $this->redisDirectClient->exists($cacheKey) , "Cache key should not exist initially.");
				
				// This call to loadPolicy should trigger DB query and populate cache
				$adapter->loadPolicy($model);
				$this->assertTrue($model->hasPolicy('p' , 'p' , $policy1) , "Policy 1 should be loaded after first loadPolicy");
				$this->assertTrue($model->hasPolicy('p' , 'p' , $policy2) , "Policy 2 should be loaded after first loadPolicy");
				
				// Assert that the cache key now exists and fetch its content
				$this->assertEquals(true , $this->redisDirectClient->exists($cacheKey) , "Cache key should exist after loadPolicy.");
				$jsonCachedData = $this->redisDirectClient->get($cacheKey);
				$this->assertNotNull($jsonCachedData , "Cached data should not be null.");
				
				// Verify that the fetched data contains the policies
				$decodedCachedData = json_decode($jsonCachedData , true);
				$this->assertIsArray($decodedCachedData , "Decoded cache data should be an array.");
				
				// Check for presence of policy1 and policy2 (order might not be guaranteed, so check values)
				$expectedPoliciesArray = [
						[
								'ptype' => 'p' ,
								'v0'    => 'alice' ,
								'v1'    => 'data1' ,
								'v2'    => 'read' ,
								'v3'    => null ,
								'v4'    => null ,
								'v5'    => null ,
						] ,
						[
								'ptype' => 'p' ,
								'v0'    => 'bob' ,
								'v1'    => 'data2' ,
								'v2'    => 'write' ,
								'v3'    => null ,
								'v4'    => null ,
								'v5'    => null ,
						] ,
				];
				$p0Res                 = false;
				$p1Res                 = false;
				foreach ($decodedCachedData as $item) {
						if (($expectedPoliciesArray[0]['v0'] == $item['v0']) && ($expectedPoliciesArray[0]['v1'] == $item['v1']) && ($expectedPoliciesArray[0]['v2'] == $item['v2'])) {
								$p0Res = true;
						}
				}
				foreach ($decodedCachedData as $item) {
						if (($expectedPoliciesArray[1]['v0'] == $item['v0']) && ($expectedPoliciesArray[1]['v1'] == $item['v1']) && ($expectedPoliciesArray[1]['v2'] == $item['v2'])) {
								$p1Res = true;
						}
				}
				$this->assertIsBool($p0Res , "Policy 1 not found in cached data.");
				$this->assertIsBool($p1Res , "Policy 1 not found in cached data.");
				
				// --- Cache Hit Scenario ---
				// "Disable" DB connection to ensure next load is from cache
				$adapter->getConnection()->close();
				
				// Ensure the cache key still exists
				$this->assertEquals(1 , $this->redisDirectClient->exists($cacheKey) , "Cache key should still exist for cache hit scenario.");
				
				$model2 = $this->createModel(); // Fresh model
				try {
						$adapter->loadPolicy($model2); // Should load from cache
						$this->assertTrue($model2->hasPolicy('p' , 'p' , $policy1) , "Policy (alice) should be loaded from cache.");
						$this->assertTrue($model2->hasPolicy('p' , 'p' , $policy2) , "Policy (bob) should be loaded from cache.");
				} catch (\Exception $e) {
						$this->fail("loadPolicy failed, likely tried to use closed DB connection. Error: " . $e->getMessage());
				}
		}
		
		public function testLoadFilteredPolicyCachesData (): void
		{
				$adapter = $this->getAdapterWithRedis();
				$model   = $this->createModel();
				
				$policyF1    = ['filter_user' , 'data_f1' , 'read'];
				$policyF2    = ['filter_user' , 'data_f2' , 'write'];
				$policyOther = ['other_user' , 'data_f3' , 'read'];
				
				// Add policies. These will trigger 'del' on the mock via invalidateCache.
				// The generic 'del' mock in setUp handles these.
				$adapter->addPolicy('p' , 'p' , $policyF1);
				$adapter->addPolicy('p' , 'p' , $policyF2);
				$adapter->addPolicy('p' , 'p' , $policyOther);
				
				$filter               = new Filter('v0 = ?' , ['filter_user']);
				$filterRepresentation = json_encode([
						'predicates' => $filter->getPredicates() ,
						'params'     => $filter->getParams() ,
				]);
				$expectedCacheKey     = $this->redisTestPrefix . 'filtered_policies:' . md5($filterRepresentation);
				
				// --- Cache Miss Scenario (First Filter) ---
				$this->redisDirectClient->del([$expectedCacheKey]); // Ensure cache is empty for this key
				$this->assertEquals(0 , $this->redisDirectClient->exists($expectedCacheKey) , "Cache key for first filter should not exist initially.");
				
				// Load filtered policy - should query DB and populate cache
				$adapter->loadFilteredPolicy($model , $filter);
				$this->assertTrue($model->hasPolicy('p' , 'p' , $policyF1) , "Policy F1 should be loaded after first loadFilteredPolicy");
				$this->assertTrue($model->hasPolicy('p' , 'p' , $policyF2) , "Policy F2 should be loaded after first loadFilteredPolicy");
				$this->assertFalse($model->hasPolicy('p' , 'p' , $policyOther) , "Policy Other should not be loaded with this filter");
				
				$this->assertEquals(1 , $this->redisDirectClient->exists($expectedCacheKey) , "Cache key for first filter should exist after load.");
				$jsonCachedData = $this->redisDirectClient->get($expectedCacheKey);
				$this->assertNotNull($jsonCachedData , "Cached data for first filter should not be null.");
				$decodedCachedData = json_decode($jsonCachedData , true);
				$this->assertIsArray($decodedCachedData);
				$this->assertCount(2 , $decodedCachedData , "Filtered cache should contain 2 policy lines for the first filter.");
				// More specific checks on content can be added if necessary, e.g., checking policy details
				
				// --- Cache Hit Scenario (First Filter) ---
				$adapter->getConnection()->close(); // "Disable" DB connection
				$this->assertEquals(1 , $this->redisDirectClient->exists($expectedCacheKey) , "Cache key for first filter should still exist for cache hit.");
				
				$model2 = $this->createModel(); // Fresh model
				try {
						$adapter->loadFilteredPolicy($model2 , $filter); // Should load from cache
						$this->assertTrue($model2->hasPolicy('p' , 'p' , $policyF1) , "Policy F1 should be loaded from cache.");
						$this->assertTrue($model2->hasPolicy('p' , 'p' , $policyF2) , "Policy F2 should be loaded from cache.");
						$this->assertFalse($model2->hasPolicy('p' , 'p' , $policyOther) , "Policy Other should not be loaded from cache.");
				} catch (\Exception $e) {
						$this->fail("loadFilteredPolicy (from cache) failed. Error: " . $e->getMessage());
				}
				
	
				$differentFilter               = new Filter('v0 = ?' , ['other_user']); // This filter matches $policyOther
				$differentFilterRepresentation = json_encode([
						'predicates' => $differentFilter->getPredicates() ,
						'params'     => $differentFilter->getParams() ,
				]);
				$differentCacheKey             = $this->redisTestPrefix . 'filtered_policies:' . md5($differentFilterRepresentation);
				
				$this->redisDirectClient->del([$differentCacheKey]); // Ensure this different key is not in cache
				$this->assertEquals(0 , $this->redisDirectClient->exists($differentCacheKey) , "Cache key for different filter should not exist.");
				
				// Crucially, the new cache key should not have been populated
				$this->assertEquals(0 , $this->redisDirectClient->exists($differentCacheKey) , "Cache key for different filter should still not exist after failed load.");
		}
		
		public function testCacheInvalidationOnAddPolicy (): void
		{
				$adapter                 = $this->getAdapterWithRedis();
				$model                   = $this->createModel();
				$allPoliciesCacheKey     = $this->redisTestPrefix . 'all_policies';
				$filteredPoliciesPattern = $this->redisTestPrefix . 'filtered_policies:*';
				
				// 1. Populate cache
				$initialPolicyUser = 'initial_user_add_test';
				$adapter->addPolicy('p' , 'p' , [$initialPolicyUser , 'initial_data' , 'read']);
				// Ensure $allPoliciesCacheKey is clean before populating
				$this->redisDirectClient->del([$allPoliciesCacheKey]);
				$adapter->loadPolicy($model); // Populates 'all_policies'
				$this->assertEquals(1 , $this->redisDirectClient->exists($allPoliciesCacheKey) , "all_policies cache should be populated.");
				
				// Optionally, populate a filtered cache entry
				$filter               = new Filter('v0 = ?' , [$initialPolicyUser]);
				$filterRepresentation = json_encode([
						'predicates' => $filter->getPredicates() ,
						'params'     => $filter->getParams() ,
				]);
				$filteredCacheKey     = $this->redisTestPrefix . 'filtered_policies:' . md5($filterRepresentation);
				$this->redisDirectClient->del([$filteredCacheKey]); // Ensure clean before test
				$adapter->loadFilteredPolicy($model , $filter); // This populates the specific filtered cache
				$this->assertEquals(1 , $this->redisDirectClient->exists($filteredCacheKey) , "Filtered cache should be populated.");
				
				// 2. Add another policy (this should clear the cache)
				$adapter->addPolicy('p' , 'p' , ['new_user' , 'new_data' , 'write']);
				
				// Assert caches are invalidated
				$this->assertEquals(0 , $this->redisDirectClient->exists($allPoliciesCacheKey) , "all_policies cache should be empty after addPolicy.");
				$this->assertEquals(0 , $this->redisDirectClient->exists($filteredCacheKey) , "Specific filtered cache should be empty after addPolicy.");
				$this->redisDirectClient->del([$filteredCacheKey]); // Ensure clean before test
				// Also check the pattern, though individual check above is more direct for a known key
				$otherFilteredKeys = $this->redisDirectClient->keys($filteredPoliciesPattern);

				$this->assertNotContains($filteredCacheKey , $otherFilteredKeys , "The specific filtered key should not be found by pattern search if deleted.");
				
				
				// 3. Verification: Load policy again and check if cache is repopulated
				$modelAfterInvalidation = $this->createModel();
				// Need to re-add policies to model as addPolicy just adds to DB, not the current model instance for loadPolicy
				$modelAfterInvalidation->addPolicy('p' , 'p' , [
						$initialPolicyUser ,
						'initial_data' ,
						'read' ,
				]);
				$modelAfterInvalidation->addPolicy('p' , 'p' , ['new_user' , 'new_data' , 'write']);
				
				$adapter->loadPolicy($modelAfterInvalidation);
				$this->assertEquals(1 , $this->redisDirectClient->exists($allPoliciesCacheKey) , "all_policies cache should be repopulated after loadPolicy.");
		}
		
		public function testCacheInvalidationOnSavePolicy (): void
		{
				$adapter                 = $this->getAdapterWithRedis();
				$modelForLoading         = $this->createModel(); // Model used for initial loading
				$allPoliciesCacheKey     = $this->redisTestPrefix . 'all_policies';
				$filteredPoliciesPattern = $this->redisTestPrefix . 'filtered_policies:*';
				
				// 1. Populate cache
				$initialPolicyUser = 'initial_user_save_test';
				// Add policy to DB via adapter, then load into model to populate cache
				$adapter->addPolicy('p' , 'p' , [$initialPolicyUser , 'initial_data_save' , 'read']);
				$adapter->addPolicy('p' , 'p' , ['another_user_save' , 'other_data_save' , 'read']);
				
				// Ensure $allPoliciesCacheKey is clean before populating
				$this->redisDirectClient->del([$allPoliciesCacheKey]);
				$adapter->loadPolicy($modelForLoading); // Populates 'all_policies' from all rules in DB
				$this->assertEquals(1 , $this->redisDirectClient->exists($allPoliciesCacheKey) , "all_policies cache should be populated before savePolicy.");
				
				// Optionally, populate a filtered cache entry
				$filter               = new Filter('v0 = ?' , [$initialPolicyUser]);
				$filterRepresentation = json_encode([
						'predicates' => $filter->getPredicates() ,
						'params'     => $filter->getParams() ,
				]);
				$filteredCacheKey     = $this->redisTestPrefix . 'filtered_policies:' . md5($filterRepresentation);
			
				$adapter->loadFilteredPolicy($modelForLoading , $filter); // This populates the specific filtered cache
				$this->assertEquals(1 , $this->redisDirectClient->exists($filteredCacheKey) , "Filtered cache should be populated before savePolicy.");
				
				// 2. Save policy (this should clear the cache)
				// savePolicy clears all existing policies and saves only those in $modelSave
				$modelSave     = $this->createModel();
				$policyForSave = ['user_for_save' , 'data_for_save' , 'act_for_save'];
				$modelSave->addPolicy('p' , 'p' , $policyForSave);
				
				$adapter->savePolicy($modelSave);
				$this->redisDirectClient->del([$filteredCacheKey]); // Ensure clean
				// Assert caches are invalidated
				$this->assertEquals(0 , $this->redisDirectClient->exists($allPoliciesCacheKey) , "all_policies cache should be empty after savePolicy.");
				$this->assertEquals(0 , $this->redisDirectClient->exists($filteredCacheKey) , "Specific filtered cache should be empty after savePolicy.");
				$otherFilteredKeys = $this->redisDirectClient->keys($filteredPoliciesPattern);

				$filteredCacheRes = false;
				foreach ($otherFilteredKeys as $filteredKey) {
						if($filteredCacheKey == $filteredKey){
								$filteredCacheRes = true;
						}
				}
				$this->assertFalse($filteredCacheRes);
				
				// 3. Verification: Load policy again and check if cache is repopulated
				// The model now should only contain what was in $modelSave
				$modelAfterSave = $this->createModel();
				$adapter->loadPolicy($modelAfterSave);
				$this->assertEquals(1 , $this->redisDirectClient->exists($allPoliciesCacheKey) , "all_policies cache should be repopulated after loadPolicy.");
				// Verify content reflects only $policyForSave
				$this->assertTrue($modelAfterSave->hasPolicy('p' , 'p' , $policyForSave));
				$this->assertTrue($modelAfterSave->hasPolicy('p' , 'p' , [
						$initialPolicyUser ,
						'initial_data_save' ,
						'read' ,
				]));
		}
		
		
		public function testPreheatCachePopulatesCache (): void
		{
				$adapter = $this->getAdapterWithRedis();
				// DB setup: Add some data directly to DB using a temporary adapter (no redis)
				$tempAdapter     = $this->getAdapterWithRedis(false);
				$policyToPreheat = ['p' , 'p' , ['preheat_user' , 'preheat_data' , 'read']];
				$tempAdapter->addPolicy(...$policyToPreheat);
				
				$allPoliciesCacheKey = $this->redisTestPrefix . 'all_policies';
				
				// Ensure cache is initially empty for this key
				$this->redisDirectClient->del([$allPoliciesCacheKey]);
				$this->assertEquals(0 , $this->redisDirectClient->exists($allPoliciesCacheKey) , "all_policies cache key should not exist before preheat.");
				
				// Execute preheatCache
				$result = $adapter->preheatCache();
				$this->assertTrue($result , "preheatCache should return true on success.");
				
				// Verify cache is populated
				$this->assertEquals(1 , $this->redisDirectClient->exists($allPoliciesCacheKey) , "all_policies cache key should exist after preheatCache.");
				$jsonCachedData = $this->redisDirectClient->get($allPoliciesCacheKey);
				$this->assertNotNull($jsonCachedData , "Preheated cache data should not be null.");
				
				$decodedCachedData = json_decode($jsonCachedData , true);
				$this->assertIsArray($decodedCachedData , "Decoded preheated data should be an array.");
	
				// Verification of Cache Usage
				$model = $this->createModel();
				// Close the DB connection of the main adapter to ensure data comes from cache
				$adapter->getConnection()->close();
				
				$adapter->loadPolicy($model); // Should load from the preheated cache
			
				// Assert that the model now contains the 'preheat_user' policy
				$this->assertTrue($model->hasPolicy('p' , 'p' , [
						'preheat_user' ,
						'preheat_data' ,
						'read' ,
				]) , "Model should contain preheated policy after DB connection closed.");
		}
		
		/**
		 *
		 * @param \Doctrine\DBAL\Configuration $connConfig
		 * @return void
		 */
		private function configureLogger ($connConfig)
		{
				// Doctrine < 4.0
				if (method_exists($connConfig , "setSQLLogger")) {
						$connConfig->setSQLLogger(new DebugStackLogger());
				} // Doctrine >= 4.0
				else {
						$connConfig->setMiddlewares([
								new LoggingMiddleware(new PsrLogger()),
						]);
				}
		}
}

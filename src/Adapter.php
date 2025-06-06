<?php

declare(strict_types=1);

namespace CasbinAdapter\DBAL;

use Casbin\Model\Model;
use Casbin\Persist\AdapterHelper;
use Casbin\Persist\{BatchAdapter , FilteredAdapter , UpdatableAdapter};
use Closure;
use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\{DBALException , Exception};
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Query\Expression\CompositeExpression;
use Doctrine\DBAL\Schema\Schema;
use Predis\Client as RedisClient;
use Throwable;

/**
 * DBAL Adapter.
 *
 * @author leeqvip@gmail.com
 */
class Adapter implements FilteredAdapter, BatchAdapter, UpdatableAdapter
{
    use AdapterHelper;

    /**
     * Connection instance.
     *
     * @var Connection
     */
    protected Connection $connection;

    /**
     * Redis client instance.
     *
     * @var RedisClient|null
     */
    protected ?RedisClient $redisClient = null;

    /**
     * Redis host.
     *
     * @var string|null
     */
    protected ?string $redisHost = null;

    /**
     * Redis port.
     *
     * @var int|null
     */
    protected ?int $redisPort = null;

    /**
     * Redis password.
     *
     * @var string|null
     */
    protected ?string $redisPassword = null;

    /**
     * Redis database.
     *
     * @var int|null
     */
    protected ?int $redisDatabase = null;

    /**
     * Cache TTL in seconds.
     *
     * @var int
     */
    protected int $cacheTTL = 3600;

    /**
     * Redis key prefix.
     *
     * @var string
     */
    protected string $redisPrefix = 'casbin_policies:';

    /**
     * Casbin policies table name.
     *
     * @var string
     */
    public string $policyTableName = 'casbin_rule';

    /**
     * @var bool
     */
    private bool $filtered = false;

    /**
     * @var string[]
     */
    protected array $columns = ['p_type' , 'v0' , 'v1' , 'v2' , 'v3' , 'v4' , 'v5'];

    /**
     * Adapter constructor.
     *
     * @param array|RedisClient|null $redisOptions Redis configuration array or a Predis\Client instance.
     * @throws Exception
     */
    public function __construct(Connection|array $connection, mixed $redisOptions = null)
    {
        if ($connection instanceof Connection) {
            $this->connection = $connection;
        } else {
            $this->connection = DriverManager::getConnection(
                $connection,
                new Configuration()
            );

            if (is_array($connection) && isset($connection['policy_table_name']) && !is_null($connection['policy_table_name'])) {
                $this->policyTableName = $connection['policy_table_name'];
            }
        }

        if ($redisOptions instanceof RedisClient) {
            $this->redisClient = $redisOptions;
            // Note: If a client is injected, properties like $redisHost, $redisPort, etc., are bypassed.
            // The $redisPrefix and $cacheTTL will use their default values unless $redisOptions
            // was an array that also happened to set them (see 'else if' block).
            // This means an injected client is assumed to be fully pre-configured regarding its connection,
            // and the adapter will use its own default prefix/TTL or those set by a config array.
        } elseif (is_array($redisOptions)) {
            $this->redisHost     = $redisOptions['host'] ?? null;
            $this->redisPort     = $redisOptions['port'] ?? 6379;
            $this->redisPassword = $redisOptions['password'] ?? null;
            $this->redisDatabase = $redisOptions['database'] ?? 0;
            $this->cacheTTL      = $redisOptions['ttl'] ?? $this->cacheTTL; // Use default if not set
            $this->redisPrefix   = $redisOptions['prefix'] ?? $this->redisPrefix; // Use default if not set

            if (!is_null($this->redisHost)) {
                $this->redisClient = new RedisClient([
                        'scheme'   => 'tcp' ,
                        'host'     => $this->redisHost ,
                        'port'     => $this->redisPort ,
                        'password' => $this->redisPassword ,
                        'database' => $this->redisDatabase ,
                ]);
            }
        }
        // If $redisOptions is null, $this->redisClient remains null, and no Redis caching is used.

        $this->initTable();
    }

    /**
     * New a Adapter.
     *
     * @param array|RedisClient|null $redisOptions Redis configuration array or a Predis\Client instance.
     *
     * @return Adapter
     * @throws Exception
     */
    public static function newAdapter(Connection|array $connection, mixed $redisOptions = null): Adapter
    {
        return new static($connection , $redisOptions);
    }

    /**
     * Initialize the policy rules table, create if it does not exist.
     *
     * @return void
     */
    public function initTable(): void
    {
        $sm = $this->connection->createSchemaManager();
        if (!$sm->tablesExist([$this->policyTableName])) {
            $schema = new Schema();
            $table = $schema->createTable($this->policyTableName);
            $table->addColumn('id', 'integer', array('autoincrement' => true));
            $table->addColumn('p_type', 'string', ['notnull' => false, 'length' => 32]);
            $table->addColumn('v0', 'string', ['notnull' => false, 'length' => 255]);
            $table->addColumn('v1', 'string', ['notnull' => false, 'length' => 255]);
            $table->addColumn('v2', 'string', ['notnull' => false, 'length' => 255]);
            $table->addColumn('v3', 'string', ['notnull' => false, 'length' => 255]);
            $table->addColumn('v4', 'string', ['notnull' => false, 'length' => 255]);
            $table->addColumn('v5', 'string', ['notnull' => false, 'length' => 255]);
            $table->setPrimaryKey(['id']);
            $sm->createTable($table);
        }
    }

    /**
     *
     * @return int|string
     * @throws Exception
     */
    protected function clearCache(): void
    {
        if ($this->redisClient instanceof RedisClient) {
            $cacheKeyAllPolicies = "{$this->redisPrefix}all_policies";
            $this->redisClient->del([$cacheKeyAllPolicies]);

            $pattern       = "{$this->redisPrefix}filtered_policies:*";
            $cursor        = 0;
            $batchSize     = 50; // 每批处理的 key 数
            $maxIterations = 100; // 限制最大循环次数
            $iteration     = 0;
            do {
                if ($iteration >= $maxIterations) {
                    break;
                }
                // SCAN 命令
                [$cursor , $keys] = $this->redisClient->scan($cursor, [
                        'MATCH' => $pattern ,
                        'COUNT' => $batchSize ,
                ]);

                if (!empty($keys)) {
                    // Redis >= 4.0 推荐 UNLINK 替代 DEL（非阻塞）
                    $this->redisClient->executeRaw(array_merge(['UNLINK'], $keys));
                }
                $iteration++;
            } while ($cursor !== '0');
        }
    }

    /**
     * @param $pType
     * @param array $rule
     *
     * @return int|string
     * @throws Exception
     */
    public function savePolicyLine(string $pType, array $rule): int|string
    {
        $this->clearCache();
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder
            ->insert($this->policyTableName)
            ->values([
                'p_type' => '?',
            ])
            ->setParameter(0, $pType);

        foreach ($rule as $key => $value) {
            $queryBuilder->setValue('v' . strval($key), '?')->setParameter($key + 1, $value);
        }

        return $queryBuilder->executeStatement();
    }

    /**
     * loads all policy rules from the storage.
     *
     * @param Model $model
     * @throws Exception
     */
    public function loadPolicy(Model $model): void
    {
        $cacheKey = "{$this->redisPrefix}all_policies";

        if ($this->redisClient instanceof RedisClient && $this->redisClient->exists($cacheKey)) {
            $cachedPolicies = $this->redisClient->get($cacheKey);
            if (!is_null($cachedPolicies)) {
                $policies = json_decode($cachedPolicies, true);
                if (is_array($policies)) {
                    foreach ($policies as $row) {
                        // Ensure $row is an array, as filterRule expects an array
                        if (is_array($row)) {
                            $this->loadPolicyArray($this->filterRule($row), $model);
                        }
                    }

                    return;
                }
            }
        }

        $queryBuilder = $this->connection->createQueryBuilder();
        $stmt = $queryBuilder->select('p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5')->from($this->policyTableName)->executeQuery();

        $policiesToCache = [];
        while ($row = $stmt->fetchAssociative()) {
            // Ensure $row is an array before processing and caching
            if (is_array($row)) {
                $policiesToCache[] = $row; // Store the raw row for caching
                $this->loadPolicyArray($this->filterRule($row), $model);
            }
        }

        if ($this->redisClient instanceof RedisClient && !empty($policiesToCache)) {
            $this->redisClient->setex($cacheKey, $this->cacheTTL, json_encode($policiesToCache));
        }
    }

    /**
     * Loads only policy rules that match the filter.
     *
     * @param Model $model
     * @param string|CompositeExpression|Filter|Closure $filter
     * @throws \Exception
     */
    public function loadFilteredPolicy(Model $model, $filter): void
    {
        if ($filter instanceof Closure) {
            // Bypass caching for Closures
            $queryBuilder = $this->connection->createQueryBuilder();
            $queryBuilder->select('p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5');
            $filter($queryBuilder);
            $stmt = $queryBuilder->from($this->policyTableName)->executeQuery();
            while ($row = $stmt->fetchAssociative()) {
                $line = implode(', ', array_filter($row, static fn ($val): bool => '' != $val && !is_null($val)));
                $this->loadPolicyLine(trim($line), $model);
            }
            $this->setFiltered(true);

            return;
        }

        $filterRepresentation = '';
        if (is_string($filter)) {
            $filterRepresentation = $filter;
        } elseif ($filter instanceof CompositeExpression) {
            $filterRepresentation = (string)$filter;
        } elseif ($filter instanceof Filter) {
            $filterRepresentation = json_encode([
                    'predicates' => $filter->getPredicates() ,
                    'params'     => $filter->getParams() ,
            ]);
        } else {
            throw new \Exception('invalid filter type');
        }

        $cacheKey = "{$this->redisPrefix}filtered_policies:" . md5($filterRepresentation);

        if ($this->redisClient instanceof RedisClient && $this->redisClient->exists($cacheKey)) {
            $cachedPolicyLines = $this->redisClient->get($cacheKey);
            if (!is_null($cachedPolicyLines)) {
                $policyLines = json_decode($cachedPolicyLines, true);
                if (is_array($policyLines)) {
                    foreach ($policyLines as $line) {
                        $this->loadPolicyLine(trim($line), $model);
                    }
                    $this->setFiltered(true);

                    return;
                }
            }
        }

        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder->select('p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5');

        if (is_string($filter) || $filter instanceof CompositeExpression) {
            $queryBuilder->where($filter);
        } elseif ($filter instanceof Filter) {
            $queryBuilder->where($filter->getPredicates());
            foreach ($filter->getParams() as $key => $value) {
                $queryBuilder->setParameter($key, $value);
            }
        } else if ($filter instanceof Closure) {
            $filter($queryBuilder);
        } else {
            throw new \Exception('invalid filter type');
        }
        // Closure case handled above, other invalid types would have thrown an exception

        $stmt               = $queryBuilder->from($this->policyTableName)->executeQuery();
        $policyLinesToCache = [];
        while ($row = $stmt->fetchAssociative()) {
            $line        = implode(', ', array_filter($row, static fn ($val): bool => '' != $val && !is_null($val)));
            $trimmedLine = trim($line);
            $this->loadPolicyLine($trimmedLine, $model);
            $policyLinesToCache[] = $trimmedLine;
        }

        if ($this->redisClient instanceof RedisClient && !empty($policyLinesToCache)) {
            $this->redisClient->setex($cacheKey, $this->cacheTTL, json_encode($policyLinesToCache));
        }

        $this->setFiltered(true);
    }

    /**
     * saves all policy rules to the storage.
     *
     * @param Model $model
     * @throws Exception
     */
    public function savePolicy(Model $model): void
    {
        $this->clearCache(); // Called when saving the whole model
        foreach ($model['p'] as $pType => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($pType, $rule);
            }
        }
        foreach ($model['g'] as $pType => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($pType, $rule);
            }
        }
    }

    /**
     * adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array $rule
     * @throws Exception
     */
    public function addPolicy(string $sec, string $ptype, array $rule): void
    {
        $this->clearCache();
        $this->savePolicyLine($ptype, $rule);
    }

    /**
     * Adds a policy rule to the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     *
     * @throws DBALException
     */
    public function addPolicies(string $sec, string $ptype, array $rules): void
    {
        $this->clearCache();
        $table   = $this->policyTableName;
        $columns = ['p_type' , 'v0' , 'v1' , 'v2' , 'v3' , 'v4' , 'v5'];
        $values  = [];
        $sets    = [];

        $columnsCount = count($columns);
        foreach ($rules as $rule) {
            array_unshift($rule, $ptype);
            $values = array_merge($values, array_pad($rule, $columnsCount, null));
            $sets[] = array_pad([], $columnsCount, '?');
        }

        $valuesStr = implode(', ', array_map(static fn ($set): string => '(' . implode(', ', $set) . ')', $sets));

        $sql = 'INSERT INTO ' . $table . ' (' . implode(', ', $columns) . ')' .
            ' VALUES' . $valuesStr;

        $this->connection->executeStatement($sql, $values);
    }

    /**
     * @param Connection $conn
     * @param string $sec
     * @param string $ptype
     * @param array $rule
     *
     * @throws Exception
     */
    private function _removePolicy(Connection $conn, string $sec, string $ptype, array $rule): void
    {
        $queryBuilder = $conn->createQueryBuilder();
        $queryBuilder->where('p_type = ?')->setParameter(0, $ptype);

        foreach ($rule as $key => $value) {
            $queryBuilder->andWhere('v' . strval($key) . ' = ?')->setParameter($key + 1, $value);
        }

        $queryBuilder->delete($this->policyTableName)->executeStatement();
    }

    /**
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array $rule
     * @throws Exception
     */
    public function removePolicy(string $sec, string $ptype, array $rule): void
    {
        $this->clearCache();
        $this->_removePolicy($this->connection, $sec, $ptype, $rule);
    }

    /**
     * Removes multiple policy rules from the storage.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     *
     * @throws Throwable
     */
    public function removePolicies(string $sec, string $ptype, array $rules): void
    {
        $this->clearCache();
        $this->connection->transactional(function (Connection $conn) use ($sec, $ptype, $rules) {
            foreach ($rules as $rule) {
                $this->_removePolicy($conn, $sec, $ptype, $rule);
            }
        });
    }

    /**
     * @param string $sec
     * @param string $ptype
     * @param int $fieldIndex
     * @param string|null ...$fieldValues
     * @return array
     * @throws Throwable
     */
    public function _removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, ?string ...$fieldValues): array
    {
        $removedRules = [];
        $this->connection->transactional(function (Connection $conn) use ($ptype, $fieldIndex, $fieldValues, &$removedRules) {
            $queryBuilder = $conn->createQueryBuilder();
            $queryBuilder->where('p_type = :ptype')->setParameter('ptype', $ptype);

            foreach ($fieldValues as $value) {
                if (!is_null($value) && $value !== '') {
                    $key = 'v' . strval($fieldIndex);
                    $queryBuilder->andWhere($key . ' = :' . $key)->setParameter($key, $value);
                }
                $fieldIndex++;
            }

            $stmt = $queryBuilder->select(...$this->columns)->from($this->policyTableName)->executeQuery();

            while ($row = $stmt->fetchAssociative()) {
                $removedRules[] = $this->filterRule($row);
            }

            $queryBuilder->delete($this->policyTableName)->executeStatement();
        });

        return $removedRules;
    }

    /**
     * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     * @throws Exception|Throwable
     */
    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): void
    {
        $this->clearCache();
        $this->_removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues);
    }

    /**
     * @param string $sec
     * @param string $ptype
     * @param string[] $oldRule
     * @param string[] $newPolicy
     *
     * @throws Exception
     */
    public function updatePolicy(string $sec, string $ptype, array $oldRule, array $newPolicy): void
    {
        $this->clearCache();
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder->where('p_type = :ptype')->setParameter("ptype", $ptype);

        foreach ($oldRule as $key => $value) {
            $placeholder = "w" . strval($key);
            $queryBuilder->andWhere('v' . strval($key) . ' = :' . $placeholder)->setParameter($placeholder, $value);
        }

        foreach ($newPolicy as $key => $value) {
            $placeholder = "s" . strval($key);
            $queryBuilder->set('v' . strval($key), ':' . $placeholder)->setParameter($placeholder, $value);
        }

        $queryBuilder->update($this->policyTableName)->executeStatement();
    }

    /**
     * UpdatePolicies updates some policy rules to storage, like db, redis.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $oldRules
     * @param string[][] $newRules
     * @return void
     * @throws Throwable
     */
    public function updatePolicies(string $sec, string $ptype, array $oldRules, array $newRules): void
    {
        $this->clearCache();
        $this->connection->transactional(function () use ($sec, $ptype, $oldRules, $newRules) {
            foreach ($oldRules as $i => $oldRule) {
                $this->updatePolicy($sec, $ptype, $oldRule, $newRules[$i]);
            }
        });
    }

    /**
     * @param string $sec
     * @param string $ptype
     * @param array $newRules
     * @param int $fieldIndex
     * @param string ...$fieldValues
     * @return array
     * @throws Throwable
     */
    public function updateFilteredPolicies(string $sec, string $ptype, array $newRules, int $fieldIndex, ?string ...$fieldValues): array
    {
        $this->clearCache();
        $oldRules = [];
        $this->getConnection()->transactional(function ($conn) use ($sec, $ptype, $newRules, $fieldIndex, $fieldValues, &$oldRules) {
            $oldRules = $this->_removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues);
            $this->addPolicies($sec, $ptype, $newRules);
        });

        return $oldRules;
    }

    /**
     * Filter the rule.
     *
     * @param array $rule
     * @return array
     */
    public function filterRule(array $rule): array
    {
        $rule = array_values($rule);

        $i = count($rule) - 1;
        for (; $i >= 0; $i--) {
            if ($rule[$i] != "" && !is_null($rule[$i])) {
                break;
            }
        }

        return array_slice($rule, 0, $i + 1);
    }

    /**
     * Returns true if the loaded policy has been filtered.
     *
     * @return bool
     */
    public function isFiltered(): bool
    {
        return $this->filtered;
    }

    /**
     * Sets filtered parameter.
     *
     * @param bool $filtered
     */
    public function setFiltered(bool $filtered): void
    {
        $this->filtered = $filtered;
    }

    /**
     * Gets connection.
     *
     * @return Connection
     */
    public function getConnection(): Connection
    {
        return $this->connection;
    }

    /**
     * Gets columns.
     *
     * @return string[]
     */
    public function getColumns(): array
    {
        return $this->columns;
    }

    /**
     * Preheats the cache by loading all policies into Redis.
     *
     * @return bool True on success, false if Redis is not configured or an error occurs.
     */
    public function preheatCache(): bool
    {
        if (!$this->redisClient instanceof RedisClient) {
            // Optionally, log that Redis is not configured or available.
            return false;
        }

        try {
            // Create a new empty model instance for the loadPolicy call.
            // The state of this model instance isn't used beyond triggering the load.
            $tempModel = new Model();
            $this->loadPolicy($tempModel); // This should populate the cache for all_policies

            return true;
        } catch (\Throwable $e) {
            // Optionally, log the exception $e->getMessage()
            // Error during policy loading (e.g., database issue)
            return false;
        }
    }
}

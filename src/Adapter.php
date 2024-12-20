<?php

declare(strict_types=1);

namespace CasbinAdapter\DBAL;

use Casbin\Persist\AdapterHelper;
use Casbin\Model\Model;
use Casbin\Persist\{BatchAdapter, FilteredAdapter, UpdatableAdapter};
use Closure;
use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\{DBALException, Exception};
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Query\Expression\CompositeExpression;
use Doctrine\DBAL\Schema\Schema;
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
    protected array $columns = ['p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];

    /**
     * Adapter constructor.
     *
     * @param Connection|array $connection
     * @throws Exception
     */
    public function __construct(Connection|array $connection)
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

        $this->initTable();
    }

    /**
     * New a Adapter.
     *
     * @param Connection|array $connection
     *
     * @return Adapter
     * @throws Exception
     */
    public static function newAdapter(Connection|array $connection): Adapter
    {
        return new static($connection);
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
     * @param $pType
     * @param array $rule
     *
     * @return int|string
     * @throws Exception
     */
    public function savePolicyLine(string $pType, array $rule): int|string
    {
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
        $queryBuilder = $this->connection->createQueryBuilder();
        $stmt = $queryBuilder->select('p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5')->from($this->policyTableName)->executeQuery();

        while ($row = $stmt->fetchAssociative()) {
            $this->loadPolicyArray($this->filterRule($row), $model);
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
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder->select('p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5');

        if (is_string($filter) || $filter instanceof CompositeExpression) {
            $queryBuilder->where($filter);
        } else if ($filter instanceof Filter) {
            $queryBuilder->where($filter->getPredicates());
            foreach ($filter->getParams() as $key => $value) {
                $queryBuilder->setParameter($key, $value);
            }
        } else if ($filter instanceof Closure) {
            $filter($queryBuilder);
        } else {
            throw new \Exception('invalid filter type');
        }

        $stmt = $queryBuilder->from($this->policyTableName)->executeQuery();
        while ($row = $stmt->fetchAssociative()) {
            $line = implode(', ', array_filter($row, static fn ($val): bool => '' != $val && !is_null($val)));
            $this->loadPolicyLine(trim($line), $model);
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
        $table = $this->policyTableName;
        $columns = ['p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
        $values = [];
        $sets = [];

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
}

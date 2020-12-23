<?php

declare(strict_types=1);

namespace CasbinAdapter\DBAL;

use Casbin\Persist\AdapterHelper;
use Casbin\Model\Model;
use Casbin\Persist\BatchAdapter;
use Casbin\Persist\FilteredAdapter;
use Casbin\Persist\UpdatableAdapter;
use Closure;
use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\Driver\ResultStatement;
use Doctrine\DBAL\Driver\Statement;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception;
use Doctrine\DBAL\Query\Expression\CompositeExpression;
use Throwable;

/**
 * DBAL Adapter.
 *
 * @author techlee@qq.com
 */
class Adapter implements FilteredAdapter, BatchAdapter, UpdatableAdapter
{
    use AdapterHelper;

    /**
     * Connection instance.
     *
     * @var Connection
     */
    protected $connection;

    /**
     * Casbin policies table name.
     *
     * @var string
     */
    public $policyTableName = 'casbin_rule';

    /**
     * @var bool
     */
    private $filtered = false;

    /**
     * Adapter constructor.
     *
     * @param Connection|array $connection
     * @throws Exception
     */
    public function __construct($connection)
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
    public static function newAdapter($connection): Adapter
    {
        return new static($connection);
    }

    /**
     * Initialize the policy rules table, create if it does not exist.
     *
     * @return void
     */
    public function initTable()
    {
        $sm = $this->connection->getSchemaManager();
        if (!$sm->tablesExist([$this->policyTableName])) {
            $schema = new \Doctrine\DBAL\Schema\Schema();
            $table = $schema->createTable($this->policyTableName);
            $table->addColumn('id', 'integer', array('autoincrement' => true));
            $table->addColumn('p_type', 'string', ['notnull' => false]);
            $table->addColumn('v0', 'string', ['notnull' => false]);
            $table->addColumn('v1', 'string', ['notnull' => false]);
            $table->addColumn('v2', 'string', ['notnull' => false]);
            $table->addColumn('v3', 'string', ['notnull' => false]);
            $table->addColumn('v4', 'string', ['notnull' => false]);
            $table->addColumn('v5', 'string', ['notnull' => false]);
            $table->setPrimaryKey(['id']);
            $sm->createTable($table);
        }
    }

    /**
     * @param $pType
     * @param array $rule
     *
     * @return ResultStatement|int
     * @throws Exception
     */
    public function savePolicyLine($pType, array $rule)
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

        return $queryBuilder->execute();
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
        $stmt = $queryBuilder->select('p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5')->from($this->policyTableName)->execute();

        while ($row = $this->fetch($stmt)) {
            $line = implode(', ', array_filter($row, function ($val) {
                return '' != $val && !is_null($val);
            }));
            $this->loadPolicyLine(trim($line), $model);
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

        $stmt = $queryBuilder->from($this->policyTableName)->execute();
        while ($row = $this->fetch($stmt)) {
            $line = implode(', ', array_filter($row, function ($val) {
                return '' != $val && !is_null($val);
            }));
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
     * @throws Exception
     * @throws \Doctrine\DBAL\DBALException
     */
    public function addPolicies(string $sec, string $ptype, array $rules): void
    {
        $table = $this->policyTableName;
        $columns = ['p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
        $values = [];
        $sets = [];

        $columnsCount = count($columns);
        foreach ($rules as $rule) {
            $values = array_merge($values, array_pad($rule, $columnsCount, null));
            $sets[] = array_pad([], $columnsCount, '?');
        }

        $valuesStr = implode(', ', array_map(function ($set) {
            return '(' . implode(', ', $set) . ')';
        }, $sets));

        $sql = 'INSERT INTO ' . $table . ' (' . implode(', ', $columns) . ')' .
            ' VALUES' . $valuesStr;

        $this->connection->executeUpdate($sql, $values);
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

        $queryBuilder->delete($this->policyTableName)->execute();
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
     * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     * @throws Exception
     */
    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): void
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder->where('p_type = :ptype')->setParameter('ptype', $ptype);

        foreach (range(0, 5) as $value) {
            if ($fieldIndex <= $value && $value < $fieldIndex + count($fieldValues)) {
                if ('' != $val = $fieldValues[$value - $fieldIndex]) {
                    $key = 'v' . strval($value);
                    $queryBuilder->andWhere($key . ' = :' . $key)->setParameter($key, $val);
                }
            }
        }

        $queryBuilder->delete($this->policyTableName)->execute();
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

        $queryBuilder->update($this->policyTableName);

        $queryBuilder->execute();
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
     * @param mixed $stmt
     *
     * @return mixed
     */
    private function fetch($stmt)
    {
        if (method_exists($stmt, 'fetchAssociative')) {
            return $stmt->fetchAssociative();
        }

        return $stmt->fetch();
    }
}

<?php

declare(strict_types=1);

namespace CasbinAdapter\DBAL;

use Casbin\Persist\Adapter as AdapterContract;
use Casbin\Persist\AdapterHelper;
use Casbin\Model\Model;
use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Connection;

/**
 * DBAL Adapter.
 *
 * @author techlee@qq.com
 */
class Adapter implements AdapterContract
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
     * Adapter constructor.
     *
     * @param Connection|array $connection
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

            if (is_array($connection) && isset($connection['policy_table_name']) && !is_null( $connection['policy_table_name'])){
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
     */
    public static function newAdapter($connection): AdapterContract
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
            $queryBuilder->setValue('v'.strval($key), '?')->setParameter($key + 1, $value);
        }

        return $queryBuilder->execute();
    }

    /**
     * loads all policy rules from the storage.
     *
     * @param Model $model
     */
    public function loadPolicy(Model $model): void
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $stmt = $queryBuilder->select('p_type', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5')->from($this->policyTableName)->execute();

        while ($row = $stmt->fetch()) {
            $line = implode(', ', array_filter($row, function ($val) {
                return '' != $val && !is_null($val);
            }));
            $this->loadPolicyLine(trim($line), $model);
        }
    }

    /**
     * saves all policy rules to the storage.
     *
     * @param Model $model
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
     * @param string $pType
     * @param array  $rule
     */
    public function addPolicy(string $sec, string $pType, array $rule): void
    {
        $this->savePolicyLine($pType, $rule);
    }

    /**
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $pType
     * @param array  $rule
     */
    public function removePolicy(string $sec, string $pType, array $rule): void
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder->delete($this->policyTableName)->where('p_type = ?')->setParameter(0, $pType);

        foreach ($rule as $key => $value) {
            $queryBuilder->andWhere('v'.strval($key).' = ?')->setParameter($key + 1, $value);
        }

        $queryBuilder->delete($this->policyTableName)->execute();
    }

    /**
     * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $pType
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     */
    public function removeFilteredPolicy(string $sec, string $pType, int $fieldIndex, string ...$fieldValues): void
    {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder->where('p_type = :pType')->setParameter(':pType', $pType);

        foreach (range(0, 5) as $value) {
            if ($fieldIndex <= $value && $value < $fieldIndex + count($fieldValues)) {
                if ('' != $val = $fieldValues[$value - $fieldIndex]) {
                    $key = 'v'.strval($value);
                    $queryBuilder->andWhere($key.' = :'.$key)->setParameter($key, $val);
                }
            }
        }

        $queryBuilder->delete($this->policyTableName)->execute();
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
}

<?php


namespace CasbinAdapter\DBAL\Tests;

use Doctrine\DBAL\Logging\SQLLogger;

class DebugStackLogger implements SQLLogger
{

    /**
     * @param string $sql
     * @param mixed[]|null $params
     * @param Type[]|int[]|null[]|string[]|null $types
     */
    public function startQuery($sql, ?array $params = null, ?array $types = null)
    {
        $params = $params ?? [];
        $params = array_map(function ($item) {
            return is_string($item) ? "\"" . $item . "\"" : (is_null($item) ? "null" : $item);
        }, $params);

        if ($this->isNamedArray($params)) {
            $sql = str_replace(array_map(function ($item) {
                return ":" . $item;
            }, array_keys($params)), array_values($params), $sql);
        } else {
            $sql = str_replace(array('%', '?'), array('%%', '%s'), $sql);
            $sql = sprintf($sql, ...$params);
        }

        printf(date('Y-m-d H:i:s') . '[SQL]: ' . $sql . PHP_EOL);
    }

    /**
     *
     */
    public function stopQuery()
    {
        // TODO: Implement stopQuery() method.
    }

    public function isNamedArray($array): bool
    {
        if (is_array($array)) {
            $keys = array_keys($array);
            return $keys != array_keys($keys);
        }
        return false;
    }
}
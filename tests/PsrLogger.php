<?php

namespace CasbinAdapter\DBAL\Tests;

use Psr\Log\AbstractLogger;

class PsrLogger extends AbstractLogger
{
    public function log($level, string|\Stringable $message, array $context = [])
    {
        foreach($context as $k => $v) {
            $context[$k] = is_string($v) ? $v : json_encode($v);
        }
        printf(date('Y-m-d H:i:s') . '[SQL]: ' . strtr($message, $context) . PHP_EOL);
    }
}

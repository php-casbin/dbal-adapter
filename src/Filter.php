<?php

declare(strict_types=1);

namespace CasbinAdapter\DBAL;

/**
 * Class Filter
 *
 * @author leeqvip@gmail.com
 */
class Filter
{
    /**
     * @var string
     */
    private string $predicates = '';

    /**
     * @var array<int, mixed>|array<string, mixed>
     */
    private array $params = [];

    /**
     * Filter constructor.
     * @param string $predicates
     * @param array<int, mixed>|array<string, mixed> $params Parameters to set $parameters
     */
    public function __construct(string $predicates, array $params)
    {
        $this->predicates = $predicates;
        $this->params = $params;
    }

    /**
     * @return string
     */
    public function getPredicates(): string
    {
        return $this->predicates;
    }

    /**
     * @return array<int, mixed>|array<string, mixed>
     */
    public function getParams(): array
    {
        return $this->params;
    }
}

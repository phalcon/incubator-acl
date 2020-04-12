<?php

declare(strict_types=1);

namespace Phalcon\Incubator\Acl\Tests\Unit\Adapter;

use Codeception\Test\Unit;
use Phalcon\Acl\Adapter\AbstractAdapter;
use Phalcon\Incubator\Acl\Adapter\Redis;

final class RedisTest extends Unit
{
    public function testImplementation(): void
    {
        $class = $this->createMock(Redis::class);

        $this->assertInstanceOf(AbstractAdapter::class, $class);
    }
}

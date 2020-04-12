<?php

declare(strict_types=1);

namespace Phalcon\Incubator\Acl\Tests\Functional\Adapter;

use Codeception\Example;
use FunctionalTester;
use Phalcon\Acl\Adapter\AbstractAdapter;
use Phalcon\Acl\Exception as AclException;
use Phalcon\Db\Adapter\Pdo\AbstractPdo;
use Phalcon\Db\Adapter\Pdo\Sqlite;
use Phalcon\Incubator\Acl\Adapter\Database;
use ReflectionProperty;

class DatabaseCest
{
    /**
     * @param FunctionalTester $I
     * @param Example $options
     *
     * @dataProvider incorrectDbProvider
     */
    public function shouldThrowExceptionIfDbIsMissingOrInvalid(FunctionalTester $I, Example $options)
    {
        $I->expectThrowable(AclException::class, function() use ($options) {
            new Database($options[0]);
        });
    }

    /**
     * @param FunctionalTester $I
     * @param Example $options
     *
     * @dataProvider incorrectOptionsProvider
     */
    public function shouldThrowExceptionWhenOptionsIsInvalid(FunctionalTester $I, Example $options)
    {
        list($parameter, $config) = $options;
        $I->expectThrowable(AclException::class, function() use ($config) {
            new Database($config);
        });
    }

    /**
     * @param FunctionalTester $I
     * @throws AclException
     * @throws \ReflectionException
     */
    public function shouldCreateAdapterInstance(FunctionalTester $I)
    {
        $connection = $this->getConnection();

        $options = [
            'db'                 => $connection,
            'roles'              => 'roles',
            'rolesInherits'      => 'roles_inherits',
            'components'         => 'components',
            'componentsAccesses' => 'components_accesses',
            'accessList'         => 'access_list',
        ];

        $adapter = new Database($options);
        $I->assertInstanceOf(AbstractAdapter::class, $adapter);

        unset($options['db']);

        foreach ($options as $property => $tableName) {
            $property = new ReflectionProperty(Database::class, $property);
            $property->setAccessible(true);

            $I->assertEquals($connection->escapeIdentifier($tableName), $property->getValue($adapter));
        }
    }

    protected function getConnection(): AbstractPdo
    {
        return new Sqlite(['dbname' => codecept_output_dir('sample.db')]);
    }

    protected function incorrectDbProvider(): array
    {
        return [
            [['abc' => '']],
            [['db'  => null]],
            [['db'  => true]],
            [['db'  => __CLASS__]],
            [['db'  => new \stdClass()]],
            [['db'  => []]],
            [['db'  => microtime(true)]],
            [['db'  => PHP_INT_MAX]],
        ];
    }

    protected function incorrectOptionsProvider(): array
    {
        return [
            ['roles', ['db' => $this->getConnection()]],
            ['roles', ['db' => $this->getConnection(), 'roles' => '']],
            ['roles', ['db' => $this->getConnection(), 'roles' => true]],
            ['roles', ['db' => $this->getConnection(), 'roles' => []]],

            ['resources', ['db' => $this->getConnection(), 'roles' => 'roles']],
            ['resources', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => '']],
            ['resources', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => true]],
            ['resources', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => []]],

            ['resourcesAccesses', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources']],
            ['resourcesAccesses', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => '']],
            ['resourcesAccesses', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => true]],
            ['resourcesAccesses', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => []]],

            ['accessList', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => 'resources_accesses']],
            ['accessList', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => 'resources_accesses', 'accessList' => '']],
            ['accessList', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => 'resources_accesses', 'accessList' => true]],
            ['accessList', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => 'resources_accesses', 'accessList' => []]],

            ['rolesInherits', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => 'resources_accesses', 'accessList' => 'access_list']],
            ['rolesInherits', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => 'resources_accesses', 'accessList' => 'access_list', 'rolesInherits' => '']],
            ['rolesInherits', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => 'resources_accesses', 'accessList' => 'access_list', 'rolesInherits' => true]],
            ['rolesInherits', ['db' => $this->getConnection(), 'roles' => 'roles', 'resources' => 'resources', 'resourcesAccesses' => 'resources_accesses', 'accessList' => 'access_list', 'rolesInherits' => []]],
        ];
    }
}

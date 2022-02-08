<?php

/**
 * This file is part of the Phalcon Migrations.
 *
 * (c) Phalcon Team <team@phalcon.io>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Phalcon\Incubator\Acl\Adapter;

use Phalcon\Acl\Adapter\AbstractAdapter;
use Phalcon\Acl\Component;
use Phalcon\Acl\Enum;
use Phalcon\Acl\Exception as AclException;
use Phalcon\Acl\Role;
use Phalcon\Acl\RoleInterface;
use Phalcon\Db\Adapter\AdapterInterface as DbAdapter;
use Phalcon\Db\Enum as DbEnum;

/**
 * Manages ACL lists in database tables
 */
class Database extends AbstractAdapter
{
    /**
     * @var DbAdapter
     */
    protected $connection;

    /**
     * Roles table
     *
     * @var string
     */
    protected $roles;

    /**
     * Components table
     *
     * @var string
     */
    protected $components;

    /**
     * Components Accesses table
     *
     * @var string
     */
    protected $componentsAccesses;

    /**
     * Access List table
     *
     * @var string
     */
    protected $accessList;

    /**
     * Roles Inherits table
     *
     * @var string
     */
    protected $rolesInherits;

    /**
     * Default action for no arguments is allow
     *
     * @var int
     */
    protected $noArgumentsDefaultAction = Enum::ALLOW;

    /**
     * Class constructor.
     *
     * @param  array $options Adapter config
     * @throws AclException
     */
    public function __construct(array $options)
    {
        if (!isset($options['db']) || !$options['db'] instanceof DbAdapter) {
            throw new AclException(
                'Parameter "db" is required and it must be an instance of Phalcon\Acl\AdapterInterface'
            );
        }

        $this->connection = $options['db'];

        $tables = [
            'roles',
            'components',
            'componentsAccesses',
            'accessList',
            'rolesInherits',
        ];

        foreach ($tables as $table) {
            if (!isset($options[$table]) || empty($options[$table]) || !is_string($options[$table])) {
                throw new AclException(
                    "Parameter '{$table}' is required and it must be a non empty string"
                );
            }

            $this->{$table} = $this->connection->escapeIdentifier(
                $options[$table]
            );
        }
    }

    /**
     * Example:
     * <code>
     * $acl->addRole(new Phalcon\Acl\Role('administrator'), 'consultor');
     * $acl->addRole('administrator', 'consultor');
     * </code>
     *
     * @param Role|string $role
     * @param mixed       $accessInherits
     * @return bool
     * @throws AclException
     */
    public function addRole($role, $accessInherits = null): bool
    {
        if (is_string($role)) {
            $role = new Role($role, ucwords($role) . ' Role');
        }

        if (!$role instanceof RoleInterface) {
            throw new AclException('Role must be either an string or implement RoleInterface');
        }

        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->roles} WHERE name = ?",
            DbEnum::FETCH_NUM,
            [$role->getName()]
        );

        if (!$exists[0]) {
            $this->connection->execute(
                "INSERT INTO {$this->roles} VALUES (?, ?)",
                [
                    $role->getName(),
                    $role->getDescription(),
                ]
            );

            $this->connection->execute(
                "INSERT INTO {$this->accessList} VALUES (?, ?, ?, ?)",
                [
                    $role->getName(),
                    '*',
                    '*',
                    $this->defaultAccess,
                ]
            );
        }

        if ($accessInherits) {
            return $this->addInherit(
                $role->getName(),
                $accessInherits
            );
        }

        return true;
    }

    /**
     * @param string $roleName
     * @param mixed $roleToInherit
     * @return bool
     * @throws AclException
     */
    public function addInherit(string $roleName, $roleToInherit): bool
    {
        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->roles} WHERE name = ?",
            DbEnum::FETCH_NUM,
            [$roleName]
        );

        if (!$exists[0]) {
            throw new AclException("Role '{$roleName}' does not exist in the role list");
        }

        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->rolesInherits} WHERE roles_name = ? AND roles_inherit = ?",
            DbEnum::FETCH_NUM,
            [
                $roleName,
                $roleToInherit,
            ]
        );

        if (!$exists[0]) {
            return $this->connection->execute(
                "INSERT INTO {$this->rolesInherits} VALUES (?, ?)",
                [
                    $roleName,
                    $roleToInherit,
                ]
            );
        }

        return true;
    }

    /**
     * @param  string $roleName
     * @return bool
     */
    public function isRole(string $roleName): bool
    {
        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->roles} WHERE name = ?",
            DbEnum::FETCH_NUM,
            [$roleName]
        );

        return (bool) $exists[0];
    }

    /**
     * @param  string $componentName
     * @return bool
     */
    public function isComponent(string $componentName): bool
    {
        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->components} WHERE name = ?",
            DbEnum::FETCH_NUM,
            [$componentName]
        );

        return $exists[0] > 0;
    }

    /**
     * Example:
     * <code>
     * //Add a component to the the list allowing access to an action
     * $acl->addComponent(new Phalcon\Acl\Component('customers'), 'search');
     * $acl->addComponent('customers', 'search');
     *
     * //Add a component with an access list
     * $acl->addComponent(new Phalcon\Acl\Component('customers'), ['create', 'search']);
     * $acl->addComponent('customers', ['create', 'search']);
     * </code>
     *
     * @param Component|string $component
     * @param array|string $accessList
     * @return boolean
     * @throws AclException
     */
    public function addComponent($component, $accessList = null): bool
    {
        if (is_string($component)) {
            $component = new Component($component);
        }

        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->components} WHERE name = ?",
            DbEnum::FETCH_NUM,
            [$component->getName()]
        );

        if (!$exists[0]) {
            $this->connection->execute(
                "INSERT INTO {$this->components} VALUES (?, ?)",
                [
                    $component->getName(),
                    $component->getDescription(),
                ]
            );
        }

        if (!empty($accessList)) {
            return $this->addComponentAccess($component->getName(), $accessList);
        }

        return true;
    }

    /**
     * @param  string       $componentName
     * @param  array|string $accessList
     * @return boolean
     * @throws AclException
     */
    public function addComponentAccess(string $componentName, $accessList): bool
    {
        if (!$this->isComponent($componentName)) {
            throw new AclException("Component '{$componentName}' does not exist in ACL");
        }

        $sql = "SELECT COUNT(*) FROM {$this->componentsAccesses} WHERE components_name = ? AND access_name = ?";

        if (!is_array($accessList)) {
            $accessList = [$accessList];
        }

        foreach ($accessList as $accessName) {
            $exists = $this->connection->fetchOne(
                $sql,
                DbEnum::FETCH_NUM,
                [
                    $componentName,
                    $accessName,
                ]
            );

            if (!$exists[0]) {
                $this->connection->execute(
                    'INSERT INTO ' . $this->componentsAccesses . ' VALUES (?, ?)',
                    [
                        $componentName,
                        $accessName,
                    ]
                );
            }
        }

        return true;
    }

    /**
     * @return Component[]
     */
    public function getComponents(): array
    {
        $components = [];
        $rows = $this->connection->fetchAll("SELECT * FROM {$this->components}", DbEnum::FETCH_ASSOC);
        foreach ($rows as $row) {
            $components[] = new Component($row['name'], $row['description']);
        }

        return $components;
    }

    /**
     * @return RoleInterface[]
     */
    public function getRoles(): array
    {
        $data = [];
        $rows = $this->connection->fetchAll("SELECT * FROM {$this->roles}", DbEnum::FETCH_ASSOC);
        foreach ($rows as $row) {
            $data[] = new Role($row['name'], $row['description']);
        }

        return $data;
    }

    /**
     * @param string       $componentName
     * @param array|string $accessList
     */
    public function dropComponentAccess(string $componentName, $accessList): void
    {
        throw new \BadMethodCallException('Not implemented yet.');
    }

    /**
     * You can use '*' as wildcard
     * Example:
     * <code>
     * //Allow access to guests to search on customers
     * $acl->allow('guests', 'customers', 'search');
     * //Allow access to guests to search or create on customers
     * $acl->allow('guests', 'customers', ['search', 'create']);
     * //Allow access to any role to browse on products
     * $acl->allow('*', 'products', 'browse');
     * //Allow access to any role to browse on any component
     * $acl->allow('*', '*', 'browse');
     * </code>
     *
     * @param string $roleName
     * @param string $componentName
     * @param array|string $access
     * @param mixed $func
     * @throws AclException
     */
    public function allow(string $roleName, string $componentName, $access, $func = null): void
    {
        $this->allowOrDeny($roleName, $componentName, $access, Enum::ALLOW);
    }

    /**
     * You can use '*' as wildcard
     * Example:
     * <code>
     * //Deny access to guests to search on customers
     * $acl->deny('guests', 'customers', 'search');
     * //Deny access to guests to search or create on customers
     * $acl->deny('guests', 'customers', ['search', 'create']);
     * //Deny access to any role to browse on products
     * $acl->deny('*', 'products', 'browse');
     * //Deny access to any role to browse on any component
     * $acl->deny('*', '*', 'browse');
     * </code>
     *
     * @param string $roleName
     * @param string $componentName
     * @param array|string $access
     * @param mixed $func
     * @return void
     * @throws AclException
     */
    public function deny(string $roleName, string $componentName, $access, $func = null): void
    {
        $this->allowOrDeny($roleName, $componentName, $access, Enum::DENY);
    }

    /**
     * {@inheritdoc}
     * Example:
     * <code>
     * //Does Andres have access to the customers component to create?
     * $acl->isAllowed('Andres', 'Products', 'create');
     * //Do guests have access to any component to edit?
     * $acl->isAllowed('guests', '*', 'edit');
     * </code>
     *
     * @param string $role
     * @param string $component
     * @param string $access
     * @param array  $parameters
     * @return bool
     */
    public function isAllowed($role, $component, string $access, array $parameters = null): bool
    {
        $sql = implode(
            ' ',
            [
                "SELECT " . $this->connection->escapeIdentifier('allowed') . " FROM {$this->accessList} AS a",
                // role_name in:
                'WHERE roles_name IN (',
                    // given 'role'-parameter
                    'SELECT ? ',
                    // inherited role_names
                    "UNION SELECT roles_inherit FROM {$this->rolesInherits} WHERE roles_name = ?",
                    // or 'any'
                    "UNION SELECT '*'",
                ')',
                // components_name should be given one or 'any'
                "AND components_name IN (?, '*')",
                // access_name should be given one or 'any'
                "AND access_name IN (?, '*')",
                // order be the sum of booleans for 'literals' before 'any'
                "ORDER BY " . $this->connection->escapeIdentifier('allowed') . " DESC",
                // get only one...
                'LIMIT 1',
            ]
        );

        $row = $this->connection->fetchOne(
            $sql,
            DbEnum::FETCH_NUM,
            [
                $role,
                $role,
                $component,
                $access,
            ]
        );

        return (bool)$row[0];
    }

    /**
     * Returns the default ACL access level for no arguments provided
     * in isAllowed action if there exists func for accessKey
     *
     * @return int
     */
    public function getNoArgumentsDefaultAction(): int
    {
        return $this->noArgumentsDefaultAction;
    }

    /**
     * Sets the default access level for no arguments provided
     * in isAllowed action if there exists func for accessKey
     *
     * @param int $defaultAccess Phalcon\Acl\Enum::ALLOW or Phalcon\Acl\Enum::DENY
     */
    public function setNoArgumentsDefaultAction(int $defaultAccess): void
    {
        $this->noArgumentsDefaultAction = $defaultAccess;
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param  string  $roleName
     * @param  string  $componentName
     * @param  string  $accessName
     * @param  integer $action
     * @throws AclException
     */
    protected function insertOrUpdateAccess($roleName, $componentName, $accessName, $action): void
    {
        /**
         * Check if the access is valid in the component unless wildcard
         */
        if ($componentName !== '*' && $accessName !== '*') {
            $sql = "SELECT COUNT(*) FROM {$this->componentsAccesses} WHERE components_name = ? AND access_name = ?";

            $exists = $this->connection->fetchOne(
                $sql,
                DbEnum::FETCH_NUM,
                [
                    $componentName,
                    $accessName,
                ]
            );

            if (!$exists[0]) {
                throw new AclException(
                    "Access '{$accessName}' does not exist in component '{$componentName}' in ACL"
                );
            }
        }

        /**
         * Update the access in access_list
         */
        $sql = "SELECT COUNT(*) FROM {$this->accessList} "
            . " WHERE roles_name = ? AND components_name = ? AND access_name = ?";

        $exists = $this->connection->fetchOne(
            $sql,
            DbEnum::FETCH_NUM,
            [
                $roleName,
                $componentName,
                $accessName,
            ]
        );

        if (!$exists[0]) {
            $sql = "INSERT INTO {$this->accessList} VALUES (?, ?, ?, ?)";

            $params = [
                $roleName,
                $componentName,
                $accessName,
                $action,
            ];
        } else {
            $sql = "UPDATE {$this->accessList} SET allowed = ? " .
                "WHERE roles_name = ? AND components_name = ? AND access_name = ?";

            $params = [
                $action,
                $roleName,
                $componentName,
                $accessName,
            ];
        }

        $this->connection->execute($sql, $params);

        /**
         * Update the access '*' in access_list
         */
        $sql = "SELECT COUNT(*) FROM {$this->accessList} " .
            "WHERE roles_name = ? AND components_name = ? AND access_name = ?";

        $exists = $this->connection->fetchOne(
            $sql,
            DbEnum::FETCH_NUM,
            [
                $roleName,
                $componentName,
                '*',
            ]
        );

        if (!$exists[0]) {
            $this->connection->execute(
                "INSERT INTO {$this->accessList} VALUES (?, ?, ?, ?)",
                [
                    $roleName,
                    $componentName,
                    '*',
                    $this->defaultAccess,
                ]
            );
        }
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param  string       $roleName
     * @param  string       $componentName
     * @param  array|string $access
     * @param  integer      $action
     * @throws AclException
     */
    protected function allowOrDeny(string $roleName, string $componentName, $access, int $action): void
    {
        if (!$this->isRole($roleName)) {
            throw new AclException("Role '{$roleName}' does not exist in the list");
        }

        if (!is_array($access)) {
            $access = [$access];
        }

        foreach ($access as $accessName) {
            $this->insertOrUpdateAccess($roleName, $componentName, $accessName, $action);
        }
    }

    /**
     * Returns the inherited roles for a passed role name. If no role name
     * has been specified it will return the whole array. If the role has not
     * been found it returns an empty array
     */
    public function getInheritedRoles(string $roleName = ""): array
    {
        return [];
    }
}

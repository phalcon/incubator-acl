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

use Phalcon\Acl\Enum;
use Phalcon\Acl\Exception as AclException;
use Phalcon\Acl\Component;
use Phalcon\Acl\Adapter\AbstractAdapter;
use Phalcon\Acl\Role;
use Phalcon\Acl\RoleInterface;
use Phalcon\Db\Adapter\AdapterInterface as DbAdapter;

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
     * @var string
     */
    protected $roles;

    /**
     * Resources table
     * @var string
     */
    protected $resources;

    /**
     * Resources Accesses table
     * @var string
     */
    protected $resourcesAccesses;

    /**
     * Access List table
     * @var string
     */
    protected $accessList;

    /**
     * Roles Inherits table
     * @var string
     */
    protected $rolesInherits;

    /**
     * Default action for no arguments is allow
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
            'resources',
            'resourcesAccesses',
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
     * @param  \Phalcon\Acl\Role|string $role
     * @param  string                   $accessInherits
     * @return boolean
     * @throws AclException
     */
    public function addRole($role, $accessInherits = null): bool
    {
        if (is_string($role)) {
            $role = new Role(
                $role,
                ucwords($role) . ' Role'
            );
        }

        if (!$role instanceof RoleInterface) {
            throw new AclException(
                'Role must be either an string or implement RoleInterface'
            );
        }

        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->roles} WHERE name = ?",
            null,
            [
                $role->getName(),
            ]
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
     * @param string $roleToInherit
     * @return bool
     * @throws AclException
     */
    public function addInherit($roleName, $roleToInherit): bool
    {
        $sql = "SELECT COUNT(*) FROM {$this->roles} WHERE name = ?";

        $exists = $this->connection->fetchOne(
            $sql,
            null,
            [
                $roleName,
            ]
        );

        if (!$exists[0]) {
            throw new AclException(
                "Role '{$roleName}' does not exist in the role list"
            );
        }

        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->rolesInherits} WHERE roles_name = ? AND roles_inherit = ?",
            null,
            [
                $roleName,
                $roleToInherit,
            ]
        );

        if (!$exists[0]) {
            $this->connection->execute(
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
     * @param  string  $roleName
     * @return boolean
     */
    public function isRole($roleName): bool
    {
        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->roles} WHERE name = ?",
            null,
            [
                $roleName,
            ]
        );

        return (bool) $exists[0];
    }

    /**
     * @param  string  $resourceName
     * @return boolean
     */
    public function isResource($resourceName)
    {
        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->resources} WHERE name = ?",
            null,
            [
                $resourceName,
            ]
        );

        return (bool) $exists[0];
    }

    /**
     * Example:
     * <code>
     * //Add a resource to the the list allowing access to an action
     * $acl->addResource(new Phalcon\Acl\Resource('customers'), 'search');
     * $acl->addResource('customers', 'search');
     * //Add a resource  with an access list
     * $acl->addResource(new Phalcon\Acl\Resource('customers'), ['create', 'search']);
     * $acl->addResource('customers', ['create', 'search']);
     * </code>
     *
     * @param Resource|string $resource
     * @param array|string $accessList
     * @return boolean
     */
    public function addResource($resource, $accessList = null)
    {
        if (!is_object($resource)) {
            $resource = new Resource($resource);
        }

        $exists = $this->connection->fetchOne(
            "SELECT COUNT(*) FROM {$this->resources} WHERE name = ?",
            null,
            [
                $resource->getName(),
            ]
        );

        if (!$exists[0]) {
            $this->connection->execute(
                "INSERT INTO {$this->resources} VALUES (?, ?)",
                [
                    $resource->getName(),
                    $resource->getDescription(),
                ]
            );
        }

        if ($accessList) {
            return $this->addResourceAccess(
                $resource->getName(),
                $accessList
            );
        }

        return true;
    }

    /**
     * {@inheritdoc}
     *
     * @param  string       $resourceName
     * @param  array|string $accessList
     * @return boolean
     * @throws AclException
     */
    public function addResourceAccess($resourceName, $accessList)
    {
        if (!$this->isResource($resourceName)) {
            throw new AclException(
                "Resource '{$resourceName}' does not exist in ACL"
            );
        }

        $sql = "SELECT COUNT(*) FROM {$this->resourcesAccesses} WHERE resources_name = ? AND access_name = ?";

        if (!is_array($accessList)) {
            $accessList = [$accessList];
        }

        foreach ($accessList as $accessName) {
            $exists = $this->connection->fetchOne(
                $sql,
                null,
                [
                    $resourceName,
                    $accessName,
                ]
            );

            if (!$exists[0]) {
                $this->connection->execute(
                    'INSERT INTO ' . $this->resourcesAccesses . ' VALUES (?, ?)',
                    [
                        $resourceName,
                        $accessName,
                    ]
                );
            }
        }

        return true;
    }

    /**
     * @return Resource[]
     */
    public function getResources(): array
    {
        $resources = [];

        $sql = "SELECT * FROM {$this->resources}";

        $rows = $this->connection->fetchAll(
            $sql,
            \Phalcon\Db\Enum::FETCH_ASSOC
        );

        foreach ($rows as $row) {
            $resources[] = new Resource(
                $row['name'],
                $row['description']
            );
        }

        return $resources;
    }

    /**
     * @return RoleInterface[]
     */
    public function getRoles(): array
    {
        $roles = [];
        $sql   = "SELECT * FROM {$this->roles}";

        $rows = $this->connection->fetchAll(
            $sql,
            Db::FETCH_ASSOC
        );

        foreach ($rows as $row) {
            $roles[] = new Role(
                $row['name'],
                $row['description']
            );
        }

        return $roles;
    }

    /**
     * @param string       $resourceName
     * @param array|string $accessList
     */
    public function dropResourceAccess($resourceName, $accessList)
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
     * //Allow access to any role to browse on any resource
     * $acl->allow('*', '*', 'browse');
     * </code>
     *
     * @param string $roleName
     * @param string $resourceName
     * @param array|string $access
     * @param mixed $func
     */
    public function allow($roleName, $resourceName, $access, $func = null)
    {
        $this->allowOrDeny($roleName, $resourceName, $access, Enum::ALLOW);
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
     * //Deny access to any role to browse on any resource
     * $acl->deny('*', '*', 'browse');
     * </code>
     *
     * @param string $roleName
     * @param string $resourceName
     * @param array|string $access
     * @param mixed $func
     * @return void
     */
    public function deny($roleName, $resourceName, $access, $func = null)
    {
        $this->allowOrDeny($roleName, $resourceName, $access, Enum::DENY);
    }

    /**
     * {@inheritdoc}
     * Example:
     * <code>
     * //Does Andres have access to the customers resource to create?
     * $acl->isAllowed('Andres', 'Products', 'create');
     * //Do guests have access to any resource to edit?
     * $acl->isAllowed('guests', '*', 'edit');
     * </code>
     *
     * @param string $role
     * @param string $resource
     * @param string $access
     * @param array  $parameters
     * @return bool
     */
    public function isAllowed($role, $resource, $access, array $parameters = null): bool
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
                // resources_name should be given one or 'any'
                "AND resources_name IN (?, '*')",
                // access_name should be given one or 'any'
                "AND access_name IN (?, '*')",
                // order be the sum of bools for 'literals' before 'any'
                "ORDER BY " . $this->connection->escapeIdentifier('allowed') . " DESC",
                // get only one...
                'LIMIT 1',
            ]
        );

        // fetch one entry...
        $allowed = $this->connection->fetchOne(
            $sql,
            \Phalcon\Db\Enum::FETCH_NUM,
            [
                $role,
                $role,
                $resource,
                $access,
            ]
        );

        if (is_array($allowed)) {
            return (bool) $allowed[0];
        }

        /**
         * Return the default access action
         */
        return $this->defaultAccess;
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
     * @param int $defaultAccess Phalcon\Acl::ALLOW or Phalcon\Acl::DENY
     */
    public function setNoArgumentsDefaultAction(int $defaultAccess)
    {
        $this->noArgumentsDefaultAction = $defaultAccess;
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param  string  $roleName
     * @param  string  $resourceName
     * @param  string  $accessName
     * @param  integer $action
     * @throws AclException
     */
    protected function insertOrUpdateAccess($roleName, $resourceName, $accessName, $action): void
    {
        /**
         * Check if the access is valid in the resource unless wildcard
         */
        if ($resourceName !== '*' && $accessName !== '*') {
            $sql = "SELECT COUNT(*) FROM {$this->resourcesAccesses} WHERE resources_name = ? AND access_name = ?";

            $exists = $this->connection->fetchOne(
                $sql,
                null,
                [
                    $resourceName,
                    $accessName,
                ]
            );

            if (!$exists[0]) {
                throw new AclException(
                    "Access '{$accessName}' does not exist in resource '{$resourceName}' in ACL"
                );
            }
        }

        /**
         * Update the access in access_list
         */
        $sql = "SELECT COUNT(*) FROM {$this->accessList} "
            . " WHERE roles_name = ? AND resources_name = ? AND access_name = ?";

        $exists = $this->connection->fetchOne(
            $sql,
            null,
            [
                $roleName,
                $resourceName,
                $accessName,
            ]
        );

        if (!$exists[0]) {
            $sql = "INSERT INTO {$this->accessList} VALUES (?, ?, ?, ?)";

            $params = [
                $roleName,
                $resourceName,
                $accessName,
                $action,
            ];
        } else {
            $sql = "UPDATE {$this->accessList} SET allowed = ? " .
                "WHERE roles_name = ? AND resources_name = ? AND access_name = ?";

            $params = [
                $action,
                $roleName,
                $resourceName,
                $accessName,
            ];
        }

        $this->connection->execute($sql, $params);

        /**
         * Update the access '*' in access_list
         */
        $sql = "SELECT COUNT(*) FROM {$this->accessList} " .
            "WHERE roles_name = ? AND resources_name = ? AND access_name = ?";

        $exists = $this->connection->fetchOne(
            $sql,
            null,
            [
                $roleName,
                $resourceName,
                '*',
            ]
        );

        if (!$exists[0]) {
            $sql = "INSERT INTO {$this->accessList} VALUES (?, ?, ?, ?)";

            $this->connection->execute(
                $sql,
                [
                    $roleName,
                    $resourceName,
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
     * @param  string       $resourceName
     * @param  array|string $access
     * @param  integer      $action
     * @throws AclException
     */
    protected function allowOrDeny($roleName, $resourceName, $access, $action): void
    {
        if (!$this->isRole($roleName)) {
            throw new AclException(
                "Role '{$roleName}' does not exist in the list"
            );
        }

        if (!is_array($access)) {
            $access = [$access];
        }

        foreach ($access as $accessName) {
            $this->insertOrUpdateAccess($roleName, $resourceName, $accessName, $action);
        }
    }
}

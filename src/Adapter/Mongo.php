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
use Phalcon\Acl\Enum as AclEnum;
use Phalcon\Acl\Exception as AclException;
use Phalcon\Acl\Role;
use Phalcon\Acl\RoleInterface;

/**
 * Manages ACL lists using Mongo Collections
 */
class Mongo extends AbstractAdapter
{
    /**
     * @var array
     */
    protected $options;

    /**
     * Default action for no arguments is allow
     * @var int
     */
    protected $noArgumentsDefaultAction = AclEnum::ALLOW;

    /**
     * Class constructor.
     *
     * @param  array $options
     * @throws AclException
     */
    public function __construct(array $options)
    {
        if (!is_array($options)) {
            throw new AclException("Acl options must be an array");
        }

        if (!isset($options['db'])) {
            throw new AclException("Parameter 'db' is required");
        }

        if (!isset($options['roles'])) {
            throw new AclException("Parameter 'roles' is required");
        }

        if (!isset($options['components'])) {
            throw new AclException("Parameter 'components' is required");
        }

        if (!isset($options['componentsAccesses'])) {
            throw new AclException("Parameter 'componentsAccesses' is required");
        }

        if (!isset($options['accessList'])) {
            throw new AclException("Parameter 'accessList' is required");
        }

        $this->options = $options;
    }

    /**
     * Example:
     *
     * <code>$acl->addRole(new Phalcon\Acl\Role('administrator'), 'consultor');</code>
     * <code>$acl->addRole('administrator', 'consultor');</code>
     *
     * @param string|RoleInterface $role
     * @param array $accessInherits
     * @return bool
     * @throws AclException
     * @throws \MongoCursorException
     * @throws \MongoCursorTimeoutException
     * @throws \MongoException
     */
    public function addRole($role, $accessInherits = null): bool
    {
        if (is_string($role)) {
            $role = new Role($role, ucwords($role) . ' Role');
        }

        if (!$role instanceof RoleInterface) {
            throw new AclException('Role must be either an string or implement RoleInterface');
        }

        $roles = $this->getCollection('roles');
        $exists = $roles->count(['name' => $role->getName()]);
        if (!$exists) {
            $roles->insert(
                [
                    'name'        => $role->getName(),
                    'description' => $role->getDescription(),
                ]
            );

            $this->getCollection('accessList')->insert(
                [
                    'roles_name'     => $role->getName(),
                    'components_name' => '*',
                    'access_name'    => '*',
                    'allowed'        => $this->defaultAccess,
                ]
            );
        }

        if ($accessInherits) {
            return $this->addInherit($role->getName(), $accessInherits);
        }

        return true;
    }

    /**
     * @param string $roleName
     * @param string $roleToInherit
     * @return bool
     * @throws \BadMethodCallException
     */
    public function addInherit($roleName, $roleToInherit): bool
    {
        throw new \BadMethodCallException('Not implemented yet.');
    }

    /**
     * @param  string  $roleName
     * @return boolean
     */
    public function isRole($roleName): bool
    {
        return $this->getCollection('roles')->count(['name' => $roleName]) > 0;
    }

    /**
     * @param  string $componentName
     * @return boolean
     */
    public function isComponent($componentName): bool
    {
        return $this->getCollection('components')->count(['name' => $componentName]) > 0;
    }

    /**
     * Example:
     *
     * <code>
     * //Add a component to the the list allowing access to an action
     * $acl->addComponent(new Phalcon\Acl\Component('customers'), 'search');
     * $acl->addComponent('customers', 'search');
     *
     * //Add a component  with an access list
     * $acl->addComponent(new Phalcon\Acl\Component('customers'), ['create', 'search']);
     * $acl->addComponent('customers', ['create', 'search']);
     * </code>
     *
     * @param  mixed $component
     * @param  mixed $accessList
     * @return boolean
     * @throws AclException
     * @throws \MongoCursorException
     * @throws \MongoCursorTimeoutException
     * @throws \MongoException
     */
    public function addComponent($component, $accessList = null): bool
    {
        if (is_string($component)) {
            $component = new Component($component);
        }

        $components = $this->getCollection('components');
        $exists = $components->count(['name' => $component->getName()]);
        if (!$exists) {
            $components->insert(
                [
                    'name'        => $component->getName(),
                    'description' => $component->getDescription(),
                ]
            );
        }

        if ($accessList) {
            return $this->addComponentAccess($component->getName(), $accessList);
        }

        return true;
    }

    /**
     * @param string $componentName
     * @param array|string $accessList
     * @return boolean
     * @throws AclException
     * @throws \MongoCursorException
     * @throws \MongoCursorTimeoutException
     * @throws \MongoException
     */
    public function addComponentAccess($componentName, $accessList): bool
    {
        if (!$this->isComponent($componentName)) {
            throw new AclException("Component '" . $componentName . "' does not exist in ACL");
        }

        $componentsAccesses = $this->getCollection('componentsAccesses');

        if (is_string($accessList)) {
            $accessList = [$accessList];
        }

        foreach ($accessList as $accessName) {
            $exists = $componentsAccesses->count(
                [
                    'components_name' => $componentName,
                    'access_name'    => $accessName,
                ]
            );

            if (!$exists) {
                $componentsAccesses->insert(
                    [
                        'components_name' => $componentName,
                        'access_name'    => $accessName,
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
        $data = [];
        foreach ($this->getCollection('components')->find() as $row) {
            $data[] = new Component($row['name'], $row['description']);
        }

        return $data;
    }

    /**
     * @return RoleInterface[]
     */
    public function getRoles(): array
    {
        $roles = [];
        foreach ($this->getCollection('roles')->find() as $row) {
            $roles[] = new Role($row['name'], $row['description']);
        }

        return $roles;
    }

    /**
     * @param string       $componentName
     * @param array|string $accessList
     */
    public function dropComponentAccess($componentName, $accessList): void
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
     * @param mixed $access
     * @param mixed $func
     * @throws AclException
     * @throws \MongoCursorException
     * @throws \MongoCursorTimeoutException
     * @throws \MongoException
     */
    public function allow($roleName, $componentName, $access, $func = null): void
    {
        $this->allowOrDeny($roleName, $componentName, $access, AclEnum::ALLOW);
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
     * @param mixed $access
     * @param mixed $func
     * @return void
     * @throws AclException
     * @throws \MongoCursorException
     * @throws \MongoCursorTimeoutException
     * @throws \MongoException
     */
    public function deny($roleName, $componentName, $access, $func = null): void
    {
        $this->allowOrDeny($roleName, $componentName, $access, Acl::DENY);
    }

    /**
     * Example:
     * <code>
     * //Does Andres have access to the customers component to create?
     * $acl->isAllowed('Andres', 'Products', 'create');
     * //Do guests have access to any component to edit?
     * $acl->isAllowed('guests', '*', 'edit');
     * </code>
     *
     * @param  string  $role
     * @param  string  $component
     * @param  string  $access
     * @param array    $parameters
     * @return boolean
     */
    public function isAllowed($role, $component, $access, array $parameters = null): bool
    {
        $accessList = $this->getCollection('accessList');

        $access = $accessList->findOne(
            [
                'roles_name'     => $role,
                'components_name' => $component,
                'access_name'    => $access,
            ]
        );

        if (is_array($access)) {
            return (bool) $access['allowed'];
        }

        /**
         * Check if there is an common rule for that component
         */
        $access = $accessList->findOne(
            [
                'roles_name'     => $role,
                'components_name' => $component,
                'access_name'    => '*',
            ]
        );

        if (is_array($access)) {
            return (bool) $access['allowed'];
        }

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
    public function setNoArgumentsDefaultAction($defaultAccess): void
    {
        $this->noArgumentsDefaultAction = intval($defaultAccess);
    }

    /**
     * Returns a mongo collection
     *
     * @param  string           $name
     * @return \MongoCollection
     */
    protected function getCollection($name)
    {
        return $this->options['db']->selectCollection($this->options[$name]);
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param string $roleName
     * @param string $componentName
     * @param string $accessName
     * @param integer $action
     * @return boolean
     * @throws AclException
     * @throws \MongoCursorException
     * @throws \MongoCursorTimeoutException
     * @throws \MongoException
     */
    protected function insertOrUpdateAccess($roleName, $componentName, $accessName, $action)
    {
        /**
         * Check if the access is valid in the component
         */
        $exists = $this->getCollection('componentsAccesses')->count(
            [
                'components_name' => $componentName,
                'access_name'    => $accessName,
            ]
        );

        if (!$exists) {
            throw new AclException(
                "Access '" . $accessName . "' does not exist in component '" . $componentName . "' in ACL"
            );
        }

        $accessList = $this->getCollection('accessList');

        $access = $accessList->findOne(
            [
                'roles_name'     => $roleName,
                'components_name' => $componentName,
                'access_name'    => $accessName,
            ]
        );

        if (!$access) {
            $accessList->insert(
                [
                    'roles_name'     => $roleName,
                    'components_name' => $componentName,
                    'access_name'    => $accessName,
                    'allowed'        => $action,
                ]
            );
        } else {
            $access['allowed'] = $action;

            $accessList->save($access);
        }

        /**
         * Update the access '*' in access_list
         */
        $exists = $accessList->count(
            [
                'roles_name'     => $roleName,
                'components_name' => $componentName,
                'access_name'    => '*',
            ]
        );

        if (!$exists) {
            $accessList->insert(
                [
                    'roles_name'     => $roleName,
                    'components_name' => $componentName,
                    'access_name'    => '*',
                    'allowed'        => $this->defaultAccess,
                ]
            );
        }

        return true;
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param string $roleName
     * @param string $componentName
     * @param string $access
     * @param integer $action
     * @throws AclException
     * @throws \MongoCursorException
     * @throws \MongoCursorTimeoutException
     * @throws \MongoException
     */
    protected function allowOrDeny($roleName, $componentName, $access, $action)
    {
        if (!$this->isRole($roleName)) {
            throw new AclException('Role "' . $roleName . '" does not exist in the list');
        }

        if (is_string($access)) {
            $access = [$access];
        }

        foreach ($access as $accessName) {
            $this->insertOrUpdateAccess($roleName, $componentName, $accessName, $action);
        }
    }
}

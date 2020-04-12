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
 * Manages ACL lists in Redis Database
 */
class Redis extends AbstractAdapter
{
    /**
     * @var bool
     */
    protected $setNXAccess = true;

    /**
     * @var \Redis
     */
    protected $redis;

    /**
     * Default action for no arguments is allow
     * @var int
     */
    protected $noArgumentsDefaultAction = AclEnum::ALLOW;

    /**
     * Redis constructor.
     *
     * @param \Redis|null $redis
     */
    public function __construct(\Redis $redis = null)
    {
        $this->redis = $redis;
    }

    public function setRedis($redis, $chainRedis = false)
    {
        $this->redis = $redis;
        return $chainRedis ? $redis : $this;
    }

    public function getRedis()
    {
        return $this->redis;
    }

    /**
     * Example:
     * <code>$acl->addRole(new Phalcon\Acl\Role('administrator'), 'consultor');</code>
     * <code>$acl->addRole('administrator', 'consultor');</code>
     *
     * @param Role|string $role
     * @param  string $accessInherits
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

        $this->redis->hMset('roles', [$role->getName() => $role->getDescription()]);
        $this->redis->sAdd("accessList:$role:*:{$this->getDefaultAction()}}", '*');

        if ($accessInherits) {
            $this->addInherit($role->getName(), $accessInherits);
        }

        return true;
    }

    /**
     * Example:
     *
     * //Administrator implicitly inherits all descendants of 'consultor' unless explicity set in an Array
     * <code>$acl->addInherit('administrator', new Phalcon\Acl\Role('consultor'));</code>
     * <code>$acl->addInherit('administrator', 'consultor');</code>
     * <code>$acl->addInherit('administrator', ['consultor', 'poweruser']);</code>
     *
     * @param string $roleName
     * @param mixed $roleToInherit
     * @return bool
     * @throws AclException
     */
    public function addInherit(string $roleName, $roleToInherit): bool
    {
        $exists = $this->redis->hGet('roles', $roleName);
        if (!$exists) {
            throw new AclException(sprintf("Role '%s' does not exist in the role list", $roleName));
        }

        if ($roleToInherit instanceof Role) {
            $roleToInherit = $roleToInherit->getName();
        }

        /**
         * Deep inherits Explicit tests array, Implicit recurs through inheritance chain
         */
        if (is_array($roleToInherit)) {
            foreach ($roleToInherit as $role) {
                $this->redis->sAdd("rolesInherits:$roleName", $role);
            }

            return true;
        }

        if ($this->redis->exists("rolesInherits:$roleToInherit")) {
            $deeperInherits = $this->redis->sGetMembers("rolesInherits:$roleToInherit");

            foreach ($deeperInherits as $deeperInherit) {
                $this->addInherit($roleName, $deeperInherit);
            }
        }

        return (bool)$this->redis->sAdd("rolesInherits:$roleName", $roleToInherit);
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
     * @param  Component|string $component
     * @param  array|string $accessList
     * @return bool
     * @throws AclException
     */
    public function addComponent($component, $accessList): bool
    {
        if (is_string($component)) {
            $component = new Component($component, ucwords($component) . ' Component');
        }

        $this->redis->hMset('components', [$component->getName() => $component->getDescription()]);

        if ($accessList) {
            return $this->addComponentAccess($component->getName(), $accessList);
        }

        return true;
    }

    /**
     * @param  string $componentName
     * @param  array|string $accessList
     * @return boolean
     * @throws AclException
     */
    public function addComponentAccess(string $componentName, $accessList): bool
    {
        if (!$this->isComponent($componentName)) {
            throw new AclException("Component '" . $componentName . "' does not exist in ACL");
        }

        $accessList = is_string($accessList) ? explode(' ', $accessList) : $accessList;
        foreach ($accessList as $accessName) {
            $this->redis->sAdd("componentsAccesses:$componentName", $accessName);
        }

        return true;
    }

    /**
     * @param  string $roleName
     * @return bool
     */
    public function isRole(string $roleName): bool
    {
        return $this->redis->hExists('roles', $roleName);
    }

    /**
     * @param  string $componentName
     * @return bool
     */
    public function isComponent(string $componentName): bool
    {
        return $this->redis->hExists('components', $componentName);
    }

    /**
     * @param string $component
     * @param string $access
     * @return bool
     */
    public function isComponentAccess(string $component, string $access)
    {
        return $this->redis->sIsMember("componentsAccesses:$component", $access);
    }

    /**
     * @return Component[]
     */
    public function getComponents(): array
    {
        $data = [];
        foreach ($this->redis->hGetAll('components') as $name => $desc) {
            $data[] = new Component($name, $desc);
        }

        return $data;
    }

    /**
     * @return RoleInterface[]
     */
    public function getRoles(): array
    {
        $roles = [];
        foreach ($this->redis->hGetAll('roles') as $name => $desc) {
            $roles[] = new Role($name, $desc);
        }

        return $roles;
    }

    public function getComponentAccess($component)
    {
        return $this->redis->sMembers("componentsAccesses:$component");
    }

    /**
     * @param string $component
     * @param array|string $accessList
     */
    public function dropComponentAccess(string $component, $accessList): void
    {
        if (!is_array($accessList)) {
            $accessList = [$accessList];
        }

        array_unshift($accessList, "componentsAccesses:$component");

        call_user_func_array(
            [
                $this->redis,
                'sRem',
            ],
            $accessList
        );
    }

    /**
     * You can use '*' as wildcard
     *
     * Example:
     *
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
     * @param string $role
     * @param string $component
     * @param mixed $access
     * @param mixed $func
     * @throws AclException
     */
    public function allow(string $role, string $component, $access, $func = null): void
    {
        if ($role !== '*' && $component !== '*') {
            $this->allowOrDeny($role, $component, $access, AclEnum::ALLOW);
        }

        if ($role === '*' || empty($role)) {
            $this->rolePermission($component, $access, AclEnum::ALLOW);
        }

        if ($component === '*' || empty($component)) {
            $this->componentPermission($role, $access, AclEnum::ALLOW);
        }
    }

    /**
     * You can use '*' as wildcard
     *
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
     * @param string $role
     * @param string $component
     * @param mixed $access
     * @param mixed $func
     * @throws AclException
     */
    public function deny(string $role, string $component, $access, $func = null): void
    {
        if ($role === '*' || empty($role)) {
            $this->rolePermission($component, $access, AclEnum::DENY);
        } elseif ($component === '*' || empty($component)) {
            $this->componentPermission($role, $access, AclEnum::DENY);
        } else {
            $this->allowOrDeny($role, $component, $access, AclEnum::DENY);
        }
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
    public function isAllowed($role, $component, $access, array $parameters = null): bool
    {
        if ($this->redis->sIsMember("accessList:$role:$component:" . AclEnum::ALLOW, $access)) {
            return true;
        }

        if ($this->redis->exists("rolesInherits:$role")) {
            $rolesInherits = $this->redis->sMembers("rolesInherits:$role");

            foreach ($rolesInherits as $role) {
                if ($this->redis->sIsMember("accessList:$role:$component:" . AclEnum::ALLOW, $access)) {
                    return true;
                }
            }
        }

        /**
         * Return the default access action
         */
        return $this->getDefaultAction() === 1;
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
    public function setNoArgumentsDefaultAction($defaultAccess): void
    {
        $this->noArgumentsDefaultAction = intval($defaultAccess);
    }

    /**
     * @param string $roleName
     * @param string $componentName
     * @param mixed  $accessName
     * @param int    $action
     * @return bool
     * @throws AclException
     */
    protected function setAccess(string $roleName, string $componentName, $accessName, int $action)
    {
        /**
         * Check if the access is valid in the component
         */
        if ($this->isComponentAccess($componentName, $accessName)) {
            if (!$this->setNXAccess) {
                throw new AclException(
                    "Access '" . $accessName . "' does not exist in component '" . $componentName . "' in ACL"
                );
            }

            $this->addComponentAccess($componentName, $accessName);
        }

        $this->redis->sAdd("accessList:$roleName:$componentName:$action", $accessName);

        $accessList = "accessList:$roleName:$componentName";

        // remove first if exists
        foreach ([1, 2] as $act) {
            $this->redis->sRem("$accessList:$act", $accessName);
            $this->redis->sRem("$accessList:$act", "*");
        }

        $this->redis->sAdd("$accessList:$action", $accessName);
        $this->redis->sAdd("$accessList:{$this->getDefaultAction()}", "*");

        return true;
    }

    /**
     * Inserts/Updates a permission in the access list
     *
     * @param  string $roleName
     * @param  string $componentName
     * @param  mixed $access
     * @param  int $action
     * @throws AclException
     */
    protected function allowOrDeny(string $roleName, string $componentName, $access, int $action): void
    {
        if (!$this->isRole($roleName)) {
            throw new AclException('Role "' . $roleName . '" does not exist in the list');
        }

        if (!$this->isComponent($componentName)) {
            throw new AclException('Component "' . $componentName . '" does not exist in the list');
        }

        $access = ($access === '*' || empty($access)) ? $this->getComponentAccess($componentName) : $access;

        if (is_array($access)) {
            foreach ($access as $accessName) {
                $this->setAccess($roleName, $componentName, $accessName, $action);
            }
        } else {
            $this->setAccess($roleName, $componentName, $access, $action);
        }
    }

    /**
     * @param string $role
     * @param mixed $access
     * @param int $allowOrDeny
     * @throws AclException
     */
    protected function componentPermission(string $role, $access, int $allowOrDeny): void
    {
        foreach ($this->getComponents() as $component) {
            if ($role === '*' || empty($role)) {
                $this->rolePermission($component->getName(), $access, $allowOrDeny);
            } else {
                $this->allowOrDeny($role, $component->getName(), $access, $allowOrDeny);
            }
        }
    }

    /**
     * @param string $component
     * @param mixed $access
     * @param int $allowOrDeny
     * @throws AclException
     */
    protected function rolePermission(string $component, $access, int $allowOrDeny): void
    {
        foreach ($this->getRoles() as $role) {
            if ($component === '*' || empty($component)) {
                $this->componentPermission($role->getName(), $access, $allowOrDeny);
            } else {
                $this->allowOrDeny($role->getName(), $component, $access, $allowOrDeny);
            }
        }
    }
}

<?php

declare(strict_types=1);

namespace PrototypeIn\Rbac\Contracts;

use PrototypeIn\Acl\Contracts\AccessControlInterface;

interface RbacInterface extends AccessControlInterface
{
    public function hasRolePermission(string $role, string $permission): bool;

    public function getInheritedPermissions(string $role): array;

    public function getRoleHierarchy(string $role): array;
}
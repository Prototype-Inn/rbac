<?php

declare(strict_types=1);

namespace PrototypeIn\Rbac\Providers;

use PrototypeIn\Acl\Contracts\RoleProviderInterface;
use PrototypeIn\Acl\Exceptions\InvalidRoleException;
use Psr\Log\LoggerInterface;

class DatabaseRoleProvider implements RoleProviderInterface
{
    private array $rolesData = [];

    private array $resources = [];

    private ?LoggerInterface $logger;

    public function __construct(
        array $rolesData,
        ?LoggerInterface $logger = null,
        array $resources = []
    ) {
        $this->rolesData = $rolesData;
        $this->logger = $logger;
        $this->resources = $resources;
    }

    public function getRoles(): array
    {
        $this->logger?->debug('Fetching all roles', [
            'count' => count($this->rolesData),
        ]);

        return array_keys($this->rolesData);
    }

    public function getRolePermissions(string $role): array
    {
        if (!$this->hasRole($role)) {
            $this->logger?->warning('Role not found', ['role' => $role]);
            throw new InvalidRoleException($role);
        }

        $permissions = $this->rolesData[$role]['permissions'] ?? [];

        $this->logger?->debug('Fetching role permissions', [
            'role' => $role,
            'count' => count($permissions),
        ]);

        return $permissions;
    }

    public function hasRole(string $role): bool
    {
        return isset($this->rolesData[$role]);
    }

    public function hasPermission(string $role, string $permission): bool
    {
        if (!$this->hasRole($role)) {
            $this->logger?->warning('Role not found', ['role' => $role]);
            return false;
        }

        $permissions = $this->rolesData[$role]['permissions'] ?? [];

        if (in_array('*', $permissions, true)) {
            return true;
        }

        if (in_array($permission, $permissions, true)) {
            return true;
        }

        [$resource] = explode('.', $permission, 2);

        $resourcePermission = $resource . '.*';

        if (in_array($resourcePermission, $permissions, true)) {
            return true;
        }

        $this->logger?->debug('Permission check failed', [
            'role' => $role,
            'permission' => $permission,
        ]);

        return false;
    }

    public function getResources(): array
    {
        return $this->resources;
    }

    public function setRolesData(array $rolesData): void
    {
        $this->rolesData = $rolesData;
    }

    public function addRole(string $role, array $permissions): void
    {
        $this->rolesData[$role] = ['permissions' => $permissions];
    }

    public function removeRole(string $role): void
    {
        unset($this->rolesData[$role]);
    }
}
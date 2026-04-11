<?php

declare(strict_types=1);

namespace PrototypeIn\Rbac\Services;

use PrototypeIn\Acl\Contracts\RoleProviderInterface;
use PrototypeIn\Acl\Exceptions\AccessDeniedException;
use PrototypeIn\Rbac\Contracts\RbacInterface;
use Psr\Log\LoggerInterface;

class RbacService implements RbacInterface
{
    private RoleProviderInterface $roleProvider;

    private ?LoggerInterface $logger;

    private array $roleHierarchy = [];

    public function __construct(
        RoleProviderInterface $roleProvider,
        ?LoggerInterface $logger = null,
        array $roleHierarchy = []
    ) {
        $this->roleProvider = $roleProvider;
        $this->logger = $logger;
        $this->validateHierarchy($roleHierarchy);
        $this->roleHierarchy = $roleHierarchy;
        $this->logInit();
    }

    private function validateHierarchy(array $hierarchy): void
    {
        foreach ($hierarchy as $role => $parents) {
            $this->detectCycle($role, $hierarchy, [$role]);
        }
    }

    private function detectCycle(string $role, array $hierarchy, array $path): void
    {
        if (!isset($hierarchy[$role])) {
            return;
        }

        foreach ($hierarchy[$role] as $parentRole) {
            if (in_array($parentRole, $path, true)) {
                throw new \RuntimeException(sprintf('Circular role hierarchy detected: %s', $parentRole));
            }
            $this->detectCycle($parentRole, $hierarchy, [...$path, $parentRole]);
        }
    }

    private function logInit(): void
    {
        $this->logger?->info('RBAC service initialized', [
            'hierarchy' => $this->roleHierarchy,
        ]);
    }

    public function hasRolePermission(string $role, string $permission): bool
    {
        if ($this->roleProvider->hasPermission($role, $permission)) {
            return true;
        }

        $inheritedRoles = $this->getInheritedRoles($role);
        foreach ($inheritedRoles as $inheritedRole) {
            if ($this->roleProvider->hasPermission($inheritedRole, $permission)) {
                $this->logger?->debug('Permission granted via inheritance', [
                    'role' => $role,
                    'inherited_role' => $inheritedRole,
                    'permission' => $permission,
                ]);
                return true;
            }
        }

        $this->logger?->debug('Permission denied', [
            'role' => $role,
            'permission' => $permission,
        ]);

        return false;
    }

    public function getInheritedPermissions(string $role): array
    {
        if (!$this->roleProvider->hasRole($role)) {
            return [];
        }

        $permissions = $this->roleProvider->getRolePermissions($role);

        $inheritedRoles = $this->getInheritedRoles($role);
        foreach ($inheritedRoles as $inheritedRole) {
            if ($this->roleProvider->hasRole($inheritedRole)) {
                $inheritedPerms = $this->roleProvider->getRolePermissions($inheritedRole);
                $permissions = array_merge($permissions, $inheritedPerms);
            }
        }

        return array_unique($permissions);
    }

    public function getRoleHierarchy(string $role): array
    {
        return $this->getInheritedRoles($role);
    }

    public function hasPermission(string $role, string $permission): bool
    {
        return $this->hasRolePermission($role, $permission);
    }

    public function assertPermission(string $role, string $permission): void
    {
        if (!$this->hasRolePermission($role, $permission)) {
            $this->logger?->warning('Access denied', [
                'role' => $role,
                'permission' => $permission,
            ]);

            throw new AccessDeniedException(
                sprintf('Permission denied: %s', $permission),
                '',
                $permission
            );
        }

        $this->logger?->debug('Permission granted', [
            'role' => $role,
            'permission' => $permission,
        ]);
    }

    private function getInheritedRoles(string $role): array
    {
        $inherited = [];
        $this->collectInheritedRoles($role, $inherited);
        return $inherited;
    }

    private function collectInheritedRoles(string $role, array &$inherited): void
    {
        if (!isset($this->roleHierarchy[$role])) {
            return;
        }

        foreach ($this->roleHierarchy[$role] as $parentRole) {
            if (!in_array($parentRole, $inherited, true)) {
                $inherited[] = $parentRole;
                $this->collectInheritedRoles($parentRole, $inherited);
            }
        }
    }

    public function isGranted(string $role, string $resource, string $action): bool
    {
        $permission = $resource . '.' . $action;
        return $this->hasRolePermission($role, $permission);
    }

    public function getRolePermissions(string $role): array
    {
        return $this->getInheritedPermissions($role);
    }

    public function getResources(): array
    {
        return $this->roleProvider->getResources();
    }

    public function getRoles(): array
    {
        return $this->roleProvider->getRoles();
    }

    public function assertAccess(string $role, string $resource, string $action): void
    {
        $permission = $resource . '.' . $action;
        $this->assertPermission($role, $permission);
    }

    public function assertRole(string $role): void
    {
        if (!$this->roleProvider->hasRole($role)) {
            $this->logger?->error('Invalid role', [
                'role' => $role,
            ]);
            throw new \PrototypeIn\Acl\Exceptions\InvalidRoleException($role);
        }
    }
}
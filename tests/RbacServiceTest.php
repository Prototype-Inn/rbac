<?php

declare(strict_types=1);

namespace PrototypeIn\Rbac\Tests;

use Mockery;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PrototypeIn\Rbac\Providers\DatabaseRoleProvider;
use PrototypeIn\Rbac\Services\RbacService;
use Psr\Log\LoggerInterface;

#[RequiresPhpExtension('mbstring')]
class RbacServiceTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function testHasPermission(): void
    {
        $provider = new DatabaseRoleProvider([
            'admin' => ['permissions' => ['*']],
            'editor' => ['permissions' => ['post.view', 'post.edit']],
        ]);

        $rbac = new RbacService($provider);

        self::assertTrue($rbac->hasPermission('admin', 'anything'));
        self::assertTrue($rbac->hasPermission('editor', 'post.view'));
        self::assertFalse($rbac->hasPermission('editor', 'post.delete'));
    }

    public function testHasPermissionWithHierarchy(): void
    {
        $provider = new DatabaseRoleProvider([
            'admin' => ['permissions' => ['*']],
            'editor' => ['permissions' => ['post.edit']],
            'viewer' => ['permissions' => ['post.view']],
        ]);

        $hierarchy = [
            'editor' => ['viewer'],
            'admin' => ['editor'],
        ];

        $rbac = new RbacService($provider, null, $hierarchy);

        self::assertTrue($rbac->hasPermission('editor', 'post.view'));
        self::assertTrue($rbac->hasPermission('admin', 'post.view'));
        self::assertTrue($rbac->hasPermission('admin', 'post.edit'));
    }

    public function testGetInheritedPermissions(): void
    {
        $provider = new DatabaseRoleProvider([
            'admin' => ['permissions' => ['user.manage']],
            'editor' => ['permissions' => ['post.edit', 'post.delete']],
            'viewer' => ['permissions' => ['post.view']],
        ]);

        $hierarchy = [
            'editor' => ['viewer'],
        ];

        $rbac = new RbacService($provider, null, $hierarchy);

        $permissions = $rbac->getInheritedPermissions('editor');

        self::assertTrue(in_array('post.edit', $permissions, true));
        self::assertTrue(in_array('post.delete', $permissions, true));
        self::assertTrue(in_array('post.view', $permissions, true));
    }

    public function testIsGranted(): void
    {
        $provider = new DatabaseRoleProvider([
            'editor' => ['permissions' => ['post.edit']],
        ]);

        $rbac = new RbacService($provider);

        self::assertTrue($rbac->isGranted('editor', 'post', 'edit'));
        self::assertFalse($rbac->isGranted('editor', 'post', 'delete'));
    }

    public function testAssertPermission(): void
    {
        $provider = new DatabaseRoleProvider([
            'admin' => ['permissions' => ['user.create']],
        ]);

        $rbac = new RbacService($provider);

        $rbac->assertPermission('admin', 'user.create');

        $this->expectException(\PrototypeIn\Acl\Exceptions\AccessDeniedException::class);
        $rbac->assertPermission('admin', 'user.delete');
    }

    public function testAssertAccess(): void
    {
        $provider = new DatabaseRoleProvider([
            'editor' => ['permissions' => ['post.create']],
        ]);

        $rbac = new RbacService($provider);

        $rbac->assertAccess('editor', 'post', 'create');

        $this->expectException(\PrototypeIn\Acl\Exceptions\AccessDeniedException::class);
        $rbac->assertAccess('editor', 'post', 'delete');
    }

    public function testGetRoles(): void
    {
        $provider = new DatabaseRoleProvider([
            'admin' => ['permissions' => ['*']],
            'editor' => ['permissions' => ['post.edit']],
        ]);

        $rbac = new RbacService($provider);

        $roles = $rbac->getRoles();

        self::assertTrue(in_array('admin', $roles, true));
        self::assertTrue(in_array('editor', $roles, true));
    }

    public function testGetResources(): void
    {
        $provider = new DatabaseRoleProvider([], null, [
            'post' => ['view', 'create', 'edit', 'delete'],
            'user' => ['view', 'create', 'edit'],
        ]);

        $rbac = new RbacService($provider);

        $resources = $rbac->getResources();

        self::assertArrayHasKey('post', $resources);
        self::assertArrayHasKey('user', $resources);
    }

    public function testGetRoleHierarchy(): void
    {
        $provider = new DatabaseRoleProvider([
            'admin' => ['permissions' => ['*']],
            'editor' => ['permissions' => ['post.edit']],
            'viewer' => ['permissions' => ['post.view']],
        ]);

        $hierarchy = [
            'editor' => ['viewer'],
            'admin' => ['editor', 'viewer'],
        ];

        $rbac = new RbacService($provider, null, $hierarchy);

        $editorHierarchy = $rbac->getRoleHierarchy('editor');
        self::assertTrue(in_array('viewer', $editorHierarchy, true));

        $adminHierarchy = $rbac->getRoleHierarchy('admin');
        self::assertTrue(in_array('editor', $adminHierarchy, true));
        self::assertTrue(in_array('viewer', $adminHierarchy, true));
    }

    public function testAssertRole(): void
    {
        $provider = new DatabaseRoleProvider([
            'admin' => ['permissions' => ['*']],
        ]);

        $rbac = new RbacService($provider);

        $rbac->assertRole('admin');

        $this->expectException(\PrototypeIn\Acl\Exceptions\InvalidRoleException::class);
        $rbac->assertRole('nonexistent');
    }

    public function testLoggerIsCalled(): void
    {
        $logger = Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('info')->once()->with('RBAC service initialized', Mockery::any());
        $logger->shouldReceive('debug')->zeroOrMoreTimes()->withAnyArgs();

        $provider = new DatabaseRoleProvider([
            'editor' => ['permissions' => ['post.view']],
        ]);

        $rbac = new RbacService($provider, $logger);

        self::assertTrue($rbac->hasPermission('editor', 'post.view'));
    }

    public function testCircularHierarchyThrowsException(): void
    {
        $provider = new DatabaseRoleProvider([
            'admin' => ['permissions' => ['*']],
            'editor' => ['permissions' => ['post.edit']],
        ]);

        $hierarchy = [
            'admin' => ['editor'],
            'editor' => ['admin'],
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Circular role hierarchy detected');

        new RbacService($provider, null, $hierarchy);
    }
}
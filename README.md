# prototype-in/rbac

RBAC (Role-Based Access Control) sistema paremta ACL pagrindu, su paveldėjimo hierarchija.

## Priklausomybės

- PHP 8.4+
- `prototype-in/acl` (dev-develop) - tėvinis paketas
- `monolog/monolog` 3.x-dev (PSR-3 Logger)

## Diegimas

```bash
composer require prototype-in/rbac:dev-develop
```

## Pagrindinis naudojimas

```php
use PrototypeIn\Rbac\Providers\DatabaseRoleProvider;
use PrototypeIn\Rbac\Services\RbacService;

$provider = new DatabaseRoleProvider([
    'admin'  => ['permissions' => ['*']],
    'editor' => ['permissions' => ['post.view', 'post.create', 'post.edit']],
    'viewer' => ['permissions' => ['post.view']],
]);

$rbac = new RbacService($provider);

$rbac->hasPermission('editor', 'post.view'); // true
$rbac->hasPermission('viewer', 'post.edit'); // false
```

## Role hierarchija

Role gali paveldėti teises iš kitų rolių:

```php
$provider = new DatabaseRoleProvider([
    'admin'  => ['permissions' => ['user.manage']],
    'editor' => ['permissions' => ['post.edit']],
    'viewer' => ['permissions' => ['post.view']],
]);

$hierarchy = [
    'editor' => ['viewer'],  // editor pavindi viewer teises
    'admin'  => ['editor'],  // admin pavindi editor teises
];

$rbac = new RbacService($provider, null, $hierarchy);

$rbac->hasPermission('editor', 'post.view'); // true (paveldi is viewer)
$rbac->hasPermission('admin',  'post.view'); // true (paveldi is editor -> viewer)
```

## Monolog integravimas

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('rbac');
$logger->pushHandler(new StreamHandler('app.log', Logger::DEBUG));

$rbac = new RbacService($provider, $logger);
$rbac->hasPermission('editor', 'post.view');
// Log: RBAC service initialized, Permission check, Permission granted/denied
```

## Teisių tikrinimas

```php
$rbac->assertPermission('editor', 'post.create');
// meta AccessDeniedException jei neturi teises

$rbac->assertAccess('editor', 'post', 'create');
// lygiai tas pats kas post.create
```

## Ištekliai ir veiksmai

```php
$rbac->isGranted('editor', 'post', 'edit');   // true
$rbac->isGranted('editor', 'post', 'delete'); // priklauso nuo teisiu
$rbac->assertAccess('editor', 'post', 'delete');
```

## Išplėstinės sąsajos

### RbacInterface

Paveldi visas ACL sąsajos metodus:

```php
interface RbacInterface extends AccessControlInterface
{
    // Papildomi RBAC metodai
    public function hasRolePermission(string $role, string $permission): bool;
    public function getInheritedPermissions(string $role): array;
    public function getRoleHierarchy(string $role): array;
}
```

## Exception'ai

- `\PrototypeIn\Acl\Exceptions\AccessDeniedException` - kai neleidžiama
- `\PrototypeIn\Acl\Exceptions\InvalidRoleException` - kai rolė neegzistuoja

## Saugumas

- **Ciklų aptikimas**: hierarchija tikrinama konstruktoriuje, ciklinės hierarchijos meta `RuntimeException`
- **Wildcard `*`**: rolė su `*` turi visas galimas teises

## Testai

```bash
composer test
```

## Struktūra

```
src/
├── Contracts/
│   └── RbacInterface.php      # RBAC sąsaja
├── Services/
│   └── RbacService.php        # Pagrindinis servisas
└── Providers/
    └── DatabaseRoleProvider.php # Role provideris
```

## Pavyzdys su pilna konfiguracija

```php
use PrototypeIn\Rbac\Providers\DatabaseRoleProvider;
use PrototypeIn\Rbac\Services\RbacService;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('rbac');
$logger->pushHandler(new StreamHandler('rbac.log'));

$provider = new DatabaseRoleProvider([
    'superadmin' => ['permissions' => ['*']],
    'admin'      => ['permissions' => ['user.*', 'post.*', 'comment.*']],
    'editor'     => ['permissions' => ['post.create', 'post.edit', 'post.view', 'comment.create', 'comment.edit']],
    'viewer'     => ['permissions' => ['post.view', 'comment.view']],
], null, [
    'post'    => ['view', 'create', 'edit', 'delete'],
    'user'    => ['view', 'create', 'edit', 'delete'],
    'comment' => ['view', 'create', 'edit', 'delete'],
]);

$hierarchy = [
    'admin' => ['editor'],
    'editor'=> ['viewer'],
];

$rbac = new RbacService($provider, $logger, $hierarchy);

// Patikrinimas
if ($rbac->hasPermission('admin', 'user.delete')) {
    // naikinti vartotoja
}

$rbac->assertAccess('editor', 'post', 'create');
// meta exception jei negali
```

## Versija

1.0.0-dev
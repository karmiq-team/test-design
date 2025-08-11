# Laravel 12 Developer Guidelines & Standards

## Project Technical Stack

### Core Technologies
- **PHP**: 8.3 - 8.4 (Latest stable)
- **Package Manager**: Composer
- **Framework**: Laravel 12
- **Database**: MySQL 8+ / PostgreSQL 15+
- **Version Control**: Git & GitHub
- **Cache/Session/Queue**: Redis 7+

### Development Environment
```bash
# Required PHP extensions
php -m | grep -E "(redis|pdo_mysql|gd|zip|curl|mbstring|xml|bcmath)"
```

---

## Laravel Packages

### Development Packages
```json
{
  "require-dev": {
    "laravel/telescope": "^5.0",
    "barryvdh/laravel-debugbar": "^3.9",
    "opcodesio/log-viewer": "^3.0",
    "pestphp/pest": "^2.0",
    "pestphp/pest-plugin-laravel": "^2.0",
    "nunomaduro/larastan": "^2.0",
    "laravel/pint": "^1.0"
  }
}
```

### Production Packages
```json
{
  "require": {
    "laravel/sanctum": "^4.0",
    "laravel/horizon": "^5.0",
    "laravel/pulse": "^1.0",
    "laravel/reverb": "^1.0",
    "maatwebsite/excel": "^3.1",
    "league/flysystem-aws-s3-v3": "^3.0",
    "spatie/laravel-backup": "^8.0",
    "spatie/laravel-permission": "^6.0",
    "spatie/laravel-query-builder": "^5.0",
    "spatie/browsershot": "^4.0",
    "intervention/image": "^3.0",
    "guzzlehttp/guzzle": "^7.0",
    "laravel-notification-channels/telegram": "^4.0",
    "fruitcake/laravel-cors": "^3.0"
  }
}
```

---

## PHP 8.3/8.4 Type Hints & Best Practices

### 1. Strict Types Declaration
Always declare strict types at the top of PHP files:

```php
<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Collection;
```

### 2. Property Type Declarations
```php
<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Carbon\Carbon;

class User extends Model
{
    // Typed properties
    protected string $table = 'users';
    protected array $fillable = ['name', 'email', 'password'];
    protected array $hidden = ['password', 'remember_token'];
    
    // Typed constants
    public const string STATUS_ACTIVE = 'active';
    public const string STATUS_INACTIVE = 'inactive';
    public const int DEFAULT_ROLE_ID = 1;
    
    // Accessor with return type
    protected function fullName(): Attribute
    {
        return Attribute::make(
            get: fn (mixed $value, array $attributes): string => 
                $attributes['first_name'] . ' ' . $attributes['last_name']
        );
    }
    
    // Relationship with return type
    public function orders(): HasMany
    {
        return $this->hasMany(Order::class);
    }
    
    // Scopes with type hints
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_ACTIVE);
    }
}
```

### 3. Controller Type Hints
```php
<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreUserRequest;
use App\Http\Requests\UpdateUserRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use App\Services\UserService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

class UserController extends Controller
{
    public function __construct(
        private readonly UserService $userService
    ) {}
    
    public function index(): AnonymousResourceCollection
    {
        $users = User::with('roles')->paginate(15);
        
        return UserResource::collection($users);
    }
    
    public function store(StoreUserRequest $request): JsonResponse
    {
        $user = $this->userService->createUser($request->validated());
        
        return response()->json([
            'data' => new UserResource($user),
            'message' => 'User created successfully'
        ], 201);
    }
    
    public function show(User $user): UserResource
    {
        return new UserResource($user->load('roles'));
    }
    
    public function update(UpdateUserRequest $request, User $user): JsonResponse
    {
        $updatedUser = $this->userService->updateUser(
            $user, 
            $request->validated()
        );
        
        return response()->json([
            'data' => new UserResource($updatedUser),
            'message' => 'User updated successfully'
        ]);
    }
    
    public function destroy(User $user): JsonResponse
    {
        $this->userService->deleteUser($user);
        
        return response()->json([
            'message' => 'User deleted successfully'
        ]);
    }
}
```

### 4. Service Classes with Type Hints
```php
<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\User;
use App\Events\UserCreated;
use App\Events\UserDeleted;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;

class UserService
{
    public function createUser(array $data): User
    {
        return DB::transaction(function () use ($data): User {
            $user = User::create([
                'name' => $data['name'],
                'email' => $data['email'],
                'password' => Hash::make($data['password']),
            ]);
            
            event(new UserCreated($user));
            
            return $user;
        });
    }
    
    public function updateUser(User $user, array $data): User
    {
        $user->update($data);
        
        return $user->fresh();
    }
    
    public function deleteUser(User $user): bool
    {
        $result = $user->delete();
        
        if ($result) {
            event(new UserDeleted($user));
        }
        
        return $result;
    }
    
    public function getUsersByRole(string $role): Collection
    {
        return User::whereHas('roles', function (Builder $query) use ($role): void {
            $query->where('name', $role);
        })->get();
    }
}
```

### 5. Form Requests with Validation
```php
<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('create', User::class);
    }
    
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'email' => [
                'required', 
                'string', 
                'email', 
                'max:255', 
                Rule::unique('users')
            ],
            'password' => [
                'required', 
                'string', 
                'min:8', 
                'confirmed'
            ],
            'role_ids' => ['array'],
            'role_ids.*' => ['exists:roles,id'],
        ];
    }
    
    public function messages(): array
    {
        return [
            'email.unique' => 'The email address is already registered.',
            'password.confirmed' => 'Password confirmation does not match.',
        ];
    }
    
    protected function prepareForValidation(): void
    {
        $this->merge([
            'email' => strtolower($this->email),
        ]);
    }
}
```

### 6. API Resources with Type Hints
```php
<?php

declare(strict_types=1);

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'avatar' => $this->avatar_url,
            'roles' => RoleResource::collection($this->whenLoaded('roles')),
            'created_at' => $this->created_at?->toISOString(),
            'updated_at' => $this->updated_at?->toISOString(),
        ];
    }
    
    public function with(Request $request): array
    {
        return [
            'meta' => [
                'version' => '1.0',
                'timestamp' => now()->toISOString(),
            ],
        ];
    }
}
```

---

## Observer & Listener Pattern

### 1. Model Observers
```php
<?php

declare(strict_types=1);

namespace App\Observers;

use App\Models\User;
use Illuminate\Support\Facades\Cache;

class UserObserver
{
    public function creating(User $user): void
    {
        $user->uuid = Str::uuid();
    }
    
    public function created(User $user): void
    {
        Cache::tags(['users'])->flush();
        
        // Send welcome email
        $user->notify(new WelcomeNotification());
    }
    
    public function updated(User $user): void
    {
        Cache::tags(['users'])->flush();
        Cache::forget("user.{$user->id}");
    }
    
    public function deleted(User $user): void
    {
        Cache::tags(['users'])->flush();
        Cache::forget("user.{$user->id}");
    }
}
```

### 2. Event Listeners
```php
<?php

declare(strict_types=1);

namespace App\Events;

use App\Models\User;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class UserCreated
{
    use Dispatchable, SerializesModels;
    
    public function __construct(
        public readonly User $user
    ) {}
}
```

```php
<?php

declare(strict_types=1);

namespace App\Listeners;

use App\Events\UserCreated;
use App\Notifications\WelcomeNotification;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;

class SendWelcomeEmail implements ShouldQueue
{
    use InteractsWithQueue;
    
    public function handle(UserCreated $event): void
    {
        $event->user->notify(new WelcomeNotification());
    }
    
    public function failed(UserCreated $event, Throwable $exception): void
    {
        // Handle failed job
        logger()->error('Failed to send welcome email', [
            'user_id' => $event->user->id,
            'error' => $exception->getMessage(),
        ]);
    }
}
```

---

## Testing with Pest

### 1. Feature Tests
```php
<?php

declare(strict_types=1);

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

describe('User API', function (): void {
    beforeEach(function (): void {
        $this->user = User::factory()->create();
        $this->actingAs($this->user, 'sanctum');
    });
    
    it('can create a user', function (): void {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ];
        
        $response = $this->postJson('/api/users', $userData);
        
        $response->assertStatus(201)
                 ->assertJsonStructure([
                     'data' => ['id', 'name', 'email'],
                     'message'
                 ]);
        
        $this->assertDatabaseHas('users', [
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ]);
    });
    
    it('validates required fields when creating user', function (): void {
        $response = $this->postJson('/api/users', []);
        
        $response->assertStatus(422)
                 ->assertJsonValidationErrors(['name', 'email', 'password']);
    });
});
```

### 2. Unit Tests
```php
<?php

declare(strict_types=1);

use App\Services\UserService;
use App\Models\User;

describe('UserService', function (): void {
    beforeEach(function (): void {
        $this->userService = app(UserService::class);
    });
    
    it('creates user with hashed password', function (): void {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
        ];
        
        $user = $this->userService->createUser($userData);
        
        expect($user)
            ->toBeInstanceOf(User::class)
            ->and($user->name)->toBe('John Doe')
            ->and($user->email)->toBe('john@example.com')
            ->and(Hash::check('password123', $user->password))->toBeTrue();
    });
});
```

---

## Git Workflow & Branching Strategy

### Branch Naming Conventions
```bash
# Feature branches
feature/user-authentication
feature/payment-integration
feature/admin-dashboard

# Bug fixes
bugfix/login-validation-error
bugfix/memory-leak-fix

# Hotfixes
hotfix/security-vulnerability
hotfix/production-crash

# Releases
release/1.4.0
release/2.0.0-beta
```

### Commit Message Format
```bash
# Format
<type>(<scope>): <description>

[optional body]

[optional footer(s)]

# Examples
feat(auth): implement JWT authentication

- Add login/logout endpoints
- Integrate Laravel Sanctum
- Add middleware for protected routes

Closes #123

fix(payment): resolve Stripe webhook timeout

The webhook was timing out due to heavy database queries.
Moved processing to background job.

Fixes #456

docs(api): update authentication documentation

chore(deps): update Laravel to v12.0

test(user): add comprehensive user service tests
```

### Git Hooks (Pre-commit)
```bash
#!/bin/sh
# .git/hooks/pre-commit

# Run PHP CS Fixer
./vendor/bin/pint

# Run static analysis
./vendor/bin/phpstan analyse

# Run tests
./vendor/bin/pest

# Check for debugging statements
if grep -r "dd\|dump\|var_dump" app/ --exclude-dir=vendor; then
    echo "❌ Found debugging statements. Please remove them."
    exit 1
fi
```

---

## Performance & Security Best Practices

### 1. Database Query Optimization
```php
// ❌ Bad - N+1 Query Problem
$users = User::all();
foreach ($users as $user) {
    echo $user->profile->bio; // N+1 queries
}

// ✅ Good - Eager Loading
$users = User::with('profile')->get();
foreach ($users as $user) {
    echo $user->profile->bio; // 2 queries total
}

// ✅ Good - Select specific columns
User::select(['id', 'name', 'email'])
    ->with('profile:id,user_id,bio')
    ->where('active', true)
    ->get();

// ✅ Good - Chunking for large datasets
User::chunk(1000, function (Collection $users): void {
    foreach ($users as $user) {
        // Process user
    }
});
```

### 2. Caching Strategies
```php
<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Support\Facades\Cache;

class PostService
{
    public function getPopularPosts(int $limit = 10): Collection
    {
        return Cache::tags(['posts', 'popular'])
            ->remember(
                key: "popular_posts_{$limit}",
                ttl: 3600, // 1 hour
                callback: fn (): Collection => Post::popular()
                    ->with('author')
                    ->limit($limit)
                    ->get()
            );
    }
    
    public function clearPostCache(): void
    {
        Cache::tags(['posts'])->flush();
    }
}
```

### 3. Security Implementation
```php
<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

class ApiRateLimiter
{
    public function handle(Request $request, Closure $next): mixed
    {
        $key = 'api.' . $request->ip();
        
        if (RateLimiter::tooManyAttempts($key, 100)) {
            return response()->json([
                'message' => 'Too many requests'
            ], 429);
        }
        
        RateLimiter::hit($key, 3600); // 1 hour window
        
        return $next($request);
    }
}
```

---

## Server Infrastructure & Deployment

### Docker Configuration
```dockerfile
# Dockerfile
FROM php:8.4-fpm-alpine

RUN apk add --no-cache \
    nginx \
    supervisor \
    redis \
    mysql-client

COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 443

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
```

### Environment Configuration
```env
# .env.production
APP_NAME="Your App"
APP_ENV=production
APP_DEBUG=false
APP_URL=https://yourapp.com

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=your_database
DB_USERNAME=your_username
DB_PASSWORD=your_secure_password

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=your_redis_password
REDIS_PORT=6379

QUEUE_CONNECTION=redis
SESSION_DRIVER=redis
CACHE_DRIVER=redis

MAIL_MAILER=smtp
MAIL_HOST=your-smtp-host
MAIL_PORT=587
MAIL_USERNAME=your-email@domain.com
MAIL_PASSWORD=your-email-password
MAIL_ENCRYPTION=tls

AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=your-s3-bucket
```

---

## SSH Key Management

### Multiple SSH Keys Setup
```bash
# Generate separate keys
ssh-keygen -t ed25519 -C "work@company.com" -f ~/.ssh/id_ed25519_work
ssh-keygen -t ed25519 -C "personal@gmail.com" -f ~/.ssh/id_ed25519_personal

# SSH Config (~/.ssh/config)
# Work GitHub
Host github.com-work
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_work
    IdentitiesOnly yes

# Personal GitHub
Host github.com-personal
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_personal
    IdentitiesOnly yes

# Production servers
Host production-server
    HostName your-server-ip
    User deploy
    IdentityFile ~/.ssh/id_ed25519_production
    Port 22
```

### Usage Examples
```bash
# Clone with work account
git clone git@github.com-work:company/project.git

# Clone with personal account
git clone git@github.com-personal:username/personal-project.git

# Switch existing repo
git remote set-url origin git@github.com-work:company/project.git

# Test connections
ssh -T git@github.com-work
ssh -T git@github.com-personal
```

---

## Additional Tools & Monitoring

### Laravel Pulse Configuration
```php
// config/pulse.php
return [
    'domain' => env('PULSE_DOMAIN'),
    'path' => env('PULSE_PATH', 'pulse'),
    'middleware' => ['web', 'auth:sanctum'],
    
    'recorders' => [
        Recorders\Servers::class => [
            'server_name' => env('PULSE_SERVER_NAME', gethostname()),
            'directories' => [
                base_path(),
                storage_path(),
            ],
        ],
        Recorders\SlowQueries::class => [
            'threshold' => env('PULSE_SLOW_QUERIES_THRESHOLD', 1000),
        ],
        Recorders\SlowRequests::class => [
            'threshold' => env('PULSE_SLOW_REQUESTS_THRESHOLD', 1000),
        ],
    ],
];
```

### Horizon Configuration for Queues
```php
// config/horizon.php
return [
    'environments' => [
        'production' => [
            'supervisor-1' => [
                'connection' => 'redis',
                'queue' => ['default', 'emails', 'notifications'],
                'balance' => 'auto',
                'processes' => 10,
                'tries' => 3,
            ],
        ],
    ],
];
```

This comprehensive guide covers modern Laravel 12 development with PHP 8.3/8.4, emphasizing type safety, clean architecture, and best practices for scalable applications.
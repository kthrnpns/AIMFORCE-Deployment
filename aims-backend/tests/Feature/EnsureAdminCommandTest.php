<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class EnsureAdminCommandTest extends TestCase
{
    use RefreshDatabase;

    public function test_does_nothing_without_admin_variables(): void
    {
        config(['app.bootstrap_admin' => ['name' => null, 'email' => null, 'password' => null]]);

        $this->artisan('aims:ensure-admin')->assertSuccessful();
        $this->assertSame(0, User::count());
    }

    public function test_creates_then_updates_the_admin(): void
    {
        config(['app.bootstrap_admin' => ['name' => 'Kath', 'email' => 'kath@example.com', 'password' => 'first-secret']]);
        $this->artisan('aims:ensure-admin')->assertSuccessful();

        $user = User::where('email', 'kath@example.com')->firstOrFail();
        $this->assertTrue($user->hasRole('admin'));
        $this->assertTrue((bool) $user->is_active);
        $this->assertTrue(Hash::check('first-secret', $user->password));

        // Running again (next deploy) with a new password updates the same account.
        config(['app.bootstrap_admin.password' => 'second-secret']);
        $this->artisan('aims:ensure-admin')->assertSuccessful();

        $this->assertSame(1, User::count());
        $this->assertTrue(Hash::check('second-secret', $user->fresh()->password));
    }

    public function test_rejects_a_short_password(): void
    {
        config(['app.bootstrap_admin' => ['name' => 'Kath', 'email' => 'kath@example.com', 'password' => 'short']]);

        $this->artisan('aims:ensure-admin')->assertFailed();
        $this->assertSame(0, User::count());
    }
}

<?php

use App\Models\User;
use Database\Seeders\RolesAndPermissionsSeeder;
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Hash;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Creates (or updates) the first admin from ADMIN_NAME / ADMIN_EMAIL / ADMIN_PASSWORD so a fresh
// server can be signed into without shell access. Safe to run on every deploy: with no
// ADMIN_PASSWORD it does nothing. Remove ADMIN_PASSWORD after the first sign-in.
Artisan::command('aims:ensure-admin', function () {
    ['name' => $name, 'email' => $email, 'password' => $password] = config('app.bootstrap_admin');

    if (! $email || ! $password) {
        $this->info('ADMIN_EMAIL / ADMIN_PASSWORD not set: skipping admin setup.');

        return 0;
    }
    if (! filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8) {
        $this->error('ADMIN_EMAIL must be a valid email and ADMIN_PASSWORD at least 8 characters.');

        return 1;
    }

    $this->call('db:seed', ['--class' => RolesAndPermissionsSeeder::class, '--force' => true]);

    $user = User::firstOrNew(['email' => $email]);
    $created = ! $user->exists;
    $user->forceFill(['name' => $name ?: 'Administrator', 'password' => Hash::make($password), 'is_active' => true])->save();
    if (! $user->hasRole('admin')) {
        $user->assignRole('admin');
    }

    $this->info(($created ? 'Created' : 'Updated')." admin account {$email}.");

    return 0;
})->purpose('Create or update the first admin from ADMIN_* environment variables');

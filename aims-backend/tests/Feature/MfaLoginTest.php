<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class MfaLoginTest extends TestCase
{
    use RefreshDatabase;

    private function user(): User
    {
        return User::factory()->create(['email' => 'ana@example.com', 'password' => bcrypt('secret-pass')]);
    }

    public function test_in_production_the_code_is_emailed_and_not_returned(): void
    {
        $this->app['env'] = 'production';
        config(['mail.default' => 'array']);
        $this->user();

        $res = $this->postJson('/api/v1/auth/login', ['email' => 'ana@example.com', 'password' => 'secret-pass'])
            ->assertOk()->assertJsonPath('mfa_required', true)->assertJsonMissingPath('dev_code');

        $messages = app('mailer')->getSymfonyTransport()->messages();
        $this->assertCount(1, $messages);
        preg_match('/code is (\d{6})/', $messages[0]->getOriginalMessage()->getTextBody(), $m);
        $this->assertNotEmpty($m);

        $this->postJson('/api/v1/auth/verify-mfa', ['email' => $res->json('email'), 'code' => $m[1]])->assertOk();
    }

    public function test_in_production_a_mail_failure_is_reported_to_the_user(): void
    {
        $this->app['env'] = 'production';
        config(['mail.default' => 'smtp', 'mail.mailers.smtp.host' => '127.0.0.1', 'mail.mailers.smtp.port' => 1, 'mail.mailers.smtp.timeout' => 1]);
        $this->user();

        $this->postJson('/api/v1/auth/login', ['email' => 'ana@example.com', 'password' => 'secret-pass'])
            ->assertStatus(503)->assertJsonMissingPath('dev_code');
    }

    public function test_locally_the_code_is_shown_for_testing(): void
    {
        config(['mail.default' => 'array']);
        $this->user();

        $this->postJson('/api/v1/auth/login', ['email' => 'ana@example.com', 'password' => 'secret-pass'])
            ->assertOk()->assertJsonStructure(['dev_code']);
    }
}

<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Mail;
use Symfony\Component\Mailer\Bridge\Brevo\Transport\BrevoApiTransport;
use Tests\TestCase;

class MailTransportTest extends TestCase
{
    public function test_brevo_mailer_uses_the_https_api(): void
    {
        config(['services.brevo.key' => 'xkeysib-test']);

        $this->assertInstanceOf(BrevoApiTransport::class, Mail::mailer('brevo')->getSymfonyTransport());
    }
}

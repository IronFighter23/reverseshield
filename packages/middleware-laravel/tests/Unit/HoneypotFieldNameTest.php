<?php

declare(strict_types=1);

namespace ReverseShield\Laravel\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use ReverseShield\Laravel\Support\HoneypotFieldName;
use ReverseShield\Laravel\Tests\TestCase;

final class HoneypotFieldNameTest extends TestCase
{
    #[Test]
    public function it_returns_empty_string_for_empty_site_id(): void
    {
        $this->assertSame('', HoneypotFieldName::forSite(''));
    }

    #[Test]
    public function it_is_deterministic_for_the_same_site_id(): void
    {
        $a = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $b = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $this->assertSame($a, $b);
    }

    #[Test]
    public function it_produces_different_names_for_different_site_ids(): void
    {
        $a = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $b = HoneypotFieldName::forSite('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
        $this->assertNotSame($a, $b);
    }

    #[Test]
    public function the_name_starts_with_email_alt_prefix(): void
    {
        $name = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $this->assertStringStartsWith('email_alt_', $name);
    }

    #[Test]
    public function the_suffix_is_eight_lowercase_hex_chars(): void
    {
        $name = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $suffix = substr($name, strlen('email_alt_'));
        $this->assertSame(8, strlen($suffix));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{8}$/', $suffix);
    }

    #[Test]
    public function from_config_reads_the_configured_site_id(): void
    {
        $expected = HoneypotFieldName::forSite(self::TEST_SITE_ID);
        $this->assertSame($expected, HoneypotFieldName::fromConfig());
    }

    #[Test]
    public function from_config_returns_empty_when_site_id_missing(): void
    {
        config()->set('reverseshield.site_id', '');
        $this->assertSame('', HoneypotFieldName::fromConfig());
    }

    #[Test]
    public function html_field_produces_a_visually_hidden_input_with_the_derived_name(): void
    {
        $html = HoneypotFieldName::htmlField();
        $name = HoneypotFieldName::fromConfig();

        $this->assertStringContainsString('name="' . $name . '"', $html);
        $this->assertStringContainsString('tabindex="-1"', $html);
        $this->assertStringContainsString('autocomplete="off"', $html);
        $this->assertStringContainsString('aria-hidden="true"', $html);
    }

    #[Test]
    public function html_field_is_empty_when_site_id_missing(): void
    {
        config()->set('reverseshield.site_id', '');
        $this->assertSame('', HoneypotFieldName::htmlField());
    }
}

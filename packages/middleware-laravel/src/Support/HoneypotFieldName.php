<?php

declare(strict_types=1);

namespace ReverseShield\Laravel\Support;

/**
 * Derives per-site honeypot form field names deterministically from the site UUID.
 *
 * SPEC §8 guardrail: honeypot names must never be hardcoded. A scraper faced
 * with predictable names could just skip every input matching a known
 * allowlist. Deriving from the site_id gives us:
 *   * Different name per install
 *   * Stable within an install (so submitted forms can be checked against the
 *     same name the injector chose)
 *   * No coordination needed between the injector and the checker
 *
 * The derivation is identical to the WordPress plugin's, so a site running
 * both integrations exposes the same honeypot surface.
 */
final class HoneypotFieldName
{
    /**
     * Compute the honeypot field name for a given site UUID.
     *
     * Returns an empty string if the site UUID is empty — the caller should
     * treat this as "honeypot disabled" rather than as a hardcoded fallback.
     */
    public static function forSite(string $siteId): string
    {
        if ($siteId === '') {
            return '';
        }
        $seed = substr(hash('sha256', $siteId . '::honeypot'), 0, 8);

        return 'email_alt_' . $seed;
    }

    /**
     * Convenience: read the site_id from the Laravel config and derive.
     */
    public static function fromConfig(): string
    {
        /** @var string $siteId */
        $siteId = config('reverseshield.site_id', '');

        return self::forSite((string) $siteId);
    }

    /**
     * Render the honeypot field as ready-to-print HTML. Called by the Blade
     * directive @reverseshieldHoneypot, so users just drop that into their
     * forms.
     *
     * Visually hidden via absolute positioning off-screen (not display:none,
     * which some accessibility tools traverse anyway) plus tabindex=-1,
     * aria-hidden, and autocomplete=off. A real user can't focus this or
     * have their browser fill it.
     */
    public static function htmlField(): string
    {
        $name = self::fromConfig();
        if ($name === '') {
            return '';
        }

        $escapedName = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');

        return '<p style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden;" aria-hidden="true">'
            . '<label>Leave this field empty</label>'
            . '<input type="text" name="' . $escapedName . '" value="" tabindex="-1" autocomplete="off">'
            . '</p>';
    }
}

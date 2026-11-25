<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** The cookies the SDK keeps on the visitor's browser, and how it reads them. */
final class Cookies
{
    /** The session's token, where the tag reads and renews it. */
    public const TOKEN = '_kz';

    /**
     * A cookie's value from a Cookie header, the first of that name; null when there is
     * none. It reads the header itself: PHP's $_COOKIE turns a "." or a space in a name
     * into "_", so another cookie could pass for _kz there.
     */
    public static function read(string $header, string $name): ?string
    {
        foreach (explode(';', $header) as $part) {
            $at = strpos($part, '=');
            if ($at !== false && $at > 0 && trim(substr($part, 0, $at)) === $name) {
                return trim(substr($part, $at + 1));
            }
        }

        return null;
    }
}

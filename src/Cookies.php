<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** The cookies the SDK keeps on the visitor's browser, and how it reads them. */
final class Cookies
{
    /** The session's token, where the tag reads and renews it. */
    public const TOKEN = '_kz';

    /**
     * Marks a browser this server sent to the challenge page in the last ten minutes: only
     * such a browser may bring a token back in the address, so a link with someone else's
     * token in it plants nothing.
     */
    public const CHALLENGE = '_kz_c';

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

    /**
     * The Set-Cookie that keeps a token where the tag keeps it: _kz, a day. Not HttpOnly:
     * the tag reads and renews it.
     */
    public static function token(string $token, bool $secure): string
    {
        return self::TOKEN . '=' . $token . '; Path=/; Max-Age=86400; SameSite=Lax' . ($secure ? '; Secure' : '');
    }

    /** The Set-Cookie of the challenge mark, ten minutes; $clear removes it. */
    public static function challenge(bool $secure, bool $clear = false): string
    {
        return self::CHALLENGE . '=' . ($clear ? '' : '1') . '; Path=/; Max-Age=' . ($clear ? '0' : '600')
            . '; HttpOnly; SameSite=Lax' . ($secure ? '; Secure' : '');
    }
}

<?php

declare(strict_types=1);

namespace Korzen\BotProtection\Laravel;

use Symfony\Component\HttpFoundation\Cookie;

/**
 * A Symfony cookie sent as the exact Set-Cookie line the SDK writes: Symfony's own writes
 * Max-Age from its expiry time, so it can say 599 for 600, and adds an Expires.
 *
 * @internal
 */
final class SetCookie extends Cookie
{
    private readonly string $line;

    /** @param bool $secure and the rest, as the line says, for code that reads the cookie */
    public function __construct(string $line, string $name, string $value, bool $secure, bool $httpOnly)
    {
        parent::__construct($name, $value, 0, '/', null, $secure, $httpOnly, true, self::SAMESITE_LAX);
        $this->line = $line;
    }

    public function __toString(): string
    {
        return $this->line;
    }
}

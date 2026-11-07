<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The ways to read the visitor's IP, for the ip option of Middleware and Protect, or for
 * DecideRequest::from(). Use only the one your set-up makes true: a header is the
 * visitor's only when your own edge writes it, and otherwise the visitor can write it and
 * pick their IP. Each takes a PSR-7 or a Symfony (Laravel) request.
 */
final class Ip
{
    /**
     * The connection's address (REMOTE_ADDR): the visitor's when nothing stands in front
     * of your server. The default.
     */
    public static function socket(ServerRequestInterface|Request $request): ?string
    {
        return self::some(Visit::of($request)->remoteAddr);
    }

    /**
     * The last X-Forwarded-For entry: the one your own load balancer or nginx appended.
     * The entries before it are whatever the visitor sent. None when the header is absent.
     */
    public static function lastForwarded(ServerRequestInterface|Request $request): ?string
    {
        return self::some(self::lastEntry(Visit::of($request)->header('x-forwarded-for')));
    }

    /**
     * CF-Connecting-IP: the visitor's only if your server takes traffic from Cloudflare
     * alone; otherwise a visitor writes it.
     */
    public static function cloudflare(ServerRequestInterface|Request $request): ?string
    {
        return self::some(trim(Visit::of($request)->header('cf-connecting-ip')));
    }

    /**
     * Where the reader $ip reads the IP, as the API names it: custom for one of yours.
     *
     * @param \Closure(never): ?string $ip
     */
    public static function fromOf(\Closure $ip): string
    {
        $f = new \ReflectionFunction($ip);

        return match ($f->getClosureScopeClass()?->getName() === self::class ? $f->getName() : '') {
            'socket' => 'peer',
            'cloudflare' => 'cloudflare',
            'lastForwarded' => 'last_forwarded',
            default => 'custom',
        };
    }

    /**
     * The scheme $v came on, read where $ip reads the visitor's IP: CF-Visitor's with
     * Ip::cloudflare(...), the last X-Forwarded-Proto entry with Ip::lastForwarded(...),
     * each written by the edge that wrote the IP; otherwise, Ip::socket(...) or a reader of
     * yours, the framework's own view (Visit::$scheme): Laravel's, which reads a proxy's
     * header only when it trusts that proxy (TrustProxies), or for PSR-7 the connection's.
     * Null when nothing names http or https: an unknown scheme is sent as none.
     *
     * @param \Closure(never): (string|null) $ip the middleware's IP reader
     *
     * @internal
     */
    public static function schemeOf(\Closure $ip, Visit $v): ?string
    {
        $f = new \ReflectionFunction($ip);
        $reader = $f->getClosureScopeClass()?->getName() === self::class ? $f->getName() : '';

        return match ($reader) {
            'cloudflare' => self::cloudflareScheme($v->header('cf-visitor')),
            'lastForwarded' => Bounds::scheme(self::lastEntry($v->header('x-forwarded-proto'))),
            default => Bounds::scheme($v->scheme),
        };
    }

    /**
     * CF-Visitor's scheme ({"scheme":"https"}), the one the visitor reached Cloudflare on;
     * null when it names none.
     *
     * @internal
     */
    public static function cloudflareScheme(string $visitor): ?string
    {
        try {
            $v = json_decode($visitor, true, 4, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return \is_array($v) && \is_string($v['scheme'] ?? null) ? Bounds::scheme($v['scheme']) : null;
    }

    /** The last entry of a header a chain of proxies appends to, trimmed. */
    private static function lastEntry(string $v): string
    {
        $at = strrpos($v, ',');

        return trim($at === false ? $v : substr($v, $at + 1));
    }

    /**
     * Whether $ip is an address not on the Internet, loopback aside, as Bot Protection
     * reads it: private (10/8, 172.16/12, 192.168/16, fc00::/7), the carriers' inside
     * (100.64/10), link-local, multicast, unspecified, the broadcast address. No visitor
     * reaches a server from one: it is the server's own network, such as its load
     * balancer's. Loopback is a test on the developer's machine, and what is not an
     * address says nothing.
     *
     * @internal
     */
    public static function ownNetwork(string $ip): bool
    {
        $b = self::bytes($ip);
        if ($b === null) {
            return false;
        }
        if (\strlen($b) === 4) {
            [$a, $o2] = [\ord($b[0]), \ord($b[1])];

            return $a !== 127 && (
                $b === "\0\0\0\0"
                || $b === "\xff\xff\xff\xff"
                || $a === 10
                || ($a === 100 && $o2 >= 64 && $o2 < 128)
                || ($a === 169 && $o2 === 254)
                || ($a === 172 && $o2 >= 16 && $o2 < 32)
                || ($a === 192 && $o2 === 168)
                || ($a >= 224 && $a < 240)
            );
        }
        [$h0, $h1] = [\ord($b[0]), \ord($b[1])];

        return $b !== str_repeat("\0", 15) . "\1" && (
            $b === str_repeat("\0", 16)
            || ($h0 & 0xFE) === 0xFC
            || ($h0 === 0xFE && ($h1 & 0xC0) === 0x80)
            || $h0 === 0xFF
        );
    }

    /**
     * Whether $host (a name, an IPv4 address or a bracketed IPv6 one, without a port) is
     * the machine itself: localhost, 127/8, ::1.
     *
     * @internal
     */
    public static function loopback(string $host): bool
    {
        if (strtolower($host) === 'localhost') {
            return true;
        }
        $b = self::bytes(trim($host, '[]'));

        return $b !== null && (\strlen($b) === 4 ? $b[0] === "\x7f" : $b === str_repeat("\0", 15) . "\1");
    }

    /**
     * The address's bytes, an IPv4-mapped IPv6 address as its IPv4 one; null when $ip is
     * not an address.
     */
    private static function bytes(string $ip): ?string
    {
        // inet_pton also reads forms filter_var refuses; filter_var first, so both agree.
        if (filter_var($ip, \FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $b = (string) inet_pton($ip);
        if (str_starts_with($b, str_repeat("\0", 10) . "\xff\xff")) {
            return substr($b, 12);
        }

        return $b;
    }

    private static function some(string $v): ?string
    {
        return $v === '' ? null : $v;
    }
}

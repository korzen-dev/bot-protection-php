<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Request;

/** The address a visitor asked for, to come back to from the challenge page. */
final class ReturnTo
{
    /**
     * The address $request asked for, as the visitor's browser saw it: on the host of
     * X-Forwarded-Host and the scheme of X-Forwarded-Proto when a proxy sets them (the
     * first entry of each), else on the Host header; then https, but for a loopback host
     * on a laptop. A proxy that forwards Host: localhost and no X-Forwarded-Host (nginx's
     * default) needs the publicUrl option. A visitor who writes X-Forwarded-Host only sends
     * themselves elsewhere: the challenge page takes no address off your domains.
     */
    public static function request(ServerRequestInterface|Request $request): string
    {
        $v = Visit::of($request);
        $host = self::first($v->header('x-forwarded-host'));

        return self::seen(self::first($v->header('x-forwarded-proto')), $host === '' ? $v->host : $host, $v->target);
    }

    /**
     * A returnTo that builds the address on $publicUrl's scheme and host, the origin your
     * visitors see (https://shop.example), with the path and query the request asked for.
     *
     * @return \Closure(ServerRequestInterface|Request): string
     *
     * @throws \InvalidArgumentException when $publicUrl is not an http(s) URL with a host,
     *     so a typo stops the server at start instead of reaching a visitor
     */
    public static function publicUrl(string $publicUrl): \Closure
    {
        // The SDK runs outside WordPress too, and PHP 8's parse_url has none of the faults
        // wp_parse_url works around.
        // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
        $u = parse_url($publicUrl);
        $scheme = strtolower(\is_array($u) ? $u['scheme'] ?? '' : '');
        if (!\is_array($u) || !isset($u['host']) || ($scheme !== 'https' && $scheme !== 'http')) {
            throw new \InvalidArgumentException(
                'korzen: publicUrl must be an http(s) URL, such as https://shop.example',
            );
        }
        $host = $u['host'] . (isset($u['port']) ? ':' . $u['port'] : '');

        return static fn(ServerRequestInterface|Request $r): string
            => self::seen($scheme, $host, Visit::of($r)->target);
    }

    /**
     * $target on $host: over https unless the host is loopback, and then over http unless
     * $proto says https.
     */
    private static function seen(string $proto, string $host, string $target): string
    {
        if (
            preg_match('/^(\[[^\]]*\])(?::\d*)?$/D', $host, $m) === 1
            || preg_match('/^([^:]*):\d*$/D', $host, $m) === 1
        ) {
            $name = $m[1];
        } else {
            $name = $host;
        }
        $scheme = !Ip::loopback($name) || strtolower($proto) === 'https' ? 'https' : 'http';

        return $scheme . '://' . $host . $target;
    }

    /** The first entry of a header a chain of proxies appends to, trimmed. */
    private static function first(string $v): string
    {
        return trim(explode(',', $v, 2)[0]);
    }
}

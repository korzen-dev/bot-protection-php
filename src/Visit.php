<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A visitor's request as the SDK reads it, the same from PSR-7 and from Symfony (Laravel).
 *
 * @internal
 */
final readonly class Visit
{
    /**
     * @param string $method the method the browser sent, never an override
     * @param string $target the path and query asked for, as they came
     * @param array<string, list<string>> $headers by lower-cased name
     * @param list<string> $order the headers' names in the order they came, lower-cased;
     *     empty where the server keeps none
     * @param string $scheme the scheme as the framework sees it: Symfony's getScheme(), which
     *     reads X-Forwarded-Proto only from a proxy it trusts; for PSR-7, which trusts no
     *     proxy, the connection's (connScheme); '' when it names none
     */
    public function __construct(
        public string $method,
        public string $target,
        public string $host,
        private array $headers,
        public string $remoteAddr,
        public array $order = [],
        public string $scheme = '',
    ) {}

    /**
     * The order the headers came in, as PHP's $_SERVER keeps it in its HTTP_ keys:
     * lower-cased, with _ as -, and reversed under PHP-FPM, which lists them last first.
     * PHP's built-in server (php artisan serve) keeps them first first; behind nginx it is
     * the order nginx forwards them in. Empty when $server holds no HTTP_ key, as a PSR-7
     * request a framework built by hand.
     *
     * @param array<array-key, mixed> $server
     *
     * @return list<string>
     */
    public static function order(array $server, string $sapi = \PHP_SAPI): array
    {
        $names = [];
        foreach ($server as $key => $value) {
            if (\is_string($key) && str_starts_with($key, 'HTTP_')) {
                $names[] = strtolower(strtr(substr($key, 5), '_', '-'));
            }
        }

        return $sapi === 'fpm-fcgi' ? array_reverse($names) : $names;
    }

    public static function of(ServerRequestInterface|Request $r): self
    {
        if ($r instanceof Request) {
            $headers = [];
            foreach ($r->headers->all() as $name => $values) {
                $headers[strtolower($name)] = array_map('strval', $values);
            }
            $remote = $r->server->get('REMOTE_ADDR');

            return new self(
                $r->getRealMethod(),
                $r->getRequestUri(),
                $r->headers->get('host') ?? '',
                $headers,
                \is_string($remote) ? $remote : '',
                self::order($r->server->all()),
                self::frameworkScheme($r),
            );
        }
        $headers = [];
        foreach ($r->getHeaders() as $name => $values) {
            $headers[strtolower((string) $name)] = array_values($values);
        }
        // The Host header as the server got it: a PSR-7 request built from globals may hold
        // the URI's host and port too (nyholm's puts "shop.example:8080" before it).
        $server = $r->getServerParams();
        $host = $server['HTTP_HOST'] ?? $r->getHeader('host')[0] ?? '';
        $host = \is_string($host) ? $host : '';
        if ($host === '') {
            $uri = $r->getUri();
            $host = $uri->getHost() . ($uri->getPort() === null ? '' : ':' . $uri->getPort());
        }
        $remote = $server['REMOTE_ADDR'] ?? '';

        return new self(
            $r->getMethod(),
            $r->getRequestTarget(),
            $host,
            $headers,
            \is_string($remote) ? $remote : '',
            self::order($server),
            self::connScheme($server),
        );
    }

    /**
     * Symfony's (Laravel's) scheme, which reads a proxy's header only when the app trusts
     * that proxy; '' when it cannot tell: behind a trusted proxy whose Forwarded and
     * X-Forwarded-Proto disagree it throws, and a visitor who wrote them must not stop the
     * decision.
     */
    private static function frameworkScheme(Request $r): string
    {
        try {
            return $r->getScheme();
        } catch (\Throwable) {
            return '';
        }
    }

    /**
     * The connection's scheme, from the server params as the SAPI sets them: https when
     * HTTPS is set and not "off", else REQUEST_SCHEME, else http for a request that came on
     * a connection (REMOTE_ADDR); '' for one built by hand. Never the URI's: a PSR-7 factory
     * may take it from X-Forwarded-Proto, which a visitor writes (nyholm/psr7-server does).
     *
     * @param array<array-key, mixed> $server
     */
    public static function connScheme(array $server): string
    {
        $https = $server['HTTPS'] ?? '';
        if (\is_string($https) && $https !== '' && strtolower($https) !== 'off') {
            return 'https';
        }
        $scheme = $server['REQUEST_SCHEME'] ?? null;
        if (\is_string($scheme) && $scheme !== '') {
            return $scheme;
        }

        return isset($server['REMOTE_ADDR']) ? 'http' : '';
    }

    /** The header's values joined as one, as a proxy may send them; '' when absent. */
    public function header(string $name): string
    {
        return implode(', ', $this->headers[$name] ?? []);
    }

    /**
     * Every header, by lower-cased name, each with its values.
     *
     * @return array<string, list<string>>
     */
    public function headers(): array
    {
        return $this->headers;
    }

    public function has(string $name): bool
    {
        return isset($this->headers[$name]);
    }

    /** The path asked for, without the query. */
    public function path(): string
    {
        return explode('?', $this->target, 2)[0];
    }

    /** The first cookie of that name in the Cookie header; null when there is none. */
    public function cookie(string $name): ?string
    {
        // HTTP/2 may send a Cookie header per cookie: they join with "; ".
        return Cookies::read(implode('; ', $this->headers['cookie'] ?? []), $name);
    }

    /**
     * The tag's token: the x-korzen-token header when, trimmed, it is a token, else the _kz
     * cookie; null without either. A header that is no token (empty, blank, too long, sent
     * twice) leaves the cookie, so a page's mistaken header never hides a good cookie.
     * contract.json's decide.token holds the cases, which every SDK passes.
     */
    public function token(): ?string
    {
        $header = trim($this->header(DecideRequest::TOKEN_HEADER));
        if (preg_match(Challenge::TOKEN_PATTERN, $header) === 1) {
            return $header;
        }

        return $this->cookie(Cookies::TOKEN);
    }

    public function pageLoad(): bool
    {
        return $this->method === 'GET' || $this->method === 'HEAD';
    }
}

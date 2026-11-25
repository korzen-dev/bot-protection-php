<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * First-party mode (korzen's decision 0238): the tag and its beacon served from the
 * customer's own domain, under a path of its own (DEFAULT_PATH unless the firstPartyPath
 * option names one), and forwarded to Bot Protection with the visitor's address: a block
 * list or a DNS filter that stops korzen.dev stops none of it. Every Korzen forwarder
 * (Go's, Node's, this one) follows the same contract:
 *
 *     GET  P/tag.js          -> GET  /v1/tag.js          1 s
 *     GET  P/n?...           -> GET  /v1/n?...           1 s
 *     POST P/s?...           -> POST /v1/s?...           2.5 s, a body of at most 64 KiB
 *     GET  P/ping            -> 204 answered here, never forwarded
 *
 * Any other path under P is a 404 and a known one with another method a 405, neither
 * forwarded; a path outside P is the customer's own and is judged as before. Anything that
 * goes wrong (Korzen slow or down, no visitor address, a fault here) is a 503 with an empty
 * body: the tag drops that signal, and the customer's own routes wait on nothing.
 *
 * @internal
 */
final readonly class FirstParty
{
    /** The path first-party mode serves when the firstPartyPath option names none. */
    public const DEFAULT_PATH = '/kz';

    /** The longest path setting, in bytes. */
    private const MAX_PATH = 64;
    /** A GET is the tag or a nonce, from the call to the answer's last byte. */
    private const GET_MS = 1000;
    /** A POST is a beacon, from the call to the answer's last byte. */
    private const POST_MS = 2500;
    /** The body the forwarder takes: a beacon. */
    private const MAX_BEACON = 64 << 10;
    /** What the forwarder reads of Korzen's answer: the tag is tens of KiB. */
    private const MAX_ANSWER = 4 << 20;
    /** A path setting that does not read, as it is logged. */
    private const SHOWN_PATH = 80;
    /** One segment of the path setting: unreserved characters alone (RFC 3986 §2.3). */
    private const SEGMENT = '/^[A-Za-z0-9._~-]+$/D';

    /** How a route sends the visitor's address: no address is a 503. */
    private const NEEDED = 0;
    /** How a route sends the visitor's address: sent when known. */
    private const WHEN_KNOWN = 1;

    /**
     * The visitor's headers the forwarder sends on, besides every Sec-Fetch-* and Sec-CH-*:
     * never a Cookie, the browser's Authorization or an X-Forwarded-* the visitor may have
     * written.
     */
    private const SENT = ['user-agent', 'accept', 'accept-language', 'content-type', 'origin', 'if-none-match'];

    /**
     * Korzen's answer's headers the forwarder passes back: never a Set-Cookie,
     * X-Korzen-Stamp or X-Korzen-Mark, which are Korzen's origin's alone.
     */
    private const PASSED = [
        'Content-Type', 'Cache-Control', 'ETag', 'Last-Modified', 'Expires', 'Vary',
        'Content-Security-Policy', 'X-Content-Type-Options', 'X-Robots-Tag', 'Referrer-Policy',
        'Permissions-Policy', 'Timing-Allow-Origin', 'Location', 'Retry-After',
    ];

    /**
     * The contract's routes under P, by method: where each goes, its time, its body's cap
     * (0 for none), and how it sends the visitor's address. The ping, to '', is answered
     * here.
     */
    private const ROUTES = [
        '/tag.js' => [
            'GET' => [
                'to' => '/v1/tag.js',
                'ms' => self::GET_MS,
                'max' => 0,
                'visitor' => self::WHEN_KNOWN,
            ],
        ],
        '/n' => [
            'GET' => ['to' => '/v1/n', 'ms' => self::GET_MS, 'max' => 0, 'visitor' => self::NEEDED],
        ],
        '/s' => [
            'POST' => [
                'to' => '/v1/s',
                'ms' => self::POST_MS,
                'max' => self::MAX_BEACON,
                'visitor' => self::NEEDED,
            ],
        ],
        '/ping' => [
            'GET' => ['to' => '', 'ms' => 0, 'max' => 0, 'visitor' => self::WHEN_KNOWN],
        ],
    ];

    private function __construct(private Client $client, public string $prefix) {}

    /**
     * $client's first-party mode, null when it is off: $on false, a path that does not
     * read, or a transport that cannot forward, each of the last two logged once.
     *
     * @param string|null $path the path it serves; DEFAULT_PATH when null or ''
     */
    public static function of(Client $client, bool $on, ?string $path): ?self
    {
        if (!$on) {
            return null;
        }
        $path = $path === null || $path === '' ? self::DEFAULT_PATH : $path;
        if (!self::validPath($path)) {
            $shown = substr($path, 0, self::SHOWN_PATH);
            $client->warnOnceAbout(
                'first-party-path',
                'korzen: firstPartyPath must start with "/", end without one, and be at most ' . self::MAX_PATH
                . ' bytes of A-Z a-z 0-9 . _ ~ - segments (no "." or ".."): first-party mode is off (path '
                . json_encode($shown, \JSON_UNESCAPED_SLASHES | \JSON_INVALID_UTF8_SUBSTITUTE) . ')',
            );

            return null;
        }
        if (!$client->forwards()) {
            $client->warnOnceAbout(
                'first-party-transport',
                'korzen: first-party mode needs a transport that implements ForwardTransport '
                . '(CurlTransport, StreamTransport): first-party mode is off',
            );

            return null;
        }

        return new self($client, $path);
    }

    /**
     * Serves $visit when its path is under the forwarder's: Korzen's answer, or the
     * forwarder's own refusal; null for a path outside it, which the middleware judges as
     * before. It never throws: a fault on the way is a 503, logged once.
     *
     * @param \Closure(): string $body the visitor's body, read when a route takes one
     * @param \Closure(): ?string $ip the visitor's address, read as the middleware reads it
     */
    public function serve(Visit $visit, \Closure $body, \Closure $ip): ?Outcome
    {
        [$path, $query] = self::split($visit->target);
        $path = self::routed($path);
        if ($path !== $this->prefix && !str_starts_with($path, $this->prefix . '/')) {
            return null;
        }
        try {
            return $this->answer($visit, substr($path, \strlen($this->prefix)), $query, $body, $ip);
        } catch (\Throwable $e) {
            $this->client->warnOnceAbout(
                'first-party-fault',
                'korzen: the first-party forwarder answered 503 after an error: ' . $e::class,
            );

            return self::refuse(503);
        }
    }

    /**
     * The answer to a request for $rest, a path under P without P.
     *
     * @param \Closure(): string $body
     * @param \Closure(): ?string $ip
     */
    private function answer(Visit $visit, string $rest, string $query, \Closure $body, \Closure $ip): Outcome
    {
        $routes = self::ROUTES[$rest] ?? null;
        if ($routes === null) {
            return self::refuse(404);
        }
        $route = $routes[$visit->method] ?? null;
        if ($route === null) {
            $allow = array_keys($routes);
            sort($allow);

            return Outcome::forwarded(405, [['Allow', implode(', ', $allow)], ['Cache-Control', 'no-store']], '');
        }
        if ($route['to'] === '') {
            return Outcome::forwarded(204, [['Cache-Control', 'no-store'], ['Timing-Allow-Origin', '*']], '');
        }
        // The route's time runs from here.
        $deadline = microtime(true) + $route['ms'] / 1000;
        $address = self::visitorIp($ip());
        if ($route['visitor'] === self::NEEDED && $address === '') {
            return self::refuse(503);
        }
        $this->warnOwnNetwork($address);
        $sent = '';
        if ($route['max'] > 0) {
            $length = $visit->header('content-length');
            if (ctype_digit($length) && (\strlen($length) > 18 || (int) $length > $route['max'])) {
                return self::refuse(413);
            }
            $sent = $body();
            if (\strlen($sent) > $route['max']) {
                return self::refuse(413);
            }
        }
        $headers = $this->headers($visit, $address);
        $answer = $this->client->forward(
            $route['max'] > 0 ? 'POST' : 'GET',
            $route['to'] . ($query === '' ? '' : '?' . $query),
            $headers,
            $sent,
            $deadline,
            self::MAX_ANSWER,
        );
        if (\strlen($answer->body) > self::MAX_ANSWER) {
            // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- a message, never written to a page.
            throw new \RuntimeException('korzen: an answer past ' . self::MAX_ANSWER . ' bytes');
        }
        $passed = [];
        foreach (self::PASSED as $name) {
            if (\array_key_exists(strtolower($name), $answer->headers)) {
                $passed[] = [$name, $answer->header($name)];
            }
        }

        return Outcome::forwarded($answer->status, $passed, $answer->body);
    }

    /**
     * The headers the forward carries: the visitor's that the forwarder sends on (a repeated
     * one joined with ", ", an empty one as none), the visitor's address and the path.
     *
     * @return array<string, string>
     */
    private function headers(Visit $visit, string $address): array
    {
        $headers = [];
        foreach ($visit->headers() as $name => $values) {
            $value = implode(', ', $values);
            if ($value !== '' && self::sent($name)) {
                $headers[$name] = $value;
            }
        }
        if ($address !== '') {
            $headers['Korzen-Visitor-Ip'] = $address;
        }
        $headers['Korzen-Forwarded-Prefix'] = $this->prefix;

        return $headers;
    }

    /** Whether the forwarder sends on a visitor's header, by its lower-cased name. */
    private static function sent(string $name): bool
    {
        return \in_array($name, self::SENT, true) || str_starts_with($name, 'sec-fetch-')
            || str_starts_with($name, 'sec-ch-');
    }

    /**
     * Logs, once for the client, a visitor's address the forwarder sends on the server's
     * own network, as Decide's warning does: Bot Protection refuses it outside local mode.
     * Behind a proxy it is the proxy's.
     */
    private function warnOwnNetwork(string $address): void
    {
        if ($address === '' || !Ip::ownNetwork($address)) {
            return;
        }
        $this->client->warnOnceAbout(
            'first-party-visitor-ip',
            "korzen: the visitor's IP the first-party forwarder sends, {$address}, is not on the Internet: "
            . 'Bot Protection refuses it outside local mode (a page on your machine). Behind a proxy or load '
            . 'balancer, set the ip option (Ip::lastForwarded(...), Ip::cloudflare(...), or a function of '
            . "yours) to the visitor's address: " . Client::IP_HELP,
        );
    }

    /** $status with an empty body, never cached. */
    private static function refuse(int $status): Outcome
    {
        return Outcome::forwarded($status, [['Cache-Control', 'no-store']], '');
    }

    /**
     * Whether $path reads as a path setting: "/" first, no "/" last, at most MAX_PATH bytes,
     * each segment of unreserved characters and none "." or "..".
     */
    public static function validPath(string $path): bool
    {
        if (\strlen($path) > self::MAX_PATH || !str_starts_with($path, '/')) {
            return false;
        }
        foreach (explode('/', substr($path, 1)) as $segment) {
            if (preg_match(self::SEGMENT, $segment) !== 1 || $segment === '.' || $segment === '..') {
                return false;
            }
        }

        return true;
    }

    /**
     * $target's path and query, as the request line wrote them: the absolute form's scheme
     * and host taken off (nyholm/psr7 writes it after a "/"), an empty query none.
     *
     * @return array{string, string}
     */
    private static function split(string $target): array
    {
        if (preg_match('#^/?[A-Za-z][A-Za-z0-9+.-]*://[^/?]*#', $target, $m) === 1) {
            $target = '/' . ltrim(substr($target, \strlen($m[0])), '/');
        }
        $parts = explode('?', $target, 2);

        return [$parts[0], $parts[1] ?? ''];
    }

    /**
     * $path, an escaped path, as every Korzen forwarder routes it: read as a URL parser
     * reads it (RFC 3986 §5.2.4, and the WHATWG URL Standard), each "." and ".." segment
     * removed, written or escaped ("%2e", any case), and a trailing one leaving the path
     * ending in "/". Any other escape stays as it came, so "/kz/%74ag.js" is no route. A
     * path that does not start with "/" is returned as it is.
     */
    public static function routed(string $path): string
    {
        if (!str_starts_with($path, '/')) {
            return $path;
        }
        $segments = explode('/', substr($path, 1));
        $last = \count($segments) - 1;
        $out = [];
        foreach ($segments as $i => $segment) {
            $lower = strtolower($segment);
            if (\in_array($lower, ['..', '.%2e', '%2e.', '%2e%2e'], true)) {
                array_pop($out);
                if ($i === $last) {
                    $out[] = '';
                }
            } elseif ($lower === '.' || $lower === '%2e') {
                if ($i === $last) {
                    $out[] = '';
                }
            } else {
                $out[] = $segment;
            }
        }

        return '/' . implode('/', $out);
    }

    /**
    /** $ip trimmed when it is an IPv4 or IPv6 address without a zone; '' otherwise. */
    private static function visitorIp(?string $ip): string
    {
        $s = trim($ip ?? '');

        return filter_var($s, \FILTER_VALIDATE_IP) !== false && !str_contains($s, '%') ? $s : '';
    }
}

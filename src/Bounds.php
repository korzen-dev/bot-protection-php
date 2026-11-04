<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * What Bot Protection keeps of a decision's fields, as its API documents them, in UTF-8
 * bytes. decide() cuts every field to them before it sends the call, so a visitor's
 * oversized header never pushes the body past what the API reads: the server would cut
 * them alike. Every Korzen SDK cuts the same.
 *
 * @internal
 */
final class Bounds
{
    /** Fields cut to a number of bytes. */
    private const LIMITS = [
        'user_agent' => 512,
        'token' => 256,
        'path' => 512,
        'method' => 16,
        'ja4' => 64,
        'http_protocol' => 16,
        'tls_group' => 64,
    ];
    public const MAX_VALUE = 512; // a header's value
    public const MAX_HEADERS = 32; // headers, the first by name
    public const MAX_NAME = 64; // a header's name
    public const MAX_ORDER = 64; // names of header_order
    public const MAX_IP = 64; // longer is no address, and is left out
    public const MAX_ACCOUNT_AGE = 4294967295; // the API reads a u32; past it, a 400 would skip protection
    public const MAX_COUNTRY = 2; // longer is no code, and is left out: cut, Germany would read as Ge

    /**
     * $url as the client calls it, its trailing slashes taken out: an https URL with a
     * host, or an http one on loopback (localhost, 127.0.0.0/8, [::1]), a test on your
     * machine. Null for any other, which would send the key in clear or nowhere: http on
     * another host (0.0.0.0 too), another scheme, no host, a space or a control character,
     * or no URL at all.
     */
    public static function apiUrl(string $url): ?string
    {
        if (preg_match('/[\x00-\x20\x7f]/', $url) === 1) {
            return null;
        }
        $u = parse_url($url);
        $host = \is_array($u) ? $u['host'] ?? '' : '';
        $scheme = strtolower(\is_array($u) ? $u['scheme'] ?? '' : '');
        if ($host === '' || ($scheme !== 'https' && ($scheme !== 'http' || !Ip::loopback($host)))) {
            return null;
        }

        return rtrim($url, '/');
    }

    /**
     * http or https when $s names one, in any case and spacing; null for any other, which
     * the API refuses (contract.json's decide.schemes), so it is sent as none.
     */
    public static function scheme(?string $s): ?string
    {
        $v = strtolower(trim($s ?? ''));

        return $v === 'http' || $v === 'https' ? $v : null;
    }

    /** $s in at most $n bytes, cut on a UTF-8 character. */
    public static function cut(string $s, int $n): string
    {
        if (\strlen($s) <= $n) {
            return $s;
        }
        // Back off the bytes that continue a character (10xxxxxx).
        while ($n > 0 && (\ord($s[$n]) & 0xC0) === 0x80) {
            --$n;
        }

        return substr($s, 0, $n);
    }

    /**
     * The JSON body of $r: only the fields set, each cut to what the API keeps, its context
     * hashed. $onCardNumber is told when the context's card_bin may be a card number, which
     * is left out. A context that cannot be keyed is left out, and the rest is sent.
     *
     * @param (callable(): void)|null $onCardNumber
     *
     * @return array<string, mixed>
     */
    public static function body(DecideRequest $r, ?callable $onCardNumber = null): array
    {
        $out = [];
        if ($r->ip !== null && $r->ip !== '' && \strlen($r->ip) <= self::MAX_IP) {
            $out['ip'] = $r->ip;
        }
        $strings = [
            'user_agent' => $r->userAgent,
            'token' => $r->token,
            'path' => $r->path,
            'method' => $r->method,
            'ja4' => $r->ja4,
            'http_protocol' => $r->httpProtocol,
            'tls_group' => $r->tlsGroup,
        ];
        foreach ($strings as $field => $v) {
            if ($v !== null && $v !== '') {
                $out[$field] = self::cut($v, self::LIMITS[$field]);
            }
        }
        if ($r->country !== null && $r->country !== '' && \strlen($r->country) <= self::MAX_COUNTRY) {
            $out['country'] = $r->country;
        }
        $scheme = self::scheme($r->scheme);
        if ($scheme !== null) {
            $out['scheme'] = $scheme;
        }
        if ($r->ipFrom !== null && $r->ipFrom !== '') {
            $out['ip_from'] = $r->ipFrom;
        }
        $headers = self::headers($r->headers);
        if ($headers !== []) {
            $out['headers'] = (object) $headers;
        }
        $order = \array_slice($r->headerOrder, 0, self::MAX_ORDER);
        foreach ($order as $name) {
            if (\strlen($name) > self::MAX_NAME) {
                // The server ignores a list with a name this long: it is no header name.
                $order = [];
                break;
            }
        }
        if ($order !== []) {
            $out['header_order'] = $order;
        }
        if ($r->asn !== null) {
            $out['asn'] = $r->asn;
        }
        if ($r->requireToken) {
            $out['require_token'] = true;
        }
        if ($r->placesPerIdentity !== null && $r->placesPerIdentity > 0) {
            $out['places_per_identity'] = $r->placesPerIdentity;
        }
        if ($r->claims !== null) {
            $c = $r->claims;
            $days = $c->accountAgeDays;
            $out['claims'] = (object) array_filter(
                [
                    'account_age_days' => $days === null ? null : min(self::MAX_ACCOUNT_AGE, max(0, $days)),
                    'known_instrument' => $c->knownInstrument,
                    'device_attested' => $c->deviceAttested,
                    'contact_verified' => $c->contactVerified,
                ],
                static fn(int|bool|null $v): bool => $v !== null && $v !== false,
            );
        }
        try {
            $context = ContextFields::fields($r->context, $onCardNumber ?? static function (): void {});
        } catch (\Throwable) {
            $context = []; // a context that cannot be keyed is left out: the decision goes on
        }
        if ($context !== []) {
            $out['context'] = (object) $context;
        }

        return $out;
    }

    /**
     * The JSON object of $e: its request's fields cut as body() cuts a decision's, then
     * its own, each only when set.
     *
     * @return array<string, mixed>
     */
    public static function event(Event $e): array
    {
        $out = ['kind' => $e->kind];
        if ($e->tsMs !== null) {
            $out['ts_ms'] = $e->tsMs;
        }
        $out += self::body(new DecideRequest(
            ip: $e->ip,
            userAgent: $e->userAgent,
            headers: $e->headers,
            headerOrder: $e->headerOrder,
            token: $e->token,
            path: $e->path,
            method: $e->method,
            ja4: $e->ja4,
            httpProtocol: $e->httpProtocol,
            tlsGroup: $e->tlsGroup,
            country: $e->country,
            asn: $e->asn,
            scheme: $e->scheme,
        ));
        if ($e->status !== null) {
            $out['status'] = $e->status;
        }
        foreach (['request_id' => $e->requestId, 'event_id' => $e->eventId] as $field => $v) {
            if ($v !== null && $v !== '') {
                $out[$field] = $v;
            }
        }

        return $out;
    }

    /**
     * The JSON object of $f.
     *
     * @return array<string, string>
     */
    public static function feedback(Feedback $f): array
    {
        $out = [];
        foreach (['request_id' => $f->requestId, 'token' => $f->token] as $field => $v) {
            if ($v !== null && $v !== '') {
                $out[$field] = $v;
            }
        }
        $out['outcome'] = $f->outcome;

        return $out;
    }

    /**
     * The first MAX_HEADERS names in byte order, as the server keeps them, each name and
     * value cut; on two names alike once cut, the first wins. An empty value goes as none.
     *
     * @param array<array-key, string> $headers
     *
     * @return array<array-key, string>
     */
    private static function headers(array $headers): array
    {
        ksort($headers, \SORT_STRING);
        $out = [];
        foreach ($headers as $name => $value) {
            if ($value === '') {
                continue;
            }
            if (\count($out) === self::MAX_HEADERS) {
                break;
            }
            $cut = self::cut((string) $name, self::MAX_NAME);
            if (!\array_key_exists($cut, $out)) {
                $out[$cut] = self::cut($value, self::MAX_VALUE);
            }
        }

        return $out;
    }
}

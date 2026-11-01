<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** The challenge page: sending a visitor there, and reading what they bring back. */
final class Challenge
{
    /**
     * A token as API v1 writes them: an envelope, base64url without padding, at most 160
     * characters. The tokens of before, with a vN. prefix, are none.
     */
    public const TOKEN_PATTERN = '/^[A-Za-z0-9_-]{1,160}$/D';

    /**
     * A challenge page's address, at most: Korzen's are under two hundred characters, and
     * one past this is no page of Korzen's.
     */
    public const MAX_URL = 2048;

    /**
     * A challenge page's alphabet, visible ASCII: a control character or a line break would
     * split the Location header, and one past ASCII cannot be written in it.
     */
    private const PAGE = '/^[\x21-\x7e]+$/D';

    /**
     * Where to send a visitor whose decision is challenge: the decision's challenge page,
     * told to come back to $returnTo; null when the decision has none, or one that is no
     * http(s) URL with a host, of visible ASCII, within MAX_URL characters (then let the
     * visitor through).
     */
    public static function url(Decision $decision, string $returnTo): ?string
    {
        $page = $decision->challenge?->url;
        if ($page === null || !self::page($page)) {
            return null;
        }

        return $page . '&r=' . rawurlencode($returnTo);
    }

    /**
     * What the challenge page adds to the address it sends the visitor back to: token, the
     * session's fresh token once solved (null when it is not a token); found, whether the
     * address carries kz_token at all; clean, the address without it (and without
     * kz_challenge, which older pages added), the rest of it byte for byte. Null when $url
     * is not an absolute http(s) address.
     *
     * @return array{token: ?string, found: bool, clean: string}|null
     */
    public static function fromChallenge(string $url): ?array
    {
        $u = parse_url($url);
        if ($u === false || !isset($u['host']) || !\in_array(strtolower($u['scheme'] ?? ''), ['http', 'https'], true)) {
            return null;
        }
        $at = explode('#', $url, 2);
        $fragment = $at[1] ?? null;
        $at = explode('?', $at[0], 2);
        $base = $at[0];
        $query = $at[1] ?? null;
        $token = null;
        $found = false;
        $kept = [];
        foreach ($query === null || $query === '' ? [] : explode('&', $query) as $pair) {
            $kv = explode('=', $pair, 2);
            $name = urldecode($kv[0]);
            $value = $kv[1] ?? '';
            if ($name === 'kz_token') {
                $token ??= urldecode($value);
                $found = true;
            } elseif ($name !== 'kz_challenge' && $pair !== '') {
                $kept[] = $pair;
            }
        }
        $clean = $base . ($kept === [] ? '' : '?' . implode('&', $kept)) . ($fragment === null ? '' : '#' . $fragment);

        return [
            'token' => $token !== null && preg_match(self::TOKEN_PATTERN, $token) === 1 ? $token : null,
            'found' => $found,
            'clean' => $clean,
        ];
    }

    /**
     * The answer that sends a visitor to the decision's challenge page, told to come back
     * to $returnTo (without kz_ parameters), with the browser marked: the Location and the
     * Set-Cookie of a 303. Null when the decision has no page or $returnTo is not an
     * absolute http(s) address: then let the visitor through. Use it from an onChallenge
     * hook that sends the visitor itself.
     *
     * @return array{location: string, cookie: string}|null
     */
    public static function redirect(Decision $decision, string $returnTo): ?array
    {
        $back = self::fromChallenge($returnTo);
        $location = $back === null ? null : self::url($decision, $back['clean']);
        if ($back === null || $location === null) {
            return null;
        }

        return ['location' => $location, 'cookie' => Cookies::challenge(secure: self::secure($back['clean']))];
    }

    /**
     * The way back from the challenge page, for a page load whose address carries
     * kz_token: the Set-Cookie lines (the token kept as _kz, but only for a browser this
     * server sent to the page, and the mark cleared) and the address to send it on to,
     * without the token, so it leaves the address bar, the history and the Referer: its
     * path and query alone when $relative (Challenge::local). Null when the address carries
     * none or is not an absolute address.
     *
     * @return array{location: string, cookies: list<string>}|null
     *
     * @internal
     */
    public static function back(string $returnTo, bool $marked, bool $relative = false): ?array
    {
        $back = self::fromChallenge($returnTo);
        if ($back === null || !$back['found']) {
            return null;
        }
        $secure = self::secure($back['clean']);
        $cookies = [];
        if ($marked) {
            if ($back['token'] !== null) {
                $cookies[] = Cookies::token($back['token'], secure: $secure);
            }
            $cookies[] = Cookies::challenge(secure: $secure, clear: true);
        }

        return ['location' => $relative ? self::local($back['clean']) : $back['clean'], 'cookies' => $cookies];
    }

    /**
     * $url's path and query alone, for a Location on the visitor's own origin: the host a
     * request names (X-Forwarded-Host or Host, which a visitor may write) never goes in it.
     * Leading slashes and backslashes are one slash, so it is never read as another host
     * (//evil.example, /\evil.example); escapes stay as they are, a path on the site.
     *
     * @internal
     */
    public static function local(string $url): string
    {
        $u = parse_url($url);
        $path = \is_array($u) ? ($u['path'] ?? '') . (isset($u['query']) ? '?' . $u['query'] : '') : '';

        return '/' . ltrim($path, '/\\');
    }

    /** Whether $url can be a challenge page: an http(s) URL with a host, of visible ASCII, within MAX_URL. */
    private static function page(string $url): bool
    {
        if (\strlen($url) > self::MAX_URL || preg_match(self::PAGE, $url) !== 1) {
            return false;
        }
        $u = parse_url($url);

        return $u !== false && ($u['host'] ?? '') !== ''
            && \in_array(strtolower($u['scheme'] ?? ''), ['http', 'https'], true);
    }

    private static function secure(string $url): bool
    {
        return strncasecmp($url, 'https:', 6) === 0;
    }
}

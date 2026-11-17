<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * What an answer's RateLimit-Policy and RateLimit headers say
 * (draft-ietf-httpapi-ratelimit-headers-11): for your logs, never to wait on.
 */
final readonly class RateLimit
{
    /**
     * One member of a structured-field list (RFC 9651) as the RateLimit headers write them:
     * a string or a token, then ;key=integer parameters.
     */
    private const ITEM = '/^\s*(?:"([^"\\\\]*)"|([A-Za-z*][\w:.*\/-]*))'
        . '((?:\s*;\s*[a-z*][a-z0-9_.*-]*(?:=-?\d{1,15})?)*)\s*$/D';

    /**
     * @param string $policy month, trial (the free trial) or subnet
     * @param int|null $window the policy's window in seconds; null for a calendar month or the trial
     * @param int|null $remaining what was left before the call; null when the answer did not say
     * @param int|null $reset seconds until it resets; null when the answer did not say
     */
    public function __construct(
        public string $policy,
        public int $quota,
        public ?int $window = null,
        public ?int $remaining = null,
        public ?int $reset = null,
    ) {}

    /**
     * Reads an answer's RateLimit-Policy and RateLimit headers into the first policy both
     * name (the policy with its quota, q); null when the answer carries none. A member that
     * does not parse is skipped: a header is a hint for the logs, never a reason to fail.
     */
    public static function parse(?string $policy, ?string $limit): ?self
    {
        $limits = [];
        foreach (self::members($limit ?? '') as [$name, $params]) {
            $limits[$name] ??= $params;
        }
        foreach (self::members($policy ?? '') as [$name, $p]) {
            if (!isset($p['q']) || !isset($limits[$name])) {
                continue;
            }
            $l = $limits[$name];

            return new self($name, $p['q'], $p['w'] ?? null, $l['r'] ?? null, $l['t'] ?? null);
        }

        return null;
    }

    /**
     * The members of a structured-field list, each its name and its integer parameters (a
     * parameter without a value is 1), in order.
     *
     * @return list<array{string, array<string, int>}>
     */
    private static function members(string $v): array
    {
        $out = [];
        foreach (explode(',', $v) as $member) {
            if (preg_match(self::ITEM, $member, $m) !== 1) {
                continue;
            }
            $params = [];
            foreach (\array_slice(explode(';', $m[3]), 1) as $kv) {
                $kv = explode('=', trim($kv), 2);
                $params[$kv[0]] = isset($kv[1]) ? (int) $kv[1] : 1;
            }
            $out[] = [$m[1] . $m[2], $params];
        }

        return $out;
    }
}

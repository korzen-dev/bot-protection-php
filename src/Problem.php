<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** An error answer of API v1 (RFC 9457, application/problem+json). */
final readonly class Problem
{
    /**
     * @param string $code what went wrong: invalid_json, invalid_field, unknown_field,
     *     body_too_large, unauthorized, over_limit, domain_refused, not_found,
     *     method_not_allowed, conflict, rate_limited, over_capacity, deadline, unavailable,
     *     idempotency_key_reused, idempotency_key_in_use or internal
     */
    public function __construct(
        public string $type,
        public string $title,
        public int $status,
        public string $code,
        public string $detail,
        public ?string $requestId,
    ) {}

    /**
     * The problem in an error answer, null when it is none: not application/problem+json,
     * not one JSON object, or without a code (a proxy's page, a body cut short).
     */
    public static function of(Answer $answer): ?self
    {
        if (!str_starts_with(strtolower($answer->header('content-type')), 'application/problem+json')) {
            return null;
        }
        try {
            $p = json_decode($answer->body, true, 16, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($p) || !\is_string($p['code'] ?? null) || $p['code'] === '') {
            return null;
        }
        $s = static fn(string $k): string => \is_string($p[$k] ?? null) ? $p[$k] : '';
        $id = $p['request_id'] ?? null;

        return new self(
            $s('type'),
            $s('title'),
            \is_int($p['status'] ?? null) ? $p['status'] : $answer->status,
            $p['code'],
            $s('detail'),
            \is_string($id) ? $id : null,
        );
    }
}

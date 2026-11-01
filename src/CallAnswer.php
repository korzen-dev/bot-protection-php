<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** What one call ended with, told to the client's onAnswer hook, for your logs. */
final readonly class CallAnswer
{
    /**
     * @param string $route /v1/decide, /v1/events or /v1/feedback
     * @param int $status 0 when no answer came
     * @param string|null $requestId the answer's Korzen-Request-Id: name it when you ask us
     *     about a call
     * @param RateLimit|null $rateLimit null when the answer carried none
     * @param bool $replayed Idempotent-Replayed: the API answered a retry with the first
     *     call's answer
     * @param Problem|null $problem the error answer's body, null when it was none
     * @param \Throwable|null $error what went wrong on the way, null when nothing did
     */
    public function __construct(
        public string $route,
        public int $status = 0,
        public ?string $requestId = null,
        public ?RateLimit $rateLimit = null,
        public bool $replayed = false,
        public ?Problem $problem = null,
        public ?\Throwable $error = null,
    ) {}
}

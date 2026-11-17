<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * Sends first-party mode's forwards (FirstParty): a GET or a POST to Bot Protection's tag,
 * beacon and challenge page. CurlTransport and StreamTransport implement it beside
 * Transport; a Transport of yours implements it too for first-party mode to forward
 * through it, or every forward is a 503 (logged once). Throw on any failure, keep to the
 * deadline, and never follow a redirect: it is the visitor's to follow.
 */
interface ForwardTransport
{
    /**
     * Sends $method (GET or POST, with $body) to $url with $headers and returns the answer,
     * whatever its status, a redirect's included, never followed.
     *
     * @param array<string, string> $headers sent as they are, and only these: the
     *     transport adds none of its own (no Accept, no User-Agent)
     * @param float $deadline when the whole call must be over, as microtime(true)
     * @param int $limit read at most $limit + 1 bytes of the body, so a longer one is seen
     *     as longer and the rest is never read
     */
    public function send(
        string $method,
        string $url,
        #[\SensitiveParameter]
        array $headers,
        string $body,
        float $deadline,
        int $limit,
    ): Answer;
}

<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * Sends the client's calls (decide, events, feedback). CurlTransport is the default with
 * ext-curl, StreamTransport without it; give the Client your own to send it through
 * another HTTP client, or a fake in your tests. Throw on any failure: decide()
 * turns every exception into no decision. Keep to the deadline, name lookup included:
 * PHP cannot cut a call short, so an answer that comes after it is taken for none (no
 * decision, nothing recorded), but the visitor has waited for it. The headers hold the API key: mark them
 * #[\SensitiveParameter] in your own post(), as here, so a stack trace never shows it.
 */
interface Transport
{
    /**
     * POSTs $body to $url with $headers and returns the answer, its status, headers and
     * body whatever the status (a problem comes with an error status), without following a
     * redirect: Bot Protection answers its routes itself, so a redirect is no decision, and
     * following it would send the key and the visitor's request to another server.
     *
     * @param array<string, string> $headers
     * @param float $deadline when the whole call must be over, as microtime(true)
     * @param int $limit read at most $limit + 1 bytes of the body, so a longer one is seen
     *     as longer and the rest is never read
     */
    public function post(
        string $url,
        #[\SensitiveParameter]
        array $headers,
        string $body,
        float $deadline,
        int $limit,
    ): Answer;
}

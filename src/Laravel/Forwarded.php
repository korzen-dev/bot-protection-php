<?php

declare(strict_types=1);

namespace Korzen\BotProtection\Laravel;

use Symfony\Component\HttpFoundation\Response;

/**
 * First-party mode's answer, its headers sent as Korzen wrote them: Symfony's own rewrites
 * a Cache-Control (public, max-age=300 as max-age=300, public; no-store as no-store,
 * private), and Laravel's prepare() adds a Content-Type to an answer Korzen sent without
 * one, which goes back without one.
 *
 * @internal
 */
final class Forwarded extends Response
{
    /** @param list<array{string, string}> $raw the headers, name and value, in order */
    public function __construct(string $body, int $status, private readonly array $raw)
    {
        parent::__construct($body, $status);
        foreach ($raw as [$name, $value]) {
            $this->headers->set($name, $value);
        }
    }

    public function sendHeaders(?int $statusCode = null): static
    {
        // Once output has begun no header can be sent, Symfony's nor these.
        if (!headers_sent()) {
            parent::sendHeaders($statusCode);
            $this->rewrite();
        }

        return $this;
    }

    /** Sends the headers again as Korzen wrote them, and none of PHP's Content-Type where Korzen sent none. */
    private function rewrite(): void
    {
        $typed = false;
        foreach ($this->raw as [$name, $value]) {
            header($name . ': ' . $value);
            $typed = $typed || strcasecmp($name, 'Content-Type') === 0;
        }
        if (!$typed) {
            header_remove('Content-Type');
            // PHP adds its default_mimetype to an answer that names none.
            ini_set('default_mimetype', '');
        }
    }
}

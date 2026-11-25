<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * What a middleware does with a request, the same in every framework: answer it itself
 * ($status set), hand it to onBlock ($hook), or let it through to the handler with the
 * decision, or none.
 *
 * @internal
 */
final readonly class Outcome
{
    /**
     * @param list<array{string, string}> $headers name and value, in order
     * @param bool $hook whether onBlock answers it
     */
    private function __construct(
        public ?Decision $decision,
        public ?int $status = null,
        public array $headers = [],
        public string $body = '',
        public bool $hook = false,
        public bool $forwarded = false,
    ) {}

    /**
     * First-party mode's answer (FirstParty): Korzen's, or the forwarder's own refusal,
     * its headers sent as they are, and none added: an answer without a Content-Type goes
     * back without one.
     *
     * @param list<array{string, string}> $headers
     */
    public static function forwarded(int $status, array $headers, string $body): self
    {
        return new self(null, $status, $headers, $body, forwarded: true);
    }

    /** Whether the answer names its Content-Type. */
    public function typed(): bool
    {
        foreach ($this->headers as [$name]) {
            if (strcasecmp($name, 'Content-Type') === 0) {
                return true;
            }
        }

        return false;
    }

    public static function pass(?Decision $decision): self
    {
        return new self($decision);
    }

    public static function hook(Decision $decision): self
    {
        return new self($decision, hook: true);
    }

    public static function forbidden(Decision $decision): self
    {
        return new self($decision, 403, [['Content-Type', 'text/plain; charset=utf-8']], 'Forbidden');
    }
}

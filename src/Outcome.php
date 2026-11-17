<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * What a middleware does with a request, the same in every framework: answer it itself
 * ($status set), hand it to a hook ($hook set), or let it through to the handler with the
 * decision, or none. A decoy's hook comes with what to do when it answers nothing
 * ($otherwise).
 *
 * @internal
 */
final readonly class Outcome
{
    /**
     * @param list<array{string, string}> $headers name and value, in order
     * @param 'block'|'challenge'|'decoy'|null $hook
     */
    private function __construct(
        public ?Decision $decision,
        public ?int $status = null,
        public array $headers = [],
        public string $body = '',
        public ?string $hook = null,
        public ?self $otherwise = null,
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

    /** @param 'block'|'challenge' $hook */
    public static function hook(Decision $decision, string $hook): self
    {
        return new self($decision, hook: $hook);
    }

    /** The decoy's hook first; $otherwise when it answers nothing. */
    public static function decoy(Decision $decision, self $otherwise): self
    {
        return new self($decision, hook: 'decoy', otherwise: $otherwise);
    }

    /**
     * The default decoy (contract.json's decide.decoy_default): an action refused with a
     * decoy and no onDecoy is answered 202 with {} as JSON, with no header of Korzen's.
     */
    public static function accepted(Decision $decision): self
    {
        return new self($decision, 202, [['Content-Type', 'application/json']], '{}');
    }

    public static function forbidden(Decision $decision): self
    {
        return new self($decision, 403, [['Content-Type', 'text/plain; charset=utf-8']], 'Forbidden');
    }

    /** @param list<string> $cookies Set-Cookie lines */
    public static function seeOther(?Decision $decision, string $location, array $cookies): self
    {
        $headers = [['Location', $location]];
        foreach ($cookies as $cookie) {
            $headers[] = ['Set-Cookie', $cookie];
        }

        return new self($decision, 303, $headers);
    }
}

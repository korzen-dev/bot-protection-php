<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * An answer to a call, as a Transport returns it: its status, its body (or as much of it as
 * was read) and its headers, by lower-cased name, a repeated one joined with ", ".
 */
final readonly class Answer
{
    /** @param array<string, string> $headers */
    public function __construct(
        public int $status,
        public string $body = '',
        public array $headers = [],
    ) {}

    /** The header's value, '' when absent. */
    public function header(string $name): string
    {
        return $this->headers[strtolower($name)] ?? '';
    }
}

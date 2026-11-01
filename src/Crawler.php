<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** A declared crawler its vendor's published addresses verified. */
final readonly class Crawler
{
    /**
     * @param string $name such as GPTBot, ClaudeBot, Googlebot
     * @param string $kind search, assistant, scrape, seo, preview, uptime or scan: what you
     *     let through or block, by kind, in Set-up
     */
    public function __construct(
        public string $name,
        public string $kind,
    ) {}
}

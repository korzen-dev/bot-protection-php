<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** One item of a batch rejected: its place from 0, and why. */
final readonly class ItemError
{
    /**
     * @param string $code too_old, too_far_ahead, seconds_not_ms, forged, no_session,
     *     deadline, unavailable or internal
     */
    public function __construct(
        public int $index,
        public string $code,
        public string $detail,
    ) {}
}

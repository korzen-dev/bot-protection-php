<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** A decision's challenge. */
final readonly class ChallengePage
{
    /**
     * @param string|null $url the challenge page for this visitor, null unless the action is
     *     challenge: send the visitor there with Challenge::url($decision, $returnTo)
     * @param bool $passed the session solved a challenge in the last 30 minutes, so its
     *     challenge is allow
     */
    public function __construct(
        public ?string $url = null,
        public bool $passed = false,
    ) {}
}

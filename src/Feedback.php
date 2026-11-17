<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * What you learned later about a session (POST /v1/feedback): name it by exactly one of
 * $requestId and $token.
 */
final readonly class Feedback
{
    /** @param string $outcome verified_human, good_customer, chargeback or fraud */
    public function __construct(
        public string $outcome,
        public ?string $requestId = null,
        #[\SensitiveParameter]
        public ?string $token = null,
    ) {}
}

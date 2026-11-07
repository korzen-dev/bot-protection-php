<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * What your server checked itself about the account; a null or false field is left out. An
 * accountAgeDays below 0, as clock skew gives, goes as 0, and one past 4294967295 goes as
 * that: the API answers either with a 400, which would skip protection for that request. A
 * 0 is sent, and the API reads it as none.
 */
final readonly class Claims
{
    public function __construct(
        public ?int $accountAgeDays = null,
        public bool $knownInstrument = false,
        public bool $deviceAttested = false,
        public bool $contactVerified = false,
    ) {}
}

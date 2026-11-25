<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * The decision a middleware has seen so far, kept for the handler when a step after it
 * fails: the visitor goes through with the decision the API answered.
 *
 * @internal
 */
final class Seen
{
    public ?Decision $decision = null;
}

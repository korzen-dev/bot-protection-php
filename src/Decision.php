<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** POST /v1/decide's answer, on API v1. Apply $action alone; the rest is for your logs. */
final readonly class Decision
{
    public const ALLOW = 'allow';
    public const BLOCK = 'block';

    /** The actions the API documents: only they are a decision. */
    public const ACTIONS = [self::ALLOW, self::BLOCK];

    /**
     * @param string $requestId names the decision, at most 96 characters: keep it with an
     *     order; the dashboard finds the decision by it
     * @param string $class the class the bot engine judged: human, unknown or bot; '' when
     *     something before it decided, or while the protection is paused
     * @param int $botScore 0 to 100: 0 when $class is ''
     * @param string $mode monitor, block, or paused (you paused the protection, and the
     *     action is allow)
     * @param bool $tokenRequired the request was a protected action, and no valid token for
     *     the action, or one this session already used on it. In block mode the action is
     *     then block; in monitor mode it stays allow. The class is what it was. False while
     *     the protection is paused.
     * @param string $decidedBy what decided, in this order: your choice for a verified
     *     known bot (known_bots), else the first custom rule that allows or blocks
     *     (custom_rules), else the bot engine (bot_engine); '' while the protection is paused
     */
    public function __construct(
        public string $action,
        public string $requestId = '',
        public string $class = '',
        public int $botScore = 0,
        public string $mode = '',
        public bool $tokenRequired = false,
        public string $decidedBy = '',
    ) {}

    /**
     * The decision in an answer's body; null unless it is one JSON object (whitespace
     * around it aside) whose action is allow or block and whose fields have the types the
     * API documents; any other member is read past. An empty or unknown action (a newer
     * API's, a proxy's, an older API's challenge) is no decision, as a customer reading
     * action !== 'allow' would otherwise block on it.
     */
    public static function fromJson(string $json): ?self
    {
        try {
            $d = self::decode($json);
        } catch (\JsonException) {
            return null;
        }
        // A JSON array decodes to a list, which has no action either.
        if (!\is_array($d)) {
            return null;
        }
        $action = $d['action'] ?? null;
        if (!\in_array($action, self::ACTIONS, true)) {
            return null;
        }
        try {
            return new self(
                action: $action,
                requestId: self::string($d, 'request_id'),
                class: self::string($d, 'class'),
                botScore: self::int($d, 'bot_score'),
                mode: self::string($d, 'mode'),
                tokenRequired: self::bool($d, 'token_required'),
                decidedBy: self::string($d, 'decided_by'),
            );
        } catch (\UnexpectedValueException) {
            // A field without the type the API documents: no decision.
            return null;
        }
    }

    /**
     * The field named, '' when absent or null.
     *
     * @param array<mixed> $d
     *
     * @throws \UnexpectedValueException when it is not a string
     */
    private static function string(array $d, string $key): string
    {
        $v = $d[$key] ?? '';

        // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- a message, never written to a page.
        return \is_string($v) ? $v : throw new \UnexpectedValueException($key);
    }

    /**
     * The field named, 0 when absent or null.
     *
     * @param array<mixed> $d
     *
     * @throws \UnexpectedValueException when it is not an integer
     */
    private static function int(array $d, string $key): int
    {
        $v = $d[$key] ?? 0;

        // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- a message, never written to a page.
        return \is_int($v) ? $v : throw new \UnexpectedValueException($key);
    }

    /**
     * The field named, false when absent or null.
     *
     * @param array<mixed> $d
     *
     * @throws \UnexpectedValueException when it is not a boolean
     */
    private static function bool(array $d, string $key): bool
    {
        $v = $d[$key] ?? false;

        // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- a message, never written to a page.
        return \is_bool($v) ? $v : throw new \UnexpectedValueException($key);
    }

    /**
     * $json decoded. A lone surrogate escape (\ud800) is JSON's grammar but no character,
     * and PHP refuses the whole text for it, where the other SDKs keep the decision: on
     * that error alone, each is read as U+FFFD, the replacement character, and the text
     * decoded again.
     *
     * @throws \JsonException
     */
    private static function decode(string $json): mixed
    {
        try {
            return json_decode($json, true, 16, \JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            if ($e->getCode() !== \JSON_ERROR_UTF16) {
                throw $e;
            }
        }
        // Left to right: an escaped backslash is passed over, a surrogate pair kept, and a
        // surrogate alone replaced.
        $json = preg_replace_callback(
            '/\\\\(?:\\\\|u[dD][89abAB][0-9a-fA-F]{2}\\\\u[dD][c-fC-F][0-9a-fA-F]{2}|u[dD][89a-fA-F][0-9a-fA-F]{2})/',
            static fn(array $m): string => \strlen($m[0]) === 6 && $m[0][1] === 'u' ? '\\ufffd' : $m[0],
            $json,
        );

        return json_decode($json ?? '', true, 16, \JSON_THROW_ON_ERROR);
    }
}

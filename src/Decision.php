<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** POST /v1/decide's answer, on API v1. Apply $action alone; the rest is for your logs. */
final readonly class Decision
{
    public const ALLOW = 'allow';
    public const CHALLENGE = 'challenge';
    public const BLOCK = 'block';

    /** The actions the API documents: only they are a decision. */
    public const ACTIONS = [self::ALLOW, self::CHALLENGE, self::BLOCK];

    /**
     * @param string $requestId names the decision, at most 96 characters: keep it with an
     *     order to send feedback by it later
     * @param string $class human_high, human, unknown, bot or bot_high
     * @param string $mode monitor, block, or paused (you paused the protection, and the
     *     action is allow)
     * @param ChallengePage|null $challenge its page when the action is challenge, and
     *     whether the session solved it in the last 30 minutes; null when the decision is
     *     no challenge
     * @param bool $tokenRequired the request had require_token, and no valid token for
     *     the action, or one this session already used on it. In block mode the action is
     *     then challenge, or allow when the challenge cannot be issued (fail-open); in
     *     monitor mode the action stays allow. A block stays a block, and the class is
     *     what it was. False while the protection is paused.
     * @param bool $decoy answer this refusal with your decoy, not a refusal the visitor
     *     can see. True only when you turned the decoy on for this class (bot, bot_high)
     *     on the Set-up page, the action is block or challenge, and what the visitor
     *     itself showed is enough for bot or bot_high, leaving out what Bot Protection
     *     learned from your traffic as a whole and any absent signal. Never for a
     *     verified crawler, tokenRequired, an identity past its places, a session that
     *     passed the challenge page in the last 30 minutes or could not be checked for
     *     it, nor in monitor or paused mode. False otherwise, and when the API leaves it
     *     out.
     */
    public function __construct(
        public string $action,
        public string $requestId = '',
        public string $class = '',
        public int $botScore = 0,
        public string $mode = '',
        public ?ChallengePage $challenge = null,
        public bool $tokenRequired = false,
        public bool $decoy = false,
    ) {}

    /**
     * The decision in an answer's body; null unless it is one JSON object (whitespace
     * around it aside) whose action is allow, challenge or block and whose fields have the
     * types the API documents; any other member is read past. An empty or unknown action
     * (a newer API's, a proxy's) is no decision, as a customer reading action !== 'allow'
     * would otherwise block on it.
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
                challenge: self::challenge($d['challenge'] ?? null),
                tokenRequired: self::bool($d, 'token_required'),
                decoy: self::bool($d, 'decoy'),
            );
        } catch (\UnexpectedValueException) {
            // A field without the type the API documents: no decision.
            return null;
        }
    }

    /**
     * The challenge object; null for none.
     *
     * @throws \UnexpectedValueException when it does not have the documented types
     */
    private static function challenge(mixed $v): ?ChallengePage
    {
        if ($v === null) {
            return null;
        }
        // {} decodes to [], a list: an empty object is a challenge without a page.
        if (!\is_array($v) || ($v !== [] && array_is_list($v))) {
            throw new \UnexpectedValueException('not an object');
        }
        $url = $v['url'] ?? null;
        $passed = $v['passed'] ?? false;
        if (($url !== null && !\is_string($url)) || !\is_bool($passed)) {
            throw new \UnexpectedValueException('not a challenge');
        }

        return new ChallengePage($url, $passed);
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

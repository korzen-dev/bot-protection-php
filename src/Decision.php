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
     * @param list<string> $reasons the kinds of evidence behind the class (behaviour,
     *     inconsistency, environment, missing_signals, history), never the rules
     * @param list<string> $rules the rules that fired, by name, only when Korzen turned
     *     rule names on for your tenant; empty otherwise, never null (a list is [] in API v1)
     * @param string $mode monitor, block, or paused (you paused the protection, and the
     *     action is allow)
     * @param ChallengePage|null $challenge when the intended action is challenge: its page
     *     when the action is challenge, and whether the session solved it in the last 30
     *     minutes; null otherwise
     * @param bool $tokenRequired the request had require_token, and no valid token for the
     *     action, or one this session already used on it: the action is then challenge
     *     (block stays block)
     * @param int $seenBefore how many earlier sessions brought this browser to this path in
     *     the last 90 days, by the tag's device id; 0 when none, without the tag, or on a page view
     * @param Crawler|null $crawler a declared crawler from its vendor's published addresses
     *     (GPTBot, ClaudeBot, Googlebot) and its kind: still a bot, one you may let through
     *     if you invite it; null otherwise
     * @param bool $decoy true only on block or challenge: Korzen would rather the visitor
     *     met a decoy of yours (a page that looks like success) than the refusal, so it
     *     learns nothing to retry against; false otherwise, and when the API leaves it out
     * @param bool $identityLimited the request had require_token and the context's
     *     identityId, and the identity holds its placesPerIdentity on this path already,
     *     none of them this session's: the action is then challenge (block stays block), no
     *     challenge page is offered, and the class is what it was. Tell the person the
     *     identity holds its places.
     */
    public function __construct(
        public string $action,
        public string $requestId = '',
        public string $class = '',
        public int $botScore = 0,
        public int $humanScore = 0,
        public array $reasons = [],
        public array $rules = [],
        public bool $stepUp = false,
        public string $intendedAction = '',
        public string $mode = '',
        public ?ChallengePage $challenge = null,
        public bool $tokenRequired = false,
        public int $seenBefore = 0,
        public ?Crawler $crawler = null,
        public bool $decoy = false,
        public bool $identityLimited = false,
    ) {}

    /**
     * The decision in an answer's body; null unless it is one JSON object (whitespace
     * around it aside) whose action is allow, challenge or block and whose fields have the
     * types the API documents. An empty or unknown action (a newer API's, a proxy's) is no
     * decision, as a customer reading action !== 'allow' would otherwise block on it.
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
                humanScore: self::int($d, 'human_score'),
                reasons: self::list($d['reasons'] ?? []),
                rules: self::list($d['rules'] ?? []),
                stepUp: self::bool($d, 'step_up'),
                intendedAction: self::string($d, 'intended_action'),
                mode: self::string($d, 'mode'),
                challenge: self::challenge($d['challenge'] ?? null),
                tokenRequired: self::bool($d, 'token_required'),
                seenBefore: self::int($d, 'seen_before'),
                crawler: self::crawler($d['crawler'] ?? null),
                decoy: self::bool($d, 'decoy'),
                identityLimited: self::bool($d, 'identity_limited'),
            );
        } catch (\UnexpectedValueException) {
            // A field without the type the API documents: no decision.
            return null;
        }
    }

    /**
     * $v as a list of strings.
     *
     * @return list<string>
     *
     * @throws \UnexpectedValueException when it is not one
     */
    private static function list(mixed $v): array
    {
        if (!\is_array($v) || !array_is_list($v)) {
            throw new \UnexpectedValueException('not a list');
        }
        $out = [];
        foreach ($v as $item) {
            $out[] = \is_string($item) ? $item : throw new \UnexpectedValueException('not a string');
        }

        return $out;
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
     * The crawler object; null for none.
     *
     * @throws \UnexpectedValueException when it does not have the documented types
     */
    private static function crawler(mixed $v): ?Crawler
    {
        if ($v === null) {
            return null;
        }
        $name = \is_array($v) && !array_is_list($v) ? $v['name'] ?? null : null;
        $kind = \is_array($v) ? $v['kind'] ?? '' : null;
        if (!\is_string($name) || !\is_string($kind)) {
            throw new \UnexpectedValueException('not a crawler');
        }

        return new Crawler($name, $kind);
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

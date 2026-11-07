<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * Calls Korzen Bot Protection's API v1: asks about a request before a protected action
 * (POST /v1/decide), and reports events and feedback after it (POST /v1/events and
 * /v1/feedback). It fails open: when Bot Protection is slow, down, refuses the key or
 * answers anything but a decision, decide() returns null and the visitor goes through.
 * One client is enough for a process; PHP shares nothing between requests, so it holds no
 * state but the warnings it gives once and the answers waiting for onAnswer.
 */
final class Client
{
    /** This SDK's version, kept with composer.json's by release-please. */
    public const VERSION = '2.0.1'; // x-release-please-version

    /**
     * The integration every call names in its Korzen-Sdk header, unless the client is given
     * another: what Bot Protection learns of the headers your server forwards is learned per
     * integration, and an upgrade learns it again.
     */
    public const SDK = 'php/' . self::VERSION;

    public const DEFAULT_URL = 'https://korzen.dev';
    public const DEFAULT_TIMEOUT_MS = 200;
    /** Bounds a batch of events or feedback, its retries included: it is no visitor's wait. */
    public const DEFAULT_BATCH_TIMEOUT_MS = 5000;
    /** How many times a batch is sent again under its Idempotency-Key. */
    public const DEFAULT_RETRIES = 2;
    /** The first retry's wait, doubled each time, when the answer gives no Retry-After. */
    public const DEFAULT_RETRY_DELAY_MS = 200;

    /**
     * How many times a retry's wait doubles at most: the first wait times 2^30 is past any
     * batch's time, and the shift never overflows, which would send the retries at once.
     */
    private const MAX_SHIFT = 30;

    /** Where the docs say how to read the visitor's IP behind a proxy. */
    public const IP_HELP = 'https://korzen.dev/bot-protection/docs/server-call#visitor-ip';

    /**
     * What the client reads of an answer, in bytes: a decision is a few hundred, and an
     * endless body is cut there instead of filling the server's memory until the timeout.
     */
    public const MAX_ANSWER = 1 << 20;

    /** An integration the API reads: a name of 1 to 32 of [a-z0-9-], a version of 1 to 32 of [A-Za-z0-9.+-]. */
    private const INTEGRATION = '/^[a-z0-9-]{1,32}\/[A-Za-z0-9.+-]{1,32}$/D';

    /** A key the API takes: 1 to 255 visible ASCII characters. */
    private const IDEMPOTENCY_KEY = '/^[\x21-\x7e]{1,255}$/D';

    /** What is trimmed around a key: spaces and line breaks, as a copy and paste leaves them. */
    private const SPACE = " \t\n\r\v\f";

    /** The longest timeoutMs the API takes as Korzen-Deadline-Ms: a longer one is DEFAULT_TIMEOUT_MS. */
    public const MAX_TIMEOUT_MS = 1000;

    /** The key every call sends, trimmed of the spaces and line breaks around it. */
    private readonly string $apiKey;

    /**
     * How many answers wait for onAnswer at once: one past them is not told (logged once),
     * so a process that never ends a request, a worker of RoadRunner, Swoole or FrankenPHP
     * that never calls flush(), holds no more.
     */
    public const MAX_HOOKS = 64;

    private readonly string $base;
    private readonly int $timeoutMs;
    private readonly int $batchTimeoutMs;
    private readonly int $retries;
    private readonly int $retryDelayMs;
    private readonly Transport $transport;
    /** @var \Closure(string): void */
    private readonly \Closure $logger;
    /** @var (\Closure(CallAnswer): mixed)|null */
    private readonly ?\Closure $onAnswer;
    private bool $warned = false;
    private bool $warnedCard = false;
    private bool $warnedHook = false;
    private bool $warnedHooks = false;
    private bool $warnedFault = false;
    /** @var array<string, true> the topics logged once already (warnOnceAbout) */
    private array $told = [];
    /** Whether flush() is set to run when the request ends: once for the client. */
    private bool $atShutdown = false;
    /** @var list<CallAnswer> the answers onAnswer is yet to be told of, oldest first */
    private array $pending = [];
    /** The Korzen-Sdk every call carries; null sends none. */
    private readonly ?string $sdk;

    /**
     * The settings are read here, once: each that does not read is logged once and left at
     * its default, and none ever makes a call throw.
     *
     * @param string $apiKey the key from the dashboard, sent as a Bearer token; the spaces
     *     and line breaks around it are taken out, and an empty one is logged (Bot
     *     Protection refuses every call, and every visitor goes through)
     * @param string $url Bot Protection's address; /v1/decide, /v1/events and /v1/feedback
     *     are added to it. An https URL, or http on loopback (localhost, 127.0.0.0/8, [::1])
     *     for a test on your machine: any other (http elsewhere would send the key in
     *     clear) is logged and DEFAULT_URL is called; DEFAULT_URL when ''
     * @param int $timeoutMs bounds the whole call to /v1/decide: connecting, sending and
     *     reading the answer. More than 0 and at most MAX_TIMEOUT_MS; any other is logged
     *     and DEFAULT_TIMEOUT_MS. It is sent as Korzen-Deadline-Ms: the decision takes half,
     *     the network the other half.
     * @param Transport|null $transport sends the call; CurlTransport when ext-curl is
     *     loaded, else PHP's stream wrapper
     * @param (callable(string): void)|null $logger told once of each setting that does not
     *     read, once the first time a decision's IP is on your own network (behind a load
     *     balancer the connection's address is the balancer's), and once the first time a
     *     context's card_bin may be a card number; never the key. error_log when null. A
     *     PSR-3 logger fits as fn (string $m) => $log->warning($m).
     * @param (callable(CallAnswer): mixed)|null $onAnswer told of each call's answer, for your
     *     logs: its status, Korzen-Request-Id, RateLimit headers and problem. PHP cannot bound
     *     a function it calls, so it is told after the call, when the request ends (a
     *     shutdown function) or at flush(): a slow one costs no decision, and what it throws
     *     is logged once and costs nothing. At most MAX_HOOKS answers wait for it.
     * @param int $batchTimeoutMs bounds events() and feedback(), retries included; more
     *     than 0, else logged and DEFAULT_BATCH_TIMEOUT_MS
     * @param int|null $retries how many times events() and feedback() are sent again, under
     *     the same Idempotency-Key, on no answer, a 409, a 429 or a 5xx: none when 0,
     *     DEFAULT_RETRIES when null; one below 0 is logged and DEFAULT_RETRIES
     * @param int $retryDelayMs the first retry's wait, doubled each time, when the answer
     *     gives no Retry-After; more than 0, else logged and DEFAULT_RETRY_DELAY_MS
     * @param string|null $sdk the integration every call names in Korzen-Sdk, as name/version:
     *     SDK when null. A plugin built on this SDK names itself (wordpress/1.0.0); one that
     *     is no name/version is not sent, as Bot Protection would read it as none.
     */
    public function __construct(
        #[\SensitiveParameter]
        string $apiKey,
        string $url = self::DEFAULT_URL,
        int $timeoutMs = self::DEFAULT_TIMEOUT_MS,
        ?Transport $transport = null,
        ?callable $logger = null,
        ?callable $onAnswer = null,
        int $batchTimeoutMs = self::DEFAULT_BATCH_TIMEOUT_MS,
        ?int $retries = null,
        int $retryDelayMs = self::DEFAULT_RETRY_DELAY_MS,
        ?string $sdk = null,
    ) {
        $this->logger = $logger === null
            ? static function (string $message): void {
                error_log($message);
            }
        : \Closure::fromCallable($logger);
        $this->apiKey = trim($apiKey, self::SPACE);
        if ($this->apiKey === '') {
            $this->log(
                'korzen: apiKey is empty: Bot Protection refuses every call, and every visitor goes on unjudged',
            );
        } elseif ($this->apiKey !== $apiKey) {
            $this->log('korzen: apiKey had spaces or a line break around it: they were taken out');
        }
        $base = $url === '' ? self::DEFAULT_URL : Bounds::apiUrl($url);
        if ($base === null) {
            $this->log(
                'korzen: url must be an https URL (http only on loopback): ' . self::DEFAULT_URL . ' it is',
            );
        }
        $this->base = $base ?? self::DEFAULT_URL;
        $this->timeoutMs = $this->setting(
            $timeoutMs > 0 && $timeoutMs <= self::MAX_TIMEOUT_MS,
            $timeoutMs,
            self::DEFAULT_TIMEOUT_MS,
            'timeoutMs must be more than 0 and at most ' . self::MAX_TIMEOUT_MS . ' ms',
        );
        $this->batchTimeoutMs = $this->setting(
            $batchTimeoutMs > 0,
            $batchTimeoutMs,
            self::DEFAULT_BATCH_TIMEOUT_MS,
            'batchTimeoutMs must be more than 0 ms',
        );
        $this->retries = $retries === null ? self::DEFAULT_RETRIES : $this->setting(
            $retries >= 0,
            $retries,
            self::DEFAULT_RETRIES,
            'retries must be a whole number from 0',
        );
        $this->retryDelayMs = $this->setting(
            $retryDelayMs > 0,
            $retryDelayMs,
            self::DEFAULT_RETRY_DELAY_MS,
            'retryDelayMs must be more than 0 ms',
        );
        $sdk ??= self::SDK;
        $this->sdk = preg_match(self::INTEGRATION, $sdk) === 1 ? $sdk : null;
        $this->transport = $transport ?? (CurlTransport::available() ? new CurlTransport() : new StreamTransport());
        $this->onAnswer = $onAnswer === null ? null : \Closure::fromCallable($onAnswer);
    }

    /**
     * The decision on $request, or null when there is none: on any error, a timeout, a
     * status other than 200 (a problem, when the API answered one, goes to onAnswer), a
     * redirect (never followed), an answer past MAX_ANSWER, or an answer that is not one
     * JSON object whose action is allow, challenge or block. It never throws: the caller
     * lets the visitor through on null.
     */
    public function decide(DecideRequest $request): ?Decision
    {
        try {
            $this->warnOwnNetwork($request->ip);
            $ms = $this->timeoutMs;
            $answer = $this->post(
                '/v1/decide',
                ['Korzen-Deadline-Ms' => (string) $ms],
                (object) Bounds::body($request, $this->warnCardNumber(...)),
                microtime(true) + $ms / 1000,
            );

            return $answer?->status === 200 ? Decision::fromJson($answer->body) : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Reports 1 to 1000 events. It returns the batch's answer, or null when nothing was
     * recorded (an error, the protection paused, the batch timeout past). The call carries
     * an Idempotency-Key, $idempotencyKey or a fresh UUID v7, and is sent again under it,
     * up to the retries within the batch timeout, when it got no answer or a 409, 429 or
     * 5xx: a retry the API already answered gets the same answer, recorded once. Give your
     * own key (an order's id) to make a call you send again later safe too. It never throws.
     *
     * @param list<Event> $events
     */
    public function events(array $events, ?string $idempotencyKey = null): ?BatchAnswer
    {
        try {
            return $this->batch('/v1/events', ['events' => array_map(Bounds::event(...), $events)], $idempotencyKey);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Sends 1 to 1000 pieces of feedback, as events() sends events.
     *
     * @param list<Feedback> $items
     */
    public function feedback(array $items, ?string $idempotencyKey = null): ?BatchAnswer
    {
        try {
            return $this->batch(
                '/v1/feedback',
                ['feedback' => array_map(Bounds::feedback(...), $items)],
                $idempotencyKey,
            );
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * A UUID v7 (RFC 9562): the time in milliseconds, then 74 random bits. Each batch gets
     * one as its Idempotency-Key, kept across its retries.
     */
    public static function uuidV7(?float $now = null): string
    {
        $ms = (int) floor(($now ?? microtime(true)) * 1000);
        $b = substr(pack('J', $ms), 2, 6) . random_bytes(10);
        $b[6] = \chr((\ord($b[6]) & 0x0F) | 0x70);
        $b[8] = \chr((\ord($b[8]) & 0x3F) | 0x80);
        $h = bin2hex($b);

        return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4) . '-'
            . substr($h, 16, 4) . '-' . substr($h, 20);
    }

    /**
     * What var_dump() and print_r() show of the client: its fields, the API key as
     * [redacted], so a dump in a log or an error page never holds it.
     *
     * @return array<mixed>
     */
    public function __debugInfo(): array
    {
        return ['apiKey' => '[redacted]'] + get_object_vars($this);
    }

    /**
     * Posts one batch under its key, with its retries.
     *
     * @param array<string, list<array<string, mixed>>> $body
     */
    private function batch(string $route, array $body, ?string $key): ?BatchAnswer
    {
        $key ??= self::uuidV7();
        if (preg_match(self::IDEMPOTENCY_KEY, $key) !== 1) {
            $this->tell(new CallAnswer(
                $route,
                error: new \InvalidArgumentException(
                    'korzen: an Idempotency-Key must be 1 to 255 visible ASCII characters',
                ),
            ));

            return null;
        }
        $deadline = microtime(true) + $this->batchTimeoutMs / 1000;
        $delay = $this->retryDelayMs / 1000;
        $retries = $this->retries;
        for ($attempt = 0; ; ++$attempt) {
            $answer = $this->post($route, ['Idempotency-Key' => $key], $body, $deadline);
            $status = $answer->status ?? 0;
            if ($status === 200) {
                // A 200 whose body is no batch's answer is final too: sent again, it would be the same.
                return BatchAnswer::fromJson($answer->body ?? '');
            }
            // Final: a 204 (the protection paused, the batch dropped), and any status but a 409, 429 or 5xx.
            if ($status !== 0 && $status !== 409 && $status !== 429 && $status < 500) {
                return null;
            }
            $wait = self::retryAfter($answer) ?? self::backoff($delay, $attempt);
            // A wait past the batch's time left ends it now: nothing is recorded either way.
            if ($attempt >= $retries || microtime(true) + $wait > $deadline) {
                return null;
            }
            usleep((int) ($wait * 1e6));
        }
    }

    /**
     * The wait before retry $attempt + 1 when the answer gives no Retry-After: $delay
     * doubled $attempt times, MAX_SHIFT at most. Past the batch's time left, it ends the
     * retries.
     */
    private static function backoff(float $delay, int $attempt): float
    {
        return $delay * (1 << max(0, min($attempt, self::MAX_SHIFT)));
    }

    /** The answer's Retry-After, in seconds; null when it gives none it can read. */
    private static function retryAfter(?Answer $answer): ?float
    {
        $v = $answer?->header('retry-after') ?? '';
        if (preg_match('/^\d{1,7}$/D', $v) !== 1 || (int) $v >= 1 << 20) {
            return null;
        }

        return (float) $v;
    }

    /**
     * Sends $body to $route with $headers before $deadline and tells onAnswer how it went.
     * The answer, or null when none came; a body past MAX_ANSWER is cut to nothing, so it
     * is no decision and no batch's answer.
     *
     * @param array<string, string> $headers
     * @param object|array<string, mixed> $body
     */
    private function post(
        string $route,
        #[\SensitiveParameter]
        array $headers,
        object|array $body,
        float $deadline,
    ): ?Answer {
        // A key that would split the Authorization header is no key: nothing is sent.
        if (preg_match('/[\x00-\x08\x0a-\x1f\x7f]/', $this->apiKey) === 1) {
            $this->tell(new CallAnswer(
                $route,
                error: new \InvalidArgumentException('korzen: the API key holds a control character'),
            ));

            return null;
        }
        try {
            $json = json_encode(
                $body,
                \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_INVALID_UTF8_SUBSTITUTE
                    | \JSON_THROW_ON_ERROR,
            );
            $answer = $this->transport->post(
                $this->base . $route,
                $headers + ['Authorization' => 'Bearer ' . $this->apiKey, 'Content-Type' => 'application/json']
                    + ($this->sdk === null ? [] : ['Korzen-Sdk' => $this->sdk]),
                $json,
                $deadline,
                self::MAX_ANSWER,
            );
        } catch (\Throwable $e) {
            $this->tell(new CallAnswer($route, error: $this->scrub($e)));

            return null;
        }
        // An answer after the deadline is none: the budget ended the call, and a transport
        // of yours that kept it past it costs no decision and records nothing more.
        if (microtime(true) > $deadline) {
            $this->tell(new CallAnswer(
                $route,
                error: new \RuntimeException('korzen: no answer within the budget'),
            ));

            return null;
        }
        $error = null;
        if (\strlen($answer->body) > self::MAX_ANSWER) {
            $error = new \RuntimeException('korzen: an answer past ' . self::MAX_ANSWER . ' bytes');
            $answer = new Answer($answer->status, '', $answer->headers);
        }
        $problem = $answer->status === 200 || $answer->status === 204 ? null : Problem::of($answer);
        if ($error === null && $problem === null && $answer->status !== 200 && $answer->status !== 204) {
            $error = new \RuntimeException('korzen: status ' . $answer->status);
        }
        $id = $answer->header('korzen-request-id');
        $this->tell(new CallAnswer(
            $route,
            $answer->status,
            $id === '' ? null : $id,
            RateLimit::parse($answer->header('ratelimit-policy'), $answer->header('ratelimit')),
            $answer->header('idempotent-replayed') === 'true',
            $problem,
            $error,
        ));

        return $answer;
    }

    /**
     * $e, or, when its message or a frame's arguments (its own or a previous one's) hold the
     * API key, a new exception that names only its class: a transport of yours that does
     * not mark its headers #[\SensitiveParameter], or a PHP function handed them, would put
     * the key in the trace an error tracker keeps (zend.exception_ignore_args=0).
     */
    private function scrub(#[\SensitiveParameter] \Throwable $e): \Throwable
    {
        for ($t = $e; $t !== null && $this->apiKey !== ''; $t = $t->getPrevious()) {
            if (self::holds([$t->getMessage(), $t->getTrace()], $this->apiKey, 8)) {
                return new \RuntimeException(
                    'korzen: the call to Bot Protection failed (' . $e::class . '; its details held the API key)',
                );
            }
        }

        return $e;
    }

    /** Whether $v, a string or an array of them $depth deep, holds $key. */
    private static function holds(mixed $v, #[\SensitiveParameter] string $key, int $depth): bool
    {
        if (\is_string($v)) {
            return str_contains($v, $key);
        }
        if (!\is_array($v) || $depth === 0) {
            return false;
        }
        foreach ($v as $item) {
            if (self::holds($item, $key, $depth - 1)) {
                return true;
            }
        }

        return false;
    }

    /**
     * $value when $ok, else $default, logged: what the setting must be, and the default it
     * is. The value is a number, never the key.
     */
    private function setting(bool $ok, int $value, int $default, string $rule): int
    {
        if ($ok) {
            return $value;
        }
        $this->log('korzen: ' . $rule . ', not ' . $value . ': ' . $default . ' it is');

        return $default;
    }

    /** Gives the logger $message; a logger that throws costs nothing. */
    private function log(string $message): void
    {
        try {
            ($this->logger)($message);
        } catch (\Throwable) {
            // A logger that throws costs no call.
        }
    }

    /**
     * Tells onAnswer of every answer waiting for it, oldest first, each in a try of its own:
     * what it throws is logged once and costs nothing. The client calls it when the request
     * ends; a long-running worker that serves many requests in one process calls it after
     * each, once the response is sent. It never throws.
     */
    public function flush(): void
    {
        if ($this->onAnswer === null) {
            return;
        }
        // The answers of now: one of a call onAnswer makes itself waits for the next flush.
        $answers = $this->pending;
        $this->pending = [];
        foreach ($answers as $answer) {
            try {
                ($this->onAnswer)($answer);
            } catch (\Throwable $e) {
                $this->warnOnce($this->warnedHook, 'korzen: onAnswer threw ' . $e::class . '; it cost no call');
            }
        }
    }

    /**
     * Logs, once for this client, an error a middleware met and let the visitor through
     * after: what failed and the error's class, never its message, which may hold anything.
     *
     * @internal
     */
    public function fault(string $where, \Throwable $e): void
    {
        $this->warnOnce(
            $this->warnedFault,
            'korzen: ' . $where . ' let a request through after an error: ' . $e::class,
        );
    }

    /**
     * Whether first-party mode can forward through this client's transport: CurlTransport
     * and StreamTransport can, a Transport of yours when it implements ForwardTransport too.
     *
     * @internal
     */
    public function forwards(): bool
    {
        return $this->transport instanceof ForwardTransport;
    }

    /**
     * Sends first-party mode's forward of $method to $route (a path of Bot Protection's
     * with its query), with $headers and the key as a Bearer token, and returns the answer,
     * whatever its status; it throws on any failure, no key, or an answer after $deadline.
     *
     * @param array<string, string> $headers
     *
     * @internal
     */
    public function forward(
        string $method,
        string $route,
        array $headers,
        string $body,
        float $deadline,
        int $limit,
    ): Answer {
        // No key, or one that would split the Authorization header, is no forward.
        if ($this->apiKey === '' || preg_match('/[\x00-\x08\x0a-\x1f\x7f]/', $this->apiKey) === 1) {
            throw new \RuntimeException('korzen: no API key to forward with');
        }
        if (!$this->transport instanceof ForwardTransport) {
            throw new \LogicException('korzen: the transport cannot forward');
        }
        $answer = $this->transport->send(
            $method,
            $this->base . $route,
            $headers + ['Authorization' => 'Bearer ' . $this->apiKey],
            $body,
            $deadline,
            $limit,
        );
        if (microtime(true) > $deadline) {
            throw new \RuntimeException('korzen: no answer within the forward\'s time');
        }

        return $answer;
    }

    /**
     * Logs $message once for this client and $topic.
     *
     * @internal
     */
    public function warnOnceAbout(string $topic, string $message): void
    {
        if (isset($this->told[$topic])) {
            return;
        }
        $this->told[$topic] = true;
        $this->log($message);
    }

    /**
     * Keeps what a call ended with for onAnswer, told when the request ends or at flush():
     * PHP cannot bound a function it calls, so it runs after the decision, never in it.
     */
    private function tell(CallAnswer $answer): void
    {
        if ($this->onAnswer === null) {
            return;
        }
        if (\count($this->pending) >= self::MAX_HOOKS) {
            $this->warnOnce(
                $this->warnedHooks,
                'korzen: ' . self::MAX_HOOKS . ' answers already wait for onAnswer; this one is not told. '
                . 'A long-running worker calls flush() after each request.',
            );

            return;
        }
        if (!$this->atShutdown) {
            $this->atShutdown = true;
            register_shutdown_function($this->flush(...));
        }
        $this->pending[] = $answer;
    }

    /** Logs $message once for this client, the first time $warned is false. */
    private function warnOnce(bool &$warned, string $message): void
    {
        if ($warned) {
            return;
        }
        $warned = true;
        $this->log($message);
    }

    /**
     * Logs, once for this client, a context's card_bin of more than 8 digits: it may be a
     * card number, and is left out.
     */
    private function warnCardNumber(): void
    {
        if ($this->warnedCard) {
            return;
        }
        $this->warnedCard = true;
        $this->log(
            'korzen: context.card_bin had more than 8 digits, which may be a card number: it was left out. '
            . "Send the card's first six digits.",
        );
    }

    /** Logs, once for this client, an IP from the server's own network. */
    private function warnOwnNetwork(?string $ip): void
    {
        if ($this->warned || $ip === null || !Ip::ownNetwork($ip)) {
            return;
        }
        $this->warned = true;
        $this->log(
            "korzen: the visitor's IP sent to Bot Protection, {$ip}, is not on the Internet: "
            . "it is your proxy's or load balancer's. "
            . 'Set the ip option (Ip::lastForwarded(...), Ip::cloudflare(...), or a function of yours) '
            . "to the visitor's address: "
            . self::IP_HELP,
        );
    }
}

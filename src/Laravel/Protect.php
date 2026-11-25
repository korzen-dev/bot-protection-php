<?php

declare(strict_types=1);

namespace Korzen\BotProtection\Laravel;

use Korzen\BotProtection\Client;
use Korzen\BotProtection\Decision;
use Korzen\BotProtection\FirstParty;
use Korzen\BotProtection\Guard;
use Korzen\BotProtection\Ip;
use Korzen\BotProtection\Outcome;
use Korzen\BotProtection\Seen;
use Korzen\BotProtection\Visit;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel middleware, on Symfony HttpFoundation's Request and Response (so it serves any
 * HttpFoundation stack): it asks about each request before the next step. On block it
 * calls onBlock, or answers 403. Otherwise, and on any error, the request goes on, with
 * the decision (or null) as the request attribute korzen.decision:
 * $request->attributes->get('korzen.decision').
 *
 * Laravel builds it from its container, with the Client bound there; a route names the
 * action with a parameter, protect:/signup when aliased as protect.
 */
class Protect
{
    /** The request attribute that holds the decision, or null when there is none. */
    public const ATTRIBUTE = 'korzen.decision';

    /** @var \Closure(Request): ?string */
    private readonly \Closure $ip;
    /** @var (\Closure(Request, Decision): ?Response)|null */
    private readonly ?\Closure $onBlock;
    /** @var (\Closure(Request): ?string)|null */
    private readonly ?\Closure $action;
    /** First-party mode's forwarder; null when the mode is off. */
    private readonly ?FirstParty $forwarder;

    /**
     * @param (callable(Request): ?string)|null $ip reads the visitor's IP; Ip::socket(...)
     *     when null. Behind a proxy Laravel trusts, fn ($r) => $r->ip() is the visitor's.
     *     The scheme the request came on is read where it is (Ip::schemeOf): Laravel's
     *     getScheme(), X-Forwarded-Proto's or CF-Visitor's
     * @param string|null $path names the action in the decision, instead of the request's path
     * @param (callable(Request, Decision): ?Response)|null $onBlock answers a blocked request;
     *     null from it lets the request through
     * @param bool $requireToken $protectedAction's former name, deprecated: still read, the
     *     same
     * @param bool $firstParty turns first-party mode on (korzen's decision 0238): the
     *     middleware serves the tag and its beacon under $firstPartyPath on your own domain
     *     and forwards them to Bot Protection with the visitor's address, read by $ip, so a
     *     block list of korzen.dev stops none of it. Those requests are never judged and
     *     never reach the next step. Put the middleware on that path too (or on every
     *     route), with the same options
     * @param string|null $firstPartyPath the path first-party mode serves, FirstParty::DEFAULT_PATH
     *     (/kz) when null: "/" first, no "/" last, at most 64 bytes of A-Z a-z 0-9 . _ ~ -
     *     segments, none "." or "..". One that does not read is logged once, and the mode
     *     stays off
     * @param string|null $cdn names the CDN your server takes its traffic from, one of Cdn's
     *     (Cdn::CLOUDFRONT, Cdn::VERCEL, ...): its headers carry the visitor's JA4 and, on
     *     CloudFront, their header order and HTTP version (Cdn::fields). Anyone can send them
     *     to a server reachable around its CDN, so they are read only under the CDN named
     *     here: name one only when your server takes traffic from it alone. With one named,
     *     the header order the server received, the CDN's, is not sent. None when null
     * @param list<string> $allowRuleHeaders the names of the headers your custom rules name
     *     (Custom rules): each the request carries goes with its decision
     *     (DecideRequest::from), never one a rule may not name, such as a cookie
     * @param (callable(Request): ?string)|null $action names the request's action as your allow
     *     rules name it (DecideRequest::$action), for a path that serves several, such as a
     *     GraphQL operation's name; none when it returns null. One that throws lets the
     *     request through with no decision
     * @param bool $protectedAction makes every decision asked for on an action, a request
     *     that is not a GET, HEAD or OPTIONS, a protected action: it needs the tag's token
     *     (DecideRequest::$protectedAction). A try sent again within two minutes is the
     *     same try, so a form sent again after a correction goes through.
     */
    public function __construct(
        private readonly Client $client,
        ?callable $ip = null,
        private readonly ?string $path = null,
        ?callable $onBlock = null,
        private readonly bool $requireToken = false,
        bool $firstParty = false,
        ?string $firstPartyPath = null,
        private readonly ?string $cdn = null,
        private readonly array $allowRuleHeaders = [],
        ?callable $action = null,
        private readonly bool $protectedAction = false,
    ) {
        $this->ip = \Closure::fromCallable($ip ?? Ip::socket(...));
        $this->onBlock = $onBlock === null ? null : \Closure::fromCallable($onBlock);
        $this->action = $action === null ? null : \Closure::fromCallable($action);
        $this->forwarder = FirstParty::of($client, $firstParty, $firstPartyPath);
    }

    /**
     * @param \Closure(Request): mixed $next
     * @param string|null $path names the action, as a route's middleware parameter
     */
    public function handle(Request $request, \Closure $next, ?string $path = null): mixed
    {
        $seen = new Seen();
        try {
            $answer = $this->judge($request, $path ?? $this->path, $seen);
            if ($answer !== null) {
                return $answer;
            }
        } catch (\Throwable $e) {
            // Any error on the way, a hook's or the middleware's own, lets the visitor through.
            $this->client->fault('the Laravel middleware', $e);
        }
        $request->attributes->set(self::ATTRIBUTE, $seen->decision);

        // The next step's own errors are the app's: they go on as they are.
        return $next($request);
    }

    /**
     * The middleware's answer to $request, its own or a hook's; null lets it go on. The
     * decision, once there is one, is kept in $seen for the next step.
     */
    private function judge(Request $request, ?string $path, Seen $seen): ?Response
    {
        $forwarded = $this->forwarder?->serve(
            Visit::of($request),
            static fn(): string => $request->getContent(),
            fn(): ?string => ($this->ip)($request),
        );
        if ($forwarded !== null) {
            return new Forwarded($forwarded->body, $forwarded->status ?? 503, $forwarded->headers);
        }
        $visit = Visit::of($request);
        $o = Guard::run(
            $this->client,
            $visit,
            ($this->ip)($request),
            $path,
            $this->onBlock !== null,
            $this->protectedAction || $this->requireToken,
            Ip::schemeOf($this->ip, $visit),
            $this->cdn,
            Ip::fromOf($this->ip),
            $this->allowRuleHeaders,
            $this->action === null ? null : ($this->action)($request),
        );
        $seen->decision = $o->decision;
        if ($o->status !== null) {
            return self::respond($o);
        }
        $request->attributes->set(self::ATTRIBUTE, $o->decision);

        return $o->hook && $this->onBlock !== null && $o->decision !== null
            ? ($this->onBlock)($request, $o->decision)
            : null;
    }

    private static function respond(Outcome $o): Response
    {
        $res = new Response($o->body, $o->status ?? 200);
        foreach ($o->headers as [$name, $value]) {
            $res->headers->set($name, $value);
        }

        return $res;
    }
}

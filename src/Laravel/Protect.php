<?php

declare(strict_types=1);

namespace Korzen\BotProtection\Laravel;

use Korzen\BotProtection\Client;
use Korzen\BotProtection\Cookies;
use Korzen\BotProtection\Decision;
use Korzen\BotProtection\FirstParty;
use Korzen\BotProtection\Guard;
use Korzen\BotProtection\Ip;
use Korzen\BotProtection\Outcome;
use Korzen\BotProtection\ReturnTo;
use Korzen\BotProtection\Seen;
use Korzen\BotProtection\Visit;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel middleware, on Symfony HttpFoundation's Request and Response (so it serves any
 * HttpFoundation stack): it asks about each request before the next step. A block or a
 * challenge marked decoy goes to onDecoy first, when given; without it, or on null from
 * it, an action (POST, PUT, PATCH, DELETE) is answered 202 with {}, the default decoy,
 * and a page load as below. On block it
 * calls onBlock, or answers 403. On challenge it calls onChallenge; without one a page
 * load (GET or HEAD) goes to the challenge page and back to the same address, and anything
 * else, a form post or an API call, is refused with a 403. Otherwise, and on any error,
 * the request goes on, with the decision (or null) as the request attribute
 * korzen.decision: $request->attributes->get('korzen.decision'). Back from the challenge
 * page, the token it adds is kept as the _kz cookie and the visitor is sent on without it.
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
    private readonly ?\Closure $onDecoy;
    /** @var (\Closure(Request, Decision): ?Response)|null */
    private readonly ?\Closure $onBlock;
    /** @var (\Closure(Request, Decision): ?Response)|null */
    private readonly ?\Closure $onChallenge;
    /** @var \Closure(Request): string */
    private readonly \Closure $returnTo;
    /**
     * Whether the way back from the challenge page is the address's path alone: unless
     * $publicUrl or $returnTo names the origin or the address, never a host a request wrote.
     */
    private readonly bool $relative;
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
     * @param (callable(Request, Decision): ?Response)|null $onChallenge answers a challenged
     *     request; null from it lets the request through
     * @param string|null $publicUrl the origin your visitors see, such as https://shop.example
     * @param (callable(Request): string)|null $returnTo the address to come back to from the
     *     challenge page; ReturnTo::request(...) when neither it nor $publicUrl is set
     * @param bool $requireToken sends require_token with every decision asked for on an
     *     action, a request that is not a GET, HEAD or OPTIONS: the action needs the tag's
     *     token (DecideRequest::$requireToken)
     * @param (callable(Request, Decision): ?Response)|null $onDecoy answers a block or a
     *     challenge marked decoy with your decoy, before onBlock and onChallenge; without
     *     it, or on null from it, an action gets 202 with {}, the default decoy, and a page
     *     load is refused as any other
     * @param bool $firstParty turns first-party mode on (korzen's decision 0238): the
     *     middleware serves the tag, its beacon and the challenge page under
     *     $firstPartyPath on your own domain and forwards them to Bot Protection with the
     *     visitor's address, read by $ip, so a block list of korzen.dev stops none of it.
     *     Those requests are never judged and never reach the next step, and a challenged
     *     page load goes to $firstPartyPath/challenge. Put the middleware on that path too
     *     (or on every route), with the same options
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
     *
     * @throws \InvalidArgumentException when $publicUrl is not an http(s) URL
     */
    public function __construct(
        private readonly Client $client,
        ?callable $ip = null,
        private readonly ?string $path = null,
        ?callable $onBlock = null,
        ?callable $onChallenge = null,
        ?string $publicUrl = null,
        ?callable $returnTo = null,
        private readonly bool $requireToken = false,
        ?callable $onDecoy = null,
        bool $firstParty = false,
        ?string $firstPartyPath = null,
        private readonly ?string $cdn = null,
    ) {
        $this->ip = \Closure::fromCallable($ip ?? Ip::socket(...));
        $this->onBlock = $onBlock === null ? null : \Closure::fromCallable($onBlock);
        $this->onDecoy = $onDecoy === null ? null : \Closure::fromCallable($onDecoy);
        $this->onChallenge = $onChallenge === null ? null : \Closure::fromCallable($onChallenge);
        $public = $publicUrl === null ? null : ReturnTo::publicUrl($publicUrl);
        $this->returnTo = \Closure::fromCallable($returnTo ?? $public ?? ReturnTo::request(...));
        $this->relative = $returnTo === null && $public === null;
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
        try {
            $returnTo = ($this->returnTo)($request);
        } catch (\Throwable) {
            $returnTo = '';
        }
        $visit = Visit::of($request);
        $o = Guard::run(
            $this->client,
            $visit,
            ($this->ip)($request),
            $path,
            $returnTo,
            $this->onBlock !== null,
            $this->onChallenge !== null,
            $this->requireToken,
            $this->onDecoy !== null,
            $this->relative,
            Ip::schemeOf($this->ip, $visit),
            $this->forwarder->prefix ?? '',
            $this->cdn,
            Ip::fromOf($this->ip),
        );
        $seen->decision = $o->decision;
        if ($o->status !== null) {
            return self::respond($o);
        }
        $request->attributes->set(self::ATTRIBUTE, $o->decision);
        if ($o->hook === 'decoy' && $this->onDecoy !== null && $o->decision !== null) {
            $answer = ($this->onDecoy)($request, $o->decision);
            if ($answer !== null) {
                return $answer;
            }
            // A decoy that answers nothing: the default decoy on an action, else the refusal.
            $o = $o->otherwise ?? Outcome::pass($o->decision);
            if ($o->status !== null) {
                return self::respond($o);
            }
        }
        $hook = match ($o->hook) {
            'block' => $this->onBlock,
            'challenge' => $this->onChallenge,
            default => null,
        };

        return $hook !== null && $o->decision !== null ? $hook($request, $o->decision) : null;
    }

    private static function respond(Outcome $o): Response
    {
        $res = new Response($o->body, $o->status ?? 200);
        foreach ($o->headers as [$name, $value]) {
            if ($name === 'Set-Cookie') {
                $res->headers->setCookie(self::cookie($value));
            } else {
                $res->headers->set($name, $value);
            }
        }

        return $res;
    }

    /** A Set-Cookie line of Cookies as a Symfony cookie that sends it as it is. */
    private static function cookie(string $line): SetCookie
    {
        $kv = explode('=', explode(';', $line, 2)[0], 2);
        $name = $kv[0];
        $value = $kv[1] ?? '';

        return new SetCookie(
            $line,
            $name,
            $value,
            str_contains($line, '; Secure'),
            $name === Cookies::CHALLENGE,
        );
    }
}

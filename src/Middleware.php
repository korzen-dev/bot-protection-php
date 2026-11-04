<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware, for Slim, Mezzio and any PSR-15 stack: it asks about each request
 * before the handler. A block or a challenge marked decoy goes to onDecoy first, when
 * given; without it, or on null from it, an action (POST, PUT, PATCH, DELETE) is answered
 * 202 with {}, the default decoy, and a page load as below. On block it calls onBlock, or
 * answers 403. On challenge it calls
 * onChallenge; without one a page load (GET or HEAD) goes to the challenge page and back
 * to the same address, and anything else, a form post or an API call, is refused with a
 * 403: guard the form's page too, so a person meets the challenge there and the pass lets
 * the post through. Otherwise, and on any error, the handler runs, with the decision (or
 * null) as the request attribute korzen.decision. Back from the challenge page, the token
 * it adds is kept as the _kz cookie and the visitor is sent on without it.
 */
final readonly class Middleware implements MiddlewareInterface
{
    /** The request attribute that holds the decision, or null when there is none. */
    public const ATTRIBUTE = 'korzen.decision';

    /** @var \Closure(ServerRequestInterface): ?string */
    private \Closure $ip;
    /** @var (\Closure(ServerRequestInterface, Decision): ?ResponseInterface)|null */
    private ?\Closure $onDecoy;
    /** @var (\Closure(ServerRequestInterface, Decision): ?ResponseInterface)|null */
    private ?\Closure $onBlock;
    /** @var (\Closure(ServerRequestInterface, Decision): ?ResponseInterface)|null */
    private ?\Closure $onChallenge;
    /** @var \Closure(ServerRequestInterface): string */
    private \Closure $returnTo;
    /**
     * Whether the way back from the challenge page is the address's path alone: unless
     * $publicUrl or $returnTo names the origin or the address, never a host a request wrote.
     */
    private bool $relative;
    /** First-party mode's forwarder; null when the mode is off. */
    private ?FirstParty $forwarder;

    /**
     * @param (callable(ServerRequestInterface): ?string)|null $ip reads the visitor's IP;
     *     Ip::socket(...) when null. The scheme the request came on is read where it is
     *     (Ip::schemeOf): the URI's, X-Forwarded-Proto's or CF-Visitor's
     * @param string|null $path names the action in the decision, instead of the request's path
     * @param (callable(ServerRequestInterface, Decision): ?ResponseInterface)|null $onBlock
     *     answers a blocked request; null from it lets the request through
     * @param (callable(ServerRequestInterface, Decision): ?ResponseInterface)|null $onChallenge
     *     answers a challenged request; null from it lets the request through
     * @param string|null $publicUrl the origin your visitors see, such as https://shop.example,
     *     behind a proxy that forwards Host: localhost and no X-Forwarded-Host
     * @param (callable(ServerRequestInterface): string)|null $returnTo the address to come back
     *     to from the challenge page; ReturnTo::request(...) when neither it nor $publicUrl is set
     * @param bool $requireToken sends require_token with every decision asked for on an
     *     action, a request that is not a GET, HEAD or OPTIONS: the action needs the tag's
     *     token (DecideRequest::$requireToken)
     * @param (callable(ServerRequestInterface, Decision): ?ResponseInterface)|null $onDecoy
     *     answers a block or a challenge marked decoy with your decoy, before onBlock and
     *     onChallenge; without it, or on null from it, an action gets 202 with {}, the
     *     default decoy, and a page load is refused as any other
     * @param bool $firstParty turns first-party mode on (korzen's decision 0238): the
     *     middleware serves the tag, its beacon and the challenge page under
     *     $firstPartyPath on your own domain and forwards them to Bot Protection with the
     *     visitor's address, read by $ip, so a block list of korzen.dev stops none of it.
     *     Those requests are never judged and never reach the handler, and a challenged
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
        private Client $client,
        private ResponseFactoryInterface $responses,
        ?callable $ip = null,
        private ?string $path = null,
        ?callable $onBlock = null,
        ?callable $onChallenge = null,
        ?string $publicUrl = null,
        ?callable $returnTo = null,
        private bool $requireToken = false,
        ?callable $onDecoy = null,
        bool $firstParty = false,
        ?string $firstPartyPath = null,
        private ?string $cdn = null,
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

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $seen = new Seen();
        try {
            $answer = $this->judge($request, $seen);
            if ($answer !== null) {
                return $answer;
            }
        } catch (\Throwable $e) {
            // Any error on the way, a hook's or the middleware's own, lets the visitor through.
            $this->client->fault('the PSR-15 middleware', $e);
        }

        // The handler's own errors are the app's: they go on as they are.
        return $handler->handle($request->withAttribute(self::ATTRIBUTE, $seen->decision));
    }

    /**
     * The middleware's answer to $request, its own or a hook's; null lets it through to the
     * handler. The decision, once there is one, is kept in $seen for the handler.
     */
    private function judge(ServerRequestInterface $request, Seen $seen): ?ResponseInterface
    {
        $forwarded = $this->forwarder?->serve(
            Visit::of($request),
            static fn(): string => (string) $request->getBody(),
            fn(): ?string => ($this->ip)($request),
        );
        if ($forwarded !== null) {
            return $this->respond($forwarded);
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
            $this->path,
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
            return $this->respond($o);
        }
        $request = $request->withAttribute(self::ATTRIBUTE, $o->decision);
        if ($o->hook === 'decoy' && $this->onDecoy !== null && $o->decision !== null) {
            $answer = ($this->onDecoy)($request, $o->decision);
            if ($answer !== null) {
                return $answer;
            }
            // A decoy that answers nothing: the default decoy on an action, else the refusal.
            $o = $o->otherwise ?? Outcome::pass($o->decision);
            if ($o->status !== null) {
                return $this->respond($o);
            }
        }
        $hook = match ($o->hook) {
            'block' => $this->onBlock,
            'challenge' => $this->onChallenge,
            default => null,
        };

        return $hook !== null && $o->decision !== null ? $hook($request, $o->decision) : null;
    }

    private function respond(Outcome $o): ResponseInterface
    {
        $res = $this->responses->createResponse($o->status ?? 200);
        foreach ($o->headers as [$name, $value]) {
            $res = $res->withAddedHeader($name, $value);
        }
        if ($o->body !== '') {
            $res->getBody()->write($o->body);
        }
        if ($o->forwarded && !$o->typed()) {
            // PHP adds its default_mimetype to an answer that names none, when it is sent:
            // first-party mode's goes back as Korzen sent it.
            ini_set('default_mimetype', '');
        }

        return $res;
    }
}

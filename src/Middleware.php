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
 * before the handler. On block it calls onBlock, or answers 403. Otherwise, and on any
 * error, the handler runs, with the decision (or null) as the request attribute
 * korzen.decision.
 */
final readonly class Middleware implements MiddlewareInterface
{
    /** The request attribute that holds the decision, or null when there is none. */
    public const ATTRIBUTE = 'korzen.decision';

    /** @var \Closure(ServerRequestInterface): ?string */
    private \Closure $ip;
    /** @var (\Closure(ServerRequestInterface, Decision): ?ResponseInterface)|null */
    private ?\Closure $onBlock;
    /** @var (\Closure(ServerRequestInterface): ?string)|null */
    private ?\Closure $action;
    /** First-party mode's forwarder; null when the mode is off. */
    private ?FirstParty $forwarder;

    /**
     * @param (callable(ServerRequestInterface): ?string)|null $ip reads the visitor's IP;
     *     Ip::socket(...) when null. The scheme the request came on is read where it is
     *     (Ip::schemeOf): the URI's, X-Forwarded-Proto's or CF-Visitor's
     * @param string|null $path names the action in the decision, instead of the request's path
     * @param (callable(ServerRequestInterface, Decision): ?ResponseInterface)|null $onBlock
     *     answers a blocked request; null from it lets the request through
     * @param bool $requireToken $protectedAction's former name, deprecated: still read, the
     *     same
     * @param bool $firstParty turns first-party mode on (korzen's decision 0238): the
     *     middleware serves the tag and its beacon under $firstPartyPath on your own domain
     *     and forwards them to Bot Protection with the visitor's address, read by $ip, so a
     *     block list of korzen.dev stops none of it. Those requests are never judged and
     *     never reach the handler. Put the middleware on that path too (or on every route),
     *     with the same options
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
     * @param (callable(ServerRequestInterface): ?string)|null $action names the request's action as your allow
     *     rules name it (DecideRequest::$action), for a path that serves several, such as a
     *     GraphQL operation's name; none when it returns null. One that throws lets the
     *     request through with no decision
     * @param bool $protectedAction makes every decision asked for on an action, a request
     *     that is not a GET, HEAD or OPTIONS, a protected action: it needs the tag's token
     *     (DecideRequest::$protectedAction). A try sent again within two minutes is the
     *     same try, so a form sent again after a correction goes through.
     */
    public function __construct(
        private Client $client,
        private ResponseFactoryInterface $responses,
        ?callable $ip = null,
        private ?string $path = null,
        ?callable $onBlock = null,
        private bool $requireToken = false,
        bool $firstParty = false,
        ?string $firstPartyPath = null,
        private ?string $cdn = null,
        private array $allowRuleHeaders = [],
        ?callable $action = null,
        private bool $protectedAction = false,
    ) {
        $this->ip = \Closure::fromCallable($ip ?? Ip::socket(...));
        $this->onBlock = $onBlock === null ? null : \Closure::fromCallable($onBlock);
        $this->action = $action === null ? null : \Closure::fromCallable($action);
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
        $visit = Visit::of($request);
        $o = Guard::run(
            $this->client,
            $visit,
            ($this->ip)($request),
            $this->path,
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
            return $this->respond($o);
        }
        $request = $request->withAttribute(self::ATTRIBUTE, $o->decision);

        return $o->hook && $this->onBlock !== null && $o->decision !== null
            ? ($this->onBlock)($request, $o->decision)
            : null;
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

<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * What decide() sends; every field is optional, and an empty one is left out. decide()
 * cuts each to what Bot Protection keeps (Bounds) and never changes this object.
 */
final readonly class DecideRequest
{
    /**
     * The headers from() sends, the ones Bot Protection reads. Every Korzen SDK forwards
     * the same, and never a cookie or authorization.
     */
    /**
     * The header a page sends the tag's token in when the _kz cookie does not travel: an
     * API on another origin, a frame, a browser that refuses cookies. from() reads it
     * before the cookie.
     */
    public const TOKEN_HEADER = 'x-korzen-token';

    public const FORWARDED = [
        'accept',
        'accept-encoding',
        'accept-language',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-fetch-dest',
        'sec-fetch-mode',
        'sec-fetch-site',
        'upgrade-insecure-requests',
    ];

    /**
     * A signed agent's Web Bot Auth headers, sent only when the request carries a
     * Signature-Input: Bot Protection verifies the signature against them and the Host,
     * which goes with every decision. Every Korzen SDK sends the same.
     */
    public const SIGNED = ['signature', 'signature-input', 'signature-agent'];

    /**
     * @param string|null $ip the visitor's IP, as your edge reports it (Ip::socket(...),
     *     Ip::lastForwarded(...), Ip::cloudflare(...))
     * @param array<array-key, string> $headers lower-cased names (PHP keeps a name of digits
     *     as an int): such as the ones FORWARDED lists
     * @param list<string> $headerOrder the names of every header the request came with,
     *     lower-cased, in the order your server received them; empty where the order is
     *     lost
     * @param string|null $token the _kz cookie the tag sets
     * @param string|null $path names the protected action, such as /signup
     * @param bool $requireToken the action requires the tag's token (a queue join, a
     *     sign-up, a checkout): without a valid one, or with one this session already
     *     used on this path, in block mode the answer is challenge with tokenRequired,
     *     unless it was block. A visitor without JavaScript cannot pass it: set it only
     *     where that is the choice.
     * @param Context|null $context what your server knows of the person behind the request
     *     (the email, phone, card and ids of a sign-up, a login or a checkout), raw: each
     *     field is normalised and hashed before it is sent, so no raw value leaves your
     *     server. A field that does not read is left out, never an error.
     * @param int|null $placesPerIdentity with requireToken and the context's identityId: how
     *     many sessions of one identity may take this path in an hour, 1 to 10; null, 0 or
     *     less sends none, which is 1, and a number past 10 is cut to it.
     * @param string|null $scheme the scheme your server received the request on, http or
     *     https; another value is sent as none. Over http a browser sends no Client Hints
     *     and no Fetch Metadata, and Bot Protection then reads no absence of them. The
     *     middleware reads it where it reads the IP (Ip::socket(...) and a reader of yours:
     *     the framework's own view; Ip::lastForwarded(...): X-Forwarded-Proto;
     *     Ip::cloudflare(...): CF-Visitor).
     */
    public function __construct(
        public ?string $ip = null,
        public ?string $userAgent = null,
        public array $headers = [],
        public array $headerOrder = [],
        public ?string $token = null,
        public ?string $path = null,
        public ?string $method = null,
        public ?Claims $claims = null,
        public ?string $ja4 = null,
        public ?string $httpProtocol = null,
        public ?string $tlsGroup = null,
        public ?string $country = null,
        public ?int $asn = null,
        public bool $requireToken = false,
        public ?Context $context = null,
        public ?int $placesPerIdentity = null,
        public ?string $scheme = null,
        public ?string $ipFrom = null,
    ) {}

    /**
     * The request for a PSR-7 or a Symfony (Laravel) request: its User-Agent, the
     * FORWARDED headers it carries, the token (the TOKEN_HEADER when it is a token, else
     * the _kz cookie), its path and method, and
     * $ip, the visitor's address as your edge reports it (Ip::socket($request),
     * Ip::lastForwarded($request), Ip::cloudflare($request)). headerOrder is the order of
     * the server params' HTTP_ keys ($_SERVER), reversed under PHP-FPM, which lists them
     * last first; a request whose server params hold no HTTP_ key sends none. $scheme is
     * the scheme it came on (Ip::schemeOf reads it for the middleware), none when null.
     * $cdn names the CDN your server takes its traffic from, one of Cdn's: only then are its
     * headers read (Cdn::fields), the visitor's JA4, and on CloudFront their header order
     * and HTTP version, since anyone can send them to a server reachable around its CDN.
     * With a CDN named, the order the server received is the CDN's, never sent as the
     * visitor's.
     */
    public static function from(
        ServerRequestInterface|Request $request,
        ?string $ip = null,
        ?string $scheme = null,
        ?string $cdn = null,
    ): self {
        return self::fromVisit(Visit::of($request), $ip, $scheme, $cdn);
    }

    /** @internal */
    public static function fromVisit(
        Visit $v,
        ?string $ip,
        ?string $scheme = null,
        ?string $cdn = null,
        ?string $ipFrom = null,
    ): self {
        $headers = [];
        // A header sent twice goes as one, its values joined by ", " (RFC 9110 5.3); an
        // empty one goes as none.
        foreach (self::FORWARDED as $name) {
            $value = $v->header($name);
            if ($value !== '') {
                $headers[$name] = $value;
            }
        }
        // The domain the request was made to, the one a token's decision may prove yours.
        if ($v->host !== '') {
            $headers['host'] = $v->host;
        }
        if ($v->header('signature-input') !== '') {
            foreach (self::SIGNED as $name) {
                $value = $v->header($name);
                if ($value !== '') {
                    $headers[$name] = $value;
                }
            }
        }

        // Behind a CDN the order the server received is the CDN's, not the visitor's.
        $named = $cdn !== null && $cdn !== '';
        $request = new self(
            ip: $ip,
            userAgent: $v->has('user-agent') ? $v->header('user-agent') : null,
            headers: $headers,
            headerOrder: $named ? [] : $v->order,
            token: $v->token(),
            path: $v->path(),
            method: $v->method,
            scheme: $scheme,
            ipFrom: $ip === null || $ip === '' ? null : ($ipFrom ?? 'custom'),
        );

        return $named ? Cdn::fill($v, $cdn, $request) : $request;
    }

    /**
     * This request with a CDN's ja4, headerOrder and httpProtocol, each only where it has
     * none: a field set by hand wins.
     *
     * @param list<string> $headerOrder
     *
     * @internal
     */
    public function withCdn(?string $ja4, array $headerOrder, ?string $httpProtocol): self
    {
        return new self(
            $this->ip,
            $this->userAgent,
            $this->headers,
            $this->headerOrder === [] ? $headerOrder : $this->headerOrder,
            $this->token,
            $this->path,
            $this->method,
            $this->claims,
            $this->ja4 === null || $this->ja4 === '' ? $ja4 : $this->ja4,
            $this->httpProtocol === null || $this->httpProtocol === '' ? $httpProtocol : $this->httpProtocol,
            $this->tlsGroup,
            $this->country,
            $this->asn,
            $this->requireToken,
            $this->context,
            $this->placesPerIdentity,
            $this->scheme,
            $this->ipFrom,
        );
    }

    /** This request with the path that names the action. */
    public function withPath(?string $path): self
    {
        return $this->with($path, $this->requireToken, $this->context);
    }

    /** This request with require_token set or not. */
    public function withRequireToken(bool $requireToken): self
    {
        return $this->with($this->path, $requireToken, $this->context);
    }

    /** This request with what your server knows of the person behind it. */
    public function withContext(?Context $context): self
    {
        return $this->with($this->path, $this->requireToken, $context);
    }

    private function with(?string $path, bool $requireToken, ?Context $context): self
    {
        return new self(
            $this->ip,
            $this->userAgent,
            $this->headers,
            $this->headerOrder,
            $this->token,
            $path,
            $this->method,
            $this->claims,
            $this->ja4,
            $this->httpProtocol,
            $this->tlsGroup,
            $this->country,
            $this->asn,
            $requireToken,
            $context,
            $this->placesPerIdentity,
            $this->scheme,
            $this->ipFrom,
        );
    }
}

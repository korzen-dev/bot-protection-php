# Korzen Bot Protection for PHP

`korzen/bot-protection` asks [Korzen Bot Protection](https://korzen.dev/bot-protection)
about a request before a protected action (`POST /v1/decide`), on API v1, and **fails
open**: when Bot Protection is slow, down, refuses the key or answers anything but a
decision, the visitor goes through. A PSR-15 middleware (Slim, Mezzio, any PSR-15 stack)
and a Laravel middleware; no PHP extension needed, and the PSR interfaces as its only
dependencies.

## Install

```sh
composer require korzen/bot-protection
```

## Use (Slim)

```php
use Korzen\BotProtection\Client;
use Korzen\BotProtection\Ip;
use Korzen\BotProtection\Middleware;

$client = new Client((string) getenv('KORZEN_API_KEY'));

$app->post('/checkout', $checkout)->add(new Middleware(
    $client,
    $app->getResponseFactory(),
    ip: Ip::lastForwarded(...), // behind your own load balancer or nginx
));
// In $checkout: $request->getAttribute('korzen.decision'), a Decision or null
```

The key is required. `getenv()` answers `false` and Laravel's `config()` answers `null`
when it is unset, which `Client` refuses with a `TypeError` under `strict_types`: the
`(string)` cast keeps the server starting, and with an empty key every call is answered
`401` and lets the visitor through, as any failure does.

The middleware answers a block with 403 and otherwise runs your handler with the decision
as the request attribute `korzen.decision` (`null` when there is none). The actions are
`allow` and `block`; any other lets the visitor through.
`$client->decide(DecideRequest::from($request, Ip::socket($request)))` makes the call
alone, for a server that applies the decision itself: it returns a `Decision`, or `null`
on any failure, and never throws.

### PSR-15 (Mezzio and others)

`new Middleware($client, $responseFactory, ...)` takes any PSR-17 response factory:
`$app->pipe(...)` it in Mezzio, or add it to any PSR-15 stack.

### Laravel

Bind the client once, alias the middleware, and leave its cookie unencrypted: the tag
reads `_kz` in the browser, and Laravel would otherwise encrypt it.

```php
// app/Providers/AppServiceProvider.php, in register()
$this->app->singleton(Client::class, fn () => new Client((string) config('services.korzen.key')));

// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->alias(['protect' => \Korzen\BotProtection\Laravel\Protect::class]);
    $middleware->encryptCookies(except: ['_kz']);
})

// routes/web.php: protect:/signup names the action
Route::post('/signup', SignupController::class)->middleware('protect:/signup');
// In the controller: $request->attributes->get('korzen.decision')
```

`Protect` works on Symfony HttpFoundation's request and response, so it fits any
HttpFoundation stack. For options, bind it:
`$this->app->bind(Protect::class, fn ($app) => new Protect($app->make(Client::class), ip: fn ($request) => $request->ip()))`
sends the visitor's address from behind a proxy Laravel trusts.

### Payment, login and sign-up routes

Turn on `protectedAction` (formerly `requireToken`, still read) on the routes a script
goes after: the post that charges a card or places an order, the one that checks a
password, the one that creates an account. A script that never loads your page (card
testing from a new residential IP for each try) runs no tag and is answered `unknown`,
which is allowed. With the option, the action needs a token the tag earned in that
browser. Without one, `tokenRequired` is true. In block mode `action` is then `block`; in
monitor mode `action` stays `allow`. A `block` stays a `block`, and the class does not
change. `tokenRequired` is false while the protection is paused. A page load spends no
token, so guard the form's page too.

```php
$app->post('/checkout', $checkout)->add(new Middleware(
    $client,
    $app->getResponseFactory(),
    protectedAction: true, // on actions only: GET, HEAD and OPTIONS spend no token
));
```

Each protected action takes the token's use once. A try sent again within two minutes is
the same try: a person who corrects a weak password or a name already taken and sends the
form again goes through.

Laravel's `Protect` takes the same option: bind it with
`new Protect($app->make(Client::class), protectedAction: true)` for the routes that need
it.

Start in monitor mode, and watch the share of decisions without a token before you turn on
block mode: a visitor whose browser does not run the tag (an ad blocker, a DNS filter,
JavaScript off) holds no token, and is refused on these routes. Leave the option off the
routes no page of yours leads to (webhooks, a mobile app's API). More:
https://korzen.dev/bot-protection/docs/protecting-a-checkout.

## Options

Both middlewares take the same options, by name:

| Option             | What it does                                                                                                                                                           |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ip`               | reads the visitor's IP: `Ip::socket(...)` (default), `Ip::lastForwarded(...)`, `Ip::cloudflare(...)`, or yours; the scheme (`http`/`https`) is read from the same edge |
| `path`             | names the action in the decision, instead of the request's path                                                                                                        |
| `onBlock`          | `fn ($request, Decision $d)` answers a blocked request instead of the 403; `null` lets it through                                                                      |
| `protectedAction`  | sends `protected_action` on every action (not GET, HEAD or OPTIONS): the action needs the tag's token                                                                  |
| `allowRuleHeaders` | the headers [your custom rules](#your-own-monitors-and-scripts-custom-rules) name, sent when the request carries them                                                  |
| `action`           | `fn ($request): ?string`, names the request's action as your custom rules name it, for a path that serves several                                                      |
| `firstParty`       | [first-party mode](#first-party-mode): serves `firstPartyPath` and forwards it; off by default                                                                         |
| `firstPartyPath`   | the path first-party mode serves, `FirstParty::DEFAULT_PATH` (`/kz`) when `null`                                                                                       |
| `cdn`              | [the CDN in front](#behind-a-cdn) whose headers carry the visitor's JA4: `Cdn::CLOUDFRONT` and the others; none when `null`                                            |

To answer a refused action with an empty success instead of a `403`, so the bot does not
learn it lost, answer it `202` from `onBlock` yourself. Never on a sign-in form, or
anywhere a person judged a bot by mistake needs to know what happened.

The call goes through curl when ext-curl is loaded (`CurlTransport`), else a socket of
PHP's own (`StreamTransport`). Load ext-curl where you can: it bounds the whole call by
the timeout, the name lookup too (a libcurl built with the system's synchronous resolver
gets the name resolved within the time left and pinned). The socket bounds the name lookup
(the hosts file, then the nameservers `/etc/resolv.conf` names, asked over UDP until the
time left runs out: never the system's lookup, which no PHP timeout bounds, but where no
nameserver is named, as on Windows), connecting, the TLS handshake, and every read of the
headers and the body by the time left, so an answer sent a few bytes at a time costs the
visitor no more than the timeout. A `Transport` of yours must keep to the deadline too:
PHP cannot cut a call short, and an answer after it is taken for none (no decision) though
the visitor waited for it. Measured on 2026-10-22, ten calls to korzen.dev took 122 ms at
the median through curl and 206 ms through PHP's stream wrapper, with one at 5.3 s. Each
call opens its own connection: libcurl sends a POST again when a kept connection dies
before the answer, and a decide sent twice could spend a token the visitor earned once.

The client is
`new Client($apiKey, url: '', timeoutMs: 200, transport: null, logger: null, onAnswer: null, sdk: null)`.
The timeout bounds the whole call to `/v1/decide` and is sent as `Korzen-Deadline-Ms`: the
decision takes half, the network the other half. The settings are read once, when the
client is made, and each that does not read is logged once (never the key) and left at its
default, so no setting makes a call throw: the key is trimmed of the spaces and line
breaks around it (an empty one is logged: every call fails open); `url` is an https URL,
or http on loopback (`localhost`, `127.0.0.0/8`, `[::1]`) for a test on your machine, and
any other (http elsewhere would send the key in clear) calls the key's region
(`Client::regionUrl`); `timeoutMs` is more than 0 and at most 1000
(`Client::MAX_TIMEOUT_MS`), else 200. An error handed to `onAnswer` never holds the key:
one whose message or trace would is replaced by one that names its class. Every call names
its integration in `Korzen-Sdk`, `Client::SDK` (`php/<Client::VERSION>`) unless `sdk`
names another, as a plugin built on the SDK does (`wordpress/1.0.0`). The logger,
`fn (string $message)`, is told once when the IP sent is on your own network (`error_log`
by default). The helpers the middlewares are made of are public: `DecideRequest::from()`,
`Cookies::read()`, `Cdn::fields()`.

The default timeout is the latency table's row for a server in Europe or the US east:
https://korzen.dev/bot-protection/docs/server-call#latency. Elsewhere, take your server's
region's timeout from that table; one too short for the distance lets every visitor
through, and those calls still count as decisions.

### Behind a CDN

Several CDNs forward the visitor's JA4 (the fingerprint of their TLS handshake) to your
server in their own headers, and CloudFront also their header order and HTTP version. The
`cdn` option names the CDN your server stands behind, and only then are its headers read:
anyone can send them to a server reachable around its CDN, so **name a CDN only when your
server takes traffic from it alone**, as with the `ip` option.

| `cdn`                   | Header                                       | Turn it on                                                                                                |
| ----------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `Cdn::CLOUDFRONT`       | `CloudFront-Viewer-JA4-Fingerprint` and more | add `CloudFront-Viewer-JA4-Fingerprint`, `-Header-Order` and `-Http-Version` to the origin request policy |
| `Cdn::AZURE_FRONT_DOOR` | `X-Azure-JA4-Fingerprint`                    | on already                                                                                                |
| `Cdn::VERCEL`           | `x-vercel-ja4-digest`                        | on already                                                                                                |
| `Cdn::BUNNY`            | `CDN-JA4`                                    | on already                                                                                                |
| `Cdn::GOOGLE_CLOUD`     | `X-Client-JA4`                               | a custom request header `X-Client-JA4:{tls_ja4_fingerprint}` on the load balancer's backend service       |
| `Cdn::FASTLY`           | `X-Client-JA4`                               | `set req.http.X-Client-JA4 = tls.client.ja4;` in `vcl_recv`                                               |

```php
$app->add(new Middleware($client, $app->getResponseFactory(), ip: Ip::lastForwarded(...), cdn: Cdn::CLOUDFRONT));
```

A value that does not read (a JA4 outside its pattern, a header sent twice, an order with
a name that is no header name, a version not listed) is sent as none, never an error. With
a CDN named, the header order your server received, which is the CDN's, is not sent.
`Cdn::fields($request, Cdn::VERCEL, $decideRequest)` fills a `DecideRequest` of yours the
same way, a field you set winning over the CDN's.

### The decision

A `Decision` is API v1's answer, its seven members: `action` (`allow` or `block`; apply it
alone), `requestId` (keep it with an order; the dashboard finds the decision by it),
`decidedBy` (what decided: `known_bots`, `custom_rules` or `bot_engine`), `class` and
`botScore` (empty and 0 when something before the bot engine decided), `mode` (`monitor`,
`block` or `paused`) and `tokenRequired`. Any other member of the answer is read past, and
an answer whose `action` is another is no decision: the visitor goes through.

Of two `_kz` cookies (one set for a parent domain by other code) the first in the `Cookie`
header is the token, as the tag and Korzen's server read it: set no `_kz` cookie of your
own for a parent domain, or it shadows the tag's.

The token is read from the `x-korzen-token` header when the page sends one
(`korzen.token()` to an API on another origin, or from a frame, where the cookie does not
travel), else from the `_kz` cookie: you add nothing on the server. A header that is empty
or no token leaves the cookie (`DecideRequest::TOKEN_HEADER`).

### The context

`DecideRequest`'s `context` (or `withContext()`) takes what your server knows and the
traffic cannot show: `decide()` normalises the identifiers and sends only hashes and the
fields in clear, so the raw email, phone, card fingerprint and ids never leave your
server; what your server checked of the account goes as it is, as evidence of a person. A
value that does not read as its kind is left out, never an error; an absent field is never
evidence of a bot.

```php
$context = new Context(
    email: $email, // its domain sent, the address hashed
    phone: $phone, // E.164, spaces, dashes, dots and brackets allowed
    phoneCountry: 'NL',
    phoneType: 'mobile', // one of Context::PHONE_TYPES
    cardBin: $cardBin, // the first 6 to 8 digits; past 8 left out, and logged once
    cardFingerprint: $fingerprint, // Stripe's card.fingerprint
    accountId: $accountId,
    resourceId: $orderId,
    accountAgeDays: 420, // on a sign-in or a checkout
    knownInstrument: true, // the card or passkey of the account's past orders
    contactVerified: true, // the email or phone number verified
);
$client->decide(DecideRequest::fromVisit($visit, $ip)->withPath('/signup')->withContext($context));
```

Every Korzen SDK keys the context alike and passes the cases of the API's `contract.json`:
the email's domain an A-label, the address in NFC and lower case, its `+tag` cut,
`gmail.com`'s dots taken out. An address past ASCII needs ext-intl, and is left out
without it. PHP has no UTS #46, so an email whose domain holds a character outside the
Latin, Greek, Cyrillic, Japanese, Chinese and Korean letters (a full-width letter, a
ligature) is left out rather than hashed apart from the other SDKs.

### What each call ended with

`onAnswer: fn (CallAnswer $a) => …` is told of each call, for your logs: its `route`,
`status` (0 when no answer came), `requestId` (`Korzen-Request-Id`, to name when you ask
us about a call), `rateLimit` (the `RateLimit-Policy` and `RateLimit` headers, read by
`RateLimit::parse()`: never wait on them), `problem` (an error answer's
`application/problem+json`, as a `Problem` with its `code`) and `error`. PHP cannot bound
a function it calls, so `onAnswer` is told after the call, never in it: when the request
ends (a shutdown function), or at `$client->flush()`. A slow one costs no decision, and
what it throws is logged once and costs nothing. At most `Client::MAX_HOOKS` (64) answers
wait for it. A long-running worker (RoadRunner, Swoole, FrankenPHP's worker mode), whose
process outlives the request, calls `$client->flush()` after each response.

### Fail open

A hook of yours that throws (an `Exception` or an `Error`), a response that cannot be
built: each lets the request through to your handler, with the decision as
`korzen.decision`, and is logged once through the client's logger, with the error's class
and never its message. Your handler's own exceptions are yours: they go on as they are.

## Your own monitors and scripts: custom rules

A custom rule that allows (the dashboard's Custom rules page) lets your own automation
through before scoring: an uptime monitor, a QA script, a partner's server. A rule matches
a secret header it names, a secret in the User-Agent, your own addresses, a User-Agent's
text, a path, a method and an action, any of them together, or every request. The SDK
sends the User-Agent, the path and the method already; give it the names of the headers
your rules name, and, where one path serves several actions (a GraphQL or RPC endpoint),
the action's name. A header a rule may not name (a cookie, `Authorization`, `Host` and the
others) is never sent, and an action past 256 bytes goes as none.

```php
$app->add(new Middleware(
    $client,
    $app->getResponseFactory(),
    allowRuleHeaders: ['X-Monitor-Key'],
    action: fn ($request): ?string => $request->getHeaderLine('X-Operation') ?: null,
));
```

Calling `decide()` yourself, `DecideRequest::from()` takes `allowRuleHeaders`, and
`withAction()` sets the action.

## First-party mode

A DNS filter, an ad blocker or a network that blocks `korzen.dev` stops the tag, its
beacon, so those visitors are judged with less, and on a `protectedAction` route they are
refused. First-party mode serves both from your own domain, under `/kz` by default, and
forwards them to Bot Protection with the visitor's address. Put the middleware on that
path too, with the same options, and the page loads the tag from it:

```php
// Slim: every route, /kz/* among them
$app->add(new Middleware($client, $app->getResponseFactory(), ip: Ip::lastForwarded(...), firstParty: true));

// Laravel: bind it with the mode on (AppServiceProvider), and route /kz/* through it
// outside the web group, whose session and CSRF check a beacon has no part in
// (bootstrap/app.php)
$this->app->bind(Protect::class, fn ($app) => new Protect($app->make(Client::class), firstParty: true));
->withRouting(web: __DIR__.'/../routes/web.php', then: function () {
    Route::any('/kz/{any}', fn () => abort(404))->where('any', '.*')->middleware(Protect::class);
})
```

```html
<script src="/kz/tag.js" data-site-key="sk_..." async></script>
```

- **What it serves.** `GET /kz/tag.js`, `GET /kz/n`, `POST /kz/s` (a body of at most 64
  KiB), and `GET /kz/ping` (answered `204` by the middleware itself, never forwarded). Any
  other path under `/kz` is a `404`, a known one with another method a `405`; neither
  reaches Bot Protection. A body past its cap is a `413`. The requests under the path are
  never judged and never reach your handler; every other path is judged as before.
- **What it sends.** The browser's `User-Agent`, `Accept`, `Accept-Language`,
  `Content-Type`, `Origin`, `Sec-Fetch-*`, `Sec-CH-*` and `If-None-Match`, your key as the
  bearer, the visitor's address in `Korzen-Visitor-Ip` (read by `ip`, as a decision reads
  it) and the path in `Korzen-Forwarded-Prefix`. Never a `Cookie`, the browser's
  `Authorization` or an `X-Forwarded-*`. What comes back keeps Korzen's caching and
  security headers as Korzen wrote them, never a `Set-Cookie`; a redirect is passed back,
  never followed, and an answer Korzen sent without a `Content-Type` goes back without one
  (the middleware clears PHP's `default_mimetype` for that request).
- **The path.** `firstPartyPath` names another one, for example once a block list learns
  `/kz`: it starts with `/`, ends without one, and is at most 64 characters of
  `A-Z a-z 0-9 . _ ~ -` segments. One that does not read is logged once, and the mode
  stays off.
- **The transport.** The forwards go through the client's transport: `CurlTransport` and
  `StreamTransport` implement `ForwardTransport` too. A `Transport` of yours implements it
  as well, or the mode stays off, logged once.
- **The body, a limit.** PHP runs your script only once the server in front has the whole
  body, so the forwarder never sees a body that trickles or never ends, nor a chunked one
  past the cap that is still arriving. The two conformance cases that send those,
  `first-party-beacon-slow-body` and `first-party-beacon-past-the-cap-chunked`, are
  skipped for PHP. Bound them in the server in front instead: nginx's
  `client_body_timeout` and `client_max_body_size` (64k is enough for `/kz`). A chunked
  body that ends is read and capped as usual (`413`).
- **Fail open.** Bot Protection slow (past 1 s for a GET, 2.5 s for a POST), down or
  answering garbage, no visitor address, no key, an error in the forwarder: a `503` with
  an empty body and `Cache-Control: no-store`. The tag drops that signal and the page goes
  on; your other routes wait on nothing. Bot Protection's own `4xx` and `5xx` pass
  through. A visitor's address on your own network (a proxy's) is logged once.
- **How to tell it works.** In the browser's network tab, the tag's requests go to your
  own `/kz/tag.js`, `/kz/n`, `/kz/ping` and `/kz/s`, none to `korzen.dev`; `/kz/ping`
  answers `204`.

## Supported versions

PHP 8.2, 8.3, 8.4 and 8.5, the releases the PHP project supports. The call goes through
PHP's stream wrapper: https needs the openssl extension, which a PHP that serves https
has.

The guide: https://korzen.dev/bot-protection/docs/php.

## Runtime dependencies

The PSR interfaces, which hold no code of their own; every PSR-15 framework installs them
already:

- `psr/http-message`: PSR-7, the request the SDK reads and the response its middleware
  returns.
- `psr/http-factory`: PSR-17, the response factory the middleware is given to build its
  answer.
- `psr/http-server-middleware`: PSR-15, the interface the middleware implements; it brings
  `psr/http-server-handler`, the next handler's interface.

## Licence

Proprietary: you may use it only to integrate with Korzen while you hold an account. See
[the licence](https://korzen.dev/bot-protection/sdk/license).

# Korzen Bot Protection for PHP

`korzen/bot-protection` asks [Korzen Bot Protection](https://korzen.dev/bot-protection)
about a request before a protected action (`POST /v1/decide`), reports events and feedback
after it (`POST /v1/events`, `POST /v1/feedback`), on API v1, and **fails open**: when Bot
Protection is slow, down, refuses the key or answers anything but a decision, the visitor
goes through. A PSR-15 middleware (Slim, Mezzio, any PSR-15 stack) and a Laravel
middleware; no PHP extension needed, and the PSR interfaces as its only dependencies.

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

The middleware answers a block with 403, sends a challenged page load (GET or HEAD) to the
challenge page and back (and refuses a challenged form post with 403), and otherwise runs
your handler with the decision as the request attribute `korzen.decision` (`null` when
there is none). Guard the page that holds a form too, so a person meets the challenge
there. `$client->decide(DecideRequest::from($request, Ip::socket($request)))` makes the
call alone, for a server that applies the decision itself: it returns a `Decision`, or
`null` on any failure, and never throws. On sign-in, sign-up and checkout, refuse a
`challenge` as a `block` unless your own check (a CAPTCHA, an email or phone code) or the
challenge page runs: never let it through. Most scripts that send a browser's User-Agent
are answered `challenge`, not `block`.

### PSR-15 (Mezzio and others)

`new Middleware($client, $responseFactory, ...)` takes any PSR-17 response factory:
`$app->pipe(...)` it in Mezzio, or add it to any PSR-15 stack.

### Laravel

Bind the client once, alias the middleware, and leave its two cookies unencrypted: the tag
reads `_kz` in the browser, and Laravel would otherwise encrypt it.

```php
// app/Providers/AppServiceProvider.php, in register()
$this->app->singleton(Client::class, fn () => new Client((string) config('services.korzen.key')));

// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->alias(['protect' => \Korzen\BotProtection\Laravel\Protect::class]);
    $middleware->encryptCookies(except: ['_kz', '_kz_c']);
})

// routes/web.php: protect:/signup names the action
Route::post('/signup', SignupController::class)->middleware('protect:/signup');
// In the controller: $request->attributes->get('korzen.decision')
```

`Protect` works on Symfony HttpFoundation's request and response, so it fits any
HttpFoundation stack. For options, bind it:
`$this->app->bind(Protect::class, fn ($app) => new Protect($app->make(Client::class), publicUrl: 'https://shop.example'))`.
Behind a proxy Laravel trusts, `ip: fn ($request) => $request->ip()` sends the visitor's
address.

### Payment, login and sign-up routes

Turn on `requireToken` on the routes a script goes after: the post that charges a card or
places an order, the one that checks a password, the one that creates an account. A script
that never loads your page (card testing from a new residential IP for each try) runs no
tag and is answered `unknown`, which is allowed. With the option, the action needs a token
the tag earned in that browser. Without one, `tokenRequired` is true. In block mode
`action` is then `challenge`, or `allow` when the challenge cannot be issued (fail-open);
in monitor mode `action` stays `allow`. A `block` stays a `block`, and the class does not
change. `tokenRequired` is false while the protection is paused. A page load spends no
token, so guard the form's page too.

```php
$app->post('/checkout', $checkout)->add(new Middleware(
    $client,
    $app->getResponseFactory(),
    requireToken: true, // on actions only: GET, HEAD and OPTIONS spend no token
));
```

Laravel's `Protect` takes the same option: bind it with
`new Protect($app->make(Client::class), requireToken: true)` for the routes that need it.

Start in monitor mode, and watch the share of decisions without a token before you turn on
block mode: a visitor whose browser does not run the tag (an ad blocker, a DNS filter,
JavaScript off) holds no token, and cannot pass the challenge page on these routes. Leave
the option off the routes no page of yours leads to (webhooks, a mobile app's API). More:
https://korzen.dev/bot-protection/docs/protecting-a-checkout.

## Options

Both middlewares take the same options, by name:

| Option           | What it does                                                                                                                                                           |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ip`             | reads the visitor's IP: `Ip::socket(...)` (default), `Ip::lastForwarded(...)`, `Ip::cloudflare(...)`, or yours; the scheme (`http`/`https`) is read from the same edge |
| `path`           | names the action in the decision, instead of the request's path                                                                                                        |
| `onDecoy`        | `fn ($request, Decision $d)` answers a block or a challenge marked `decoy` with your decoy, first; `null` has the default decoy answer (`202` with `{}` on an action)  |
| `onBlock`        | `fn ($request, Decision $d)` answers a blocked request instead of the 403; `null` lets it through                                                                      |
| `onChallenge`    | `fn ($request, Decision $d)` answers a challenged request instead of the redirect; `null` lets it through                                                              |
| `publicUrl`      | the origin your visitors see, behind a proxy that forwards `Host: localhost`; checked at start                                                                         |
| `returnTo`       | `fn ($request): string`, the address to come back to from the challenge page                                                                                           |
| `requireToken`   | sends `require_token` on every action (not GET, HEAD or OPTIONS): the action needs the tag's token                                                                     |
| `firstParty`     | [first-party mode](#first-party-mode): serves `firstPartyPath` and forwards it; off by default                                                                         |
| `firstPartyPath` | the path first-party mode serves, `FirstParty::DEFAULT_PATH` (`/kz`) when `null`                                                                                       |
| `cdn`            | [the CDN in front](#behind-a-cdn) whose headers carry the visitor's JA4: `Cdn::CLOUDFRONT` and the others; none when `null`                                            |

A block or a challenge marked `decoy` (you turned the decoy on for its class on Set-up)
goes to your decoy handler when you give one. Without it, an action (`POST`, `PUT`,
`PATCH`, `DELETE`) is answered `202` with `{}` as `application/json`, an empty success
with no header of Korzen's, and your handler never runs; a page load (`GET`, `HEAD`) is
refused as any other, a `403` or the challenge page, because a blank page would break your
site for a person judged a bot by mistake. Your handler replaces the default.

`decoy` is true only when you turned the decoy on for the class (`bot`, `bot_high`),
`action` is `block` or `challenge`, and what the visitor itself showed is enough for `bot`
or `bot_high`, leaving out what Bot Protection learned from your traffic as a whole and
any absent signal. It is never true for a verified crawler, for `tokenRequired`, for an
identity past its places, for a session that passed the challenge page in the last 30
minutes or could not be checked for it, nor in monitor or paused mode.

The call goes through curl when ext-curl is loaded (`CurlTransport`), else a socket of
PHP's own (`StreamTransport`). Load ext-curl where you can: it bounds the whole call by
the timeout, the name lookup too (a libcurl built with the system's synchronous resolver
gets the name resolved within the time left and pinned). The socket bounds the name lookup
(the hosts file, then the nameservers `/etc/resolv.conf` names, asked over UDP until the
time left runs out: never the system's lookup, which no PHP timeout bounds, but where no
nameserver is named, as on Windows), connecting, the TLS handshake, and every read of the
headers and the body by the time left, so an answer sent a few bytes at a time costs the
visitor no more than the timeout. A `Transport` of yours must keep to the deadline too:
PHP cannot cut a call short, and an answer after it is taken for none (no decision,
nothing recorded) though the visitor waited for it. A batch's retries wait the answer's
`Retry-After`, else the delay doubled each time (at most 2^30 times); a wait past the
batch's time left ends the batch at once, nothing recorded. Measured on 2026-10-22, ten
calls to korzen.dev took 122 ms at the median through curl and 206 ms through PHP's stream
wrapper, with one at 5.3 s. Each call opens its own connection: libcurl sends a POST again
when a kept connection dies before the answer, and a decide sent twice could spend a token
the visitor earned once.

The client is
`new Client($apiKey, url: 'https://korzen.dev', timeoutMs: 200, transport: null, logger: null, onAnswer: null, batchTimeoutMs: 5000, retries: 2, retryDelayMs: 200, sdk: null)`.
The timeout bounds the whole call to `/v1/decide` and is sent as `Korzen-Deadline-Ms`: the
decision takes half, the network the other half. The settings are read once, when the
client is made, and each that does not read is logged once (never the key) and left at its
default, so no setting makes a call throw: the key is trimmed of the spaces and line
breaks around it (an empty one is logged: every call fails open); `url` is an https URL,
or http on loopback (`localhost`, `127.0.0.0/8`, `[::1]`) for a test on your machine, and
any other (http elsewhere would send the key in clear) calls `https://korzen.dev`;
`timeoutMs` is more than 0 and at most 1000 (`Client::MAX_TIMEOUT_MS`), else 200;
`batchTimeoutMs` and `retryDelayMs` are more than 0, and `retries` a whole number from 0
(`null` is the default, 2). An error handed to `onAnswer` never holds the key: one whose
message or trace would is replaced by one that names its class. Every call names its
integration in `Korzen-Sdk`, `Client::SDK` (`php/<Client::VERSION>`) unless `sdk` names
another, as a plugin built on the SDK does (`wordpress/1.0.0`). The logger,
`fn (string $message)`, is told once when the IP sent is on your own network (`error_log`
by default). The helpers the middlewares are made of are public: `DecideRequest::from()`,
`Challenge::url()`, `Challenge::fromChallenge()`, `Challenge::redirect()`,
`Cookies::token()`, `Cookies::challenge()`, `ReturnTo::request()`,
`ReturnTo::publicUrl()`, `Cdn::fields()`.

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

A `Decision` is API v1's answer, its eight members: `action` (apply it alone), `requestId`
(keep it with an order, to send feedback by it), `class`, `botScore`, `mode` (`monitor`,
`block` or `paused`), `challenge` (a `ChallengePage` with its `url` and `passed`, or
`null`), `tokenRequired` and `decoy` (`true` only on a block or a challenge Korzen would
rather answer with your decoy, see `onDecoy`). Any other member of the answer is read
past. Back from the challenge page, only an API v1 token (base64url, up to 160 characters)
is kept as the `_kz` cookie, and the visitor goes on to the address without `kz_token` and
`kz_challenge`, the rest of its query byte for byte: a presigned or an OAuth address keeps
its order and its spelling, so it still verifies. The way there is the address's path and
query alone, a relative `Location`, unless you set `publicUrl` or `returnTo`: a host a
request names (`X-Forwarded-Host`, which a visitor may write) never goes in it, and a path
that opens with `//` or `/\` is one slash, so the visitor stays on your site.

Of two `_kz` cookies (one set for a parent domain by other code) the first in the `Cookie`
header is the token, as the tag and Korzen's server read it: set no `_kz` cookie of your
own for a parent domain, or it shadows the tag's.

The token is read from the `x-korzen-token` header when the page sends one
(`korzen.token()` to an API on another origin, or from a frame, where the cookie does not
travel), else from the `_kz` cookie: you add nothing on the server. A header that is empty
or no token leaves the cookie (`DecideRequest::TOKEN_HEADER`).

### The context

`DecideRequest`'s `context` (or `withContext()`) takes what your server knows of the
person behind the request: `decide()` normalises it and sends only hashes and the fields
in clear, so the raw email, phone, card fingerprint and ids never leave your server. A
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
);
$client->decide(DecideRequest::fromVisit($visit, $ip)->withPath('/signup')->withContext($context));
```

On an action with `requireToken`, the context's `identityId` (the account, a verified
email, a fan id) with `DecideRequest`'s `placesPerIdentity` (1 to 10, 1 when left out) is
how many sessions of one identity may take the path in an hour. Past them, no challenge
page is offered. In block mode `action` is then `challenge`; in monitor mode `action`
stays `allow`. A `block` stays a `block`, and the class does not change. While the
protection is paused, no place is counted.

Every Korzen SDK keys the context alike and passes the cases of the API's `contract.json`:
the email's domain an A-label, the address in NFC and lower case, its `+tag` cut,
`gmail.com`'s dots taken out. An address past ASCII needs ext-intl, and is left out
without it. PHP has no UTS #46, so an email whose domain holds a character outside the
Latin, Greek, Cyrillic, Japanese, Chinese and Korean letters (a full-width letter, a
ligature) is left out rather than hashed apart from the other SDKs.

### Events and feedback

```php
$client->events([new Event('page', path: '/checkout', method: 'GET', ip: $ip)]);
$client->feedback([new Feedback('chargeback', requestId: $order->korzenRequestId)], idempotencyKey: $order->id);
```

Each sends 1 to 1000 items under an `Idempotency-Key` (yours, or a fresh UUID v7) and
sends the batch again under the same key, at most `retries` times within `batchTimeoutMs`,
when it got no answer, a 409, a 429 or a 5xx, waiting `Retry-After` or `retryDelayMs`
doubled each time. They return a `BatchAnswer` (`accepted`, `duplicates`, `rejected`,
`errors`), or `null` when nothing was recorded, and never throw. An `Event` carries a
decision's fields, the edge's too (`ja4`, `httpProtocol`, `tlsGroup`, `country`, `asn`),
each bounded as a decision's is: cut, a `country` longer than 2 bytes left out.

### What each call ended with

`onAnswer: fn (CallAnswer $a) => …` is told of each call, for your logs: its `route`,
`status` (0 when no answer came), `requestId` (`Korzen-Request-Id`, to name when you ask
us about a call), `rateLimit` (the `RateLimit-Policy` and `RateLimit` headers, read by
`RateLimit::parse()`: never wait on them), `replayed`, `problem` (an error answer's
`application/problem+json`, as a `Problem` with its `code`) and `error`. PHP cannot bound
a function it calls, so `onAnswer` is told after the call, never in it: when the request
ends (a shutdown function), or at `$client->flush()`. A slow one costs no decision, and
what it throws is logged once and costs nothing. At most `Client::MAX_HOOKS` (64) answers
wait for it. A long-running worker (RoadRunner, Swoole, FrankenPHP's worker mode), whose
process outlives the request, calls `$client->flush()` after each response.

### Fail open

A hook of yours that throws (an `Exception` or an `Error`), a challenge page that is no
`http(s)` URL of visible ASCII within 2048 characters, a response that cannot be built:
each lets the request through to your handler, with the decision as `korzen.decision`, and
is logged once through the client's logger, with the error's class and never its message.
Your handler's own exceptions are yours: they go on as they are.

## First-party mode

A DNS filter, an ad blocker or a network that blocks `korzen.dev` stops the tag, its
beacon and the challenge page, so those visitors are judged with less, and on a
`requireToken` route they cannot pass. First-party mode serves all three from your own
domain, under `/kz` by default, and forwards them to Bot Protection with the visitor's
address. Put the middleware on that path too, with the same options, and the page loads
the tag from it:

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
  KiB), `GET /kz/ping` (answered `204` by the middleware itself, never forwarded),
  `GET`/`POST /kz/challenge` (a post of at most 16 KiB), `GET /kz/challenge/wait` and
  `GET /kz/static/<file>`. Any other path under `/kz` is a `404`, a known one with another
  method a `405`; neither reaches Bot Protection. A body past its cap is a `413`. The
  requests under the path are never judged and never reach your handler; every other path
  is judged as before.
- **What it sends.** The browser's `User-Agent`, `Accept`, `Accept-Language`,
  `Content-Type`, `Origin`, `Sec-Fetch-*`, `Sec-CH-*` and `If-None-Match`, your key as the
  bearer, the visitor's address in `Korzen-Visitor-Ip` (read by `ip`, as a decision reads
  it) and the path in `Korzen-Forwarded-Prefix`. Never a `Cookie`, the browser's
  `Authorization` or an `X-Forwarded-*`. What comes back keeps Korzen's caching and
  security headers as Korzen wrote them, never a `Set-Cookie`; a redirect is passed back,
  never followed, and an answer Korzen sent without a `Content-Type` goes back without one
  (the middleware clears PHP's `default_mimetype` for that request).
- **The challenge page.** A challenged page load goes to `/kz/challenge?c=…&r=…` on your
  domain instead of `korzen.dev`, so a visitor who cannot reach `korzen.dev` still solves
  it. An `onChallenge` hook that sends the visitor itself gives your path to
  `Challenge::redirect($decision, $returnTo, '/kz')`: Korzen's `/challenge` goes under it
  with its query, a page elsewhere is kept, and a path that does not read is none.
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

## Licence

Proprietary: you may use it only to integrate with Korzen while you hold an account. See
[the licence](https://korzen.dev/bot-protection/sdk/license).

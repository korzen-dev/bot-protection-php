<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The CDNs whose own headers carry the visitor's JA4 and, on CloudFront, their header order
 * and HTTP version to your server, by the name the cdn option of Middleware and Protect
 * takes. Anyone can send these headers to a server reachable around its CDN, so they are
 * read only under the CDN you name: name one only when your server takes traffic from it
 * alone, as with the ip option. The API's contract.json (decide.cdn) holds them and the
 * cases, which every SDK passes; the other SDKs name them alike.
 */
final class Cdn
{
    /**
     * Amazon CloudFront: add CloudFront-Viewer-JA4-Fingerprint,
     * CloudFront-Viewer-Header-Order and CloudFront-Viewer-Http-Version to the origin
     * request policy.
     */
    public const CLOUDFRONT = 'cloudfront';

    /** Azure Front Door: X-Azure-JA4-Fingerprint. */
    public const AZURE_FRONT_DOOR = 'azure_front_door';

    /** Vercel: x-vercel-ja4-digest, on every plan. */
    public const VERCEL = 'vercel';

    /** bunny.net: CDN-JA4. */
    public const BUNNY = 'bunny';

    /**
     * Google Cloud's load balancer: a custom request header
     * X-Client-JA4: {tls_ja4_fingerprint} on the backend service.
     */
    public const GOOGLE_CLOUD = 'google_cloud';

    /** Fastly: set req.http.X-Client-JA4 = tls.client.ja4; in vcl_recv. */
    public const FASTLY = 'fastly';

    /**
     * Each CDN's headers, lower-cased: the JA4's, and the header order's and HTTP version's
     * where it forwards them (null where it does not).
     */
    public const HEADERS = [
        self::CLOUDFRONT => [
            'ja4' => 'cloudfront-viewer-ja4-fingerprint',
            'header_order' => 'cloudfront-viewer-header-order',
            'http_version' => 'cloudfront-viewer-http-version',
        ],
        self::AZURE_FRONT_DOOR => ['ja4' => 'x-azure-ja4-fingerprint', 'header_order' => null, 'http_version' => null],
        self::VERCEL => ['ja4' => 'x-vercel-ja4-digest', 'header_order' => null, 'http_version' => null],
        self::BUNNY => ['ja4' => 'cdn-ja4', 'header_order' => null, 'http_version' => null],
        self::GOOGLE_CLOUD => ['ja4' => 'x-client-ja4', 'header_order' => null, 'http_version' => null],
        self::FASTLY => ['ja4' => 'x-client-ja4', 'header_order' => null, 'http_version' => null],
    ];

    /**
     * A JA4 (TLS client) as FoxIO's specification writes it; JA4H and JA4T, under FoxIO's
     * commercial licence, are never read.
     */
    public const JA4_PATTERN = '/^[tqd][0-9a-z]{2}[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/D';

    /** One header's name in a CDN's header order, lower-cased: an HTTP token. */
    public const ORDER_NAME_PATTERN = "/^[!#$%&'*+.^_`|~0-9a-z-]{1,64}$/D";

    /** A CDN's HTTP versions, without "http/", as decide's http_protocol. */
    public const HTTP_VERSIONS = ['1.0' => 'h1', '1.1' => 'h1', '2' => 'h2', '2.0' => 'h2', '3' => 'h3', '3.0' => 'h3'];

    /**
     * $into (an empty request when null) with its ja4, headerOrder and httpProtocol read
     * from what the CDN named $cdn forwarded of the visitor in $request's headers, each only
     * when $into has none: a field you set wins. A $cdn not of HEADERS (null, '', another
     * name) reads nothing. A value that does not read (a JA4 outside its pattern, a header
     * sent twice, an order with a name that is no token, a version not listed) is left out:
     * an absent field is never evidence. It never throws. The middlewares call it with
     * their cdn option.
     */
    public static function fields(
        ServerRequestInterface|Request $request,
        ?string $cdn,
        ?DecideRequest $into = null,
    ): DecideRequest {
        return self::fill(Visit::of($request), $cdn, $into ?? new DecideRequest());
    }

    /** @internal */
    public static function fill(Visit $v, ?string $cdn, DecideRequest $into): DecideRequest
    {
        $c = self::HEADERS[$cdn ?? ''] ?? null;
        if ($c === null) {
            return $into;
        }
        // A header sent twice reads as its values joined by ", ", which none of the three
        // reads: the visitor's beside the CDN's, neither is taken.
        $ja4 = trim($v->header($c['ja4']));
        $order = $c['header_order'] === null ? [] : self::order($v->header($c['header_order']));
        $version = $c['http_version'] === null ? '' : strtolower(trim($v->header($c['http_version'])));
        if (str_starts_with($version, 'http/')) {
            $version = substr($version, 5);
        }

        return $into->withCdn(
            preg_match(self::JA4_PATTERN, $ja4) === 1 ? $ja4 : null,
            $order,
            self::HTTP_VERSIONS[$version] ?? null,
        );
    }

    /**
     * A CDN's header order, its names trimmed and lower-cased, the first MAX_ORDER kept;
     * empty when it is absent or a name is no HTTP token.
     *
     * @return list<string>
     */
    private static function order(string $value): array
    {
        // A comma is the header sent twice and joined, which the names kept may not show.
        if ($value === '' || str_contains($value, ',')) {
            return [];
        }
        $names = [];
        foreach (\array_slice(explode(':', $value), 0, Bounds::MAX_ORDER) as $name) {
            $name = strtolower(trim($name));
            if (preg_match(self::ORDER_NAME_PATTERN, $name) !== 1) {
                return [];
            }
            $names[] = $name;
        }

        return $names;
    }
}

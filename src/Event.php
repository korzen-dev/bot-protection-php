<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * One request your server saw, after the fact (POST /v1/events): a decision's fields but
 * claims and requireToken, and kind. events() cuts each field as decide() cuts them.
 */
final readonly class Event
{
    /**
     * @param string $kind page, for a page a person loads, or api, for a call a script makes
     * @param int|null $tsMs when the request came, in Unix milliseconds; now when null
     * @param array<array-key, string> $headers lower-cased names
     * @param list<string> $headerOrder
     * @param int|null $status the status your server answered; with $requestId, the event
     *     reports only that
     * @param string|null $requestId the request_id of the decision this event answers
     * @param string|null $eventId your id for the event: sent again within 20 minutes, it
     *     changes nothing
     * @param string|null $ja4 the TLS fingerprint, from an edge that has it, as a decision's
     * @param string|null $httpProtocol h1, h2 or h3
     * @param string|null $country ISO 3166 alpha-2
     * @param int|null $asn the autonomous system number
     * @param string|null $scheme the scheme the request came on, http or https, as a
     *     decision's
     */
    public function __construct(
        public string $kind,
        public ?int $tsMs = null,
        public ?string $ip = null,
        public ?string $userAgent = null,
        public array $headers = [],
        public array $headerOrder = [],
        public ?string $token = null,
        public ?string $path = null,
        public ?string $method = null,
        public ?int $status = null,
        public ?string $requestId = null,
        public ?string $eventId = null,
        public ?string $ja4 = null,
        public ?string $httpProtocol = null,
        public ?string $tlsGroup = null,
        public ?string $country = null,
        public ?int $asn = null,
        public ?string $scheme = null,
    ) {}
}

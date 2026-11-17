<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * What your server knows of the person behind a decision, every field optional and raw:
 * decide() normalises and hashes it, so the raw email, phone, card fingerprint and ids never
 * leave your server. A value that does not read as its kind is left out, never sent and
 * never an error: an absent field is never evidence of a bot. Every Korzen SDK keys the
 * context alike.
 */
final readonly class Context
{
    /**
     * The phone types the API reads, libphonenumber's PhoneNumberType in lower case. A
     * carrier lookup's types map onto them: Twilio's nonFixedVoip is voip, its fixedVoip and
     * landline fixed_line.
     */
    public const PHONE_TYPES = [
        'mobile',
        'fixed_line',
        'fixed_line_or_mobile',
        'voip',
        'toll_free',
        'premium_rate',
        'shared_cost',
        'personal_number',
        'pager',
        'uan',
        'voicemail',
        'unknown',
    ];

    /**
     * @param string|null $email the address as the person typed it: its domain is sent, and
     *     the address hashed, both normalised (the domain an A-label, the local part in NFC
     *     and lower case, +tags cut, gmail.com's dots taken out). An address past ASCII needs
     *     ext-intl, and one whose domain this SDK cannot map as a URL's host does is left out.
     * @param string|null $phone the number in E.164 (+31612345678), spaces, dashes, dots and
     *     brackets allowed: hashed
     * @param string|null $phoneCountry the number's region, ISO 3166-1 alpha-2, from your
     *     phone library
     * @param string|null $phoneType the number's type, one of PHONE_TYPES; any other is left out
     * @param string|null $cardBin the card's first 6 to 8 digits: the first six are sent. More
     *     than 8 may be a card number: left out, and logged once.
     * @param string|null $cardFingerprint your payment provider's fingerprint of the card
     *     (Stripe's card.fingerprint), 1 to 128 bytes: hashed
     * @param string|null $accountId your id of the account, 1 to 256 bytes: hashed
     * @param string|null $resourceId your id of what the action is on (the order, listing or
     *     queue), 1 to 256 bytes: hashed
     * @param string|null $identityId your id of what you limit places by on a required action
     *     (the account, a verified email, a fan id), 1 to 256 bytes: hashed. With requireToken
     *     and placesPerIdentity.
     */
    public function __construct(
        public ?string $email = null,
        public ?string $phone = null,
        public ?string $phoneCountry = null,
        public ?string $phoneType = null,
        public ?string $cardBin = null,
        public ?string $cardFingerprint = null,
        public ?string $accountId = null,
        public ?string $resourceId = null,
        public ?string $identityId = null,
    ) {}
}

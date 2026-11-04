<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * A Context as decide() sends it: each field normalised, the identifiers hashed, a field
 * that does not read left out. Every Korzen SDK keys the context alike, as the Node SDK
 * does, and passes the cases of the API's contract.json.
 *
 * PHP has no UTS #46 of its own (ext-intl's idn_to_ascii is ICU's, its version the
 * system's): a domain is mapped here only when every character is one whose mapping is
 * plain (a letter of the scripts below, lowered, in NFC, which UTS #46 keeps as it is), and
 * an email whose domain holds any other is left out, so it is never hashed apart from Node.
 * Past ASCII it needs ext-intl (Normalizer, IntlChar); without it such an email is left out.
 *
 * @internal
 */
final class ContextFields
{
    public const MAX_DOMAIN = 253; // an email domain's bytes
    public const MAX_LABEL = 63; // a label's bytes
    public const MAX_CARD_FINGERPRINT = 128; // a card fingerprint's bytes
    public const MAX_ID = 256; // an account's, a resource's or an identity's id, in bytes
    public const BIN_DIGITS = 6; // a card's BIN: the first six digits, never more
    public const MAX_BIN_GIVEN = 8; // past these digits it may be a card number

    private const ACE = 'xn--';
    private const CAPITAL_SIGMA = 0x03A3;
    private const SMALL_SIGMA = 0x03C3;
    private const FINAL_SIGMA = 0x03C2;
    private const DOTTED_CAPITAL_I = 0x0130;

    /**
     * What JavaScript's trim takes away (ECMAScript's WhiteSpace and LineTerminator): the
     * ASCII controls tab to carriage return, the Unicode space separators, U+2028, U+2029
     * and U+FEFF; not U+001C to U+001F nor U+0085.
     */
    private const JS_SPACE = '[\x{9}-\x{D}\x{20}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}'
        . '\x{3000}\x{FEFF}]';

    /**
     * The scripts whose letters a domain may hold, by code point: each was in Unicode by
     * 11.0, none is written right to left (so UTS #46's Bidi rule never applies), and none
     * holds a joiner (its ContextJ rule).
     */
    private const SCRIPTS = [
        [0x00C0, 0x024F], // Latin-1's letters, Latin Extended-A and -B
        [0x0300, 0x036F], // Combining Diacritical Marks
        [0x0370, 0x03FF], // Greek and Coptic
        [0x0400, 0x04FF], // Cyrillic
        [0x1E00, 0x1EFF], // Latin Extended Additional
        [0x3041, 0x30FF], // Hiragana and Katakana
        [0x4E00, 0x9FEF], // CJK Unified Ideographs, as of Unicode 11.0
        [0xAC00, 0xD7A3], // Hangul Syllables
    ];

    /**
     * Characters of those scripts whose UTS #46 mapping is not their lower case: U+0130,
     * the dotted capital I (to "i" and U+0307), U+1E9E, the capital sharp s (to "ss" or
     * U+00DF, by Unicode's version), U+0345, the ypogegrammeni (to iota) and U+034F, the
     * grapheme joiner (taken out).
     */
    private const UNSURE = [0x0130, 0x1E9E, 0x0345, 0x034F];

    /**
     * $context as decide() sends it, in the API's field names; empty when no field is left.
     * $onCardNumber is told when card_bin had more digits than a BIN: it may be a card
     * number, and is left out.
     *
     * @param callable(): void $onCardNumber
     *
     * @return array<string, string>
     */
    public static function fields(?Context $context, callable $onCardNumber): array
    {
        if ($context === null) {
            return [];
        }
        $out = [];
        $email = self::normalEmail($context->email);
        if ($email !== null) {
            $out['email_domain'] = $email[1];
            $out['email_hash'] = self::hash('email', $email[0]);
        }
        $phone = self::normalPhone($context->phone);
        if ($phone !== null) {
            $out['phone_hash'] = self::hash('phone', $phone);
        }
        $country = $context->phoneCountry;
        if ($country !== null && preg_match('/^[A-Za-z]{2}$/D', $country) === 1) {
            $out['phone_country'] = strtoupper($country);
        }
        if ($context->phoneType !== null && \in_array($context->phoneType, Context::PHONE_TYPES, true)) {
            $out['phone_type'] = $context->phoneType;
        }
        $bin = self::cardBin($context->cardBin, $onCardNumber);
        if ($bin !== null) {
            $out['card_bin'] = $bin;
        }
        $ids = [
            ['card_fingerprint_hash', 'card', $context->cardFingerprint, self::MAX_CARD_FINGERPRINT],
            ['account_hash', 'account', $context->accountId, self::MAX_ID],
            ['resource_hash', 'resource', $context->resourceId, self::MAX_ID],
            ['identity_hash', 'identity', $context->identityId, self::MAX_ID],
        ];
        foreach ($ids as [$wire, $kind, $given, $most]) {
            if ($given !== null && $given !== '' && \strlen($given) <= $most) {
                $out[$wire] = self::hash($kind, $given);
            }
        }

        return $out;
    }

    /** hex(SHA-256("kz1:" . $kind . ":" . $value)), lower case: the wire hash. */
    public static function hash(string $kind, string $value): string
    {
        return hash('sha256', "kz1:{$kind}:{$value}");
    }

    /**
     * An address as the API hashes it, and its domain; null when it is no address, or one
     * this SDK cannot normalise as the others do. It is trimmed as JavaScript trims, split
     * at its last "@", the domain an A-label, the local part in NFC and lower case, cut at
     * its first "+" and, at gmail.com, without its dots (unless that leaves it empty).
     *
     * @return array{string, string}|null
     */
    public static function normalEmail(?string $raw): ?array
    {
        // No UTF-8; or, without ext-intl, past ASCII or an A-label, which this SDK maps only with it.
        if (
            $raw === null
            || preg_match('//u', $raw) !== 1
            || (!self::unicode() && preg_match('/[\x80-\xff]|xn--/i', $raw) === 1)
        ) {
            return null;
        }
        $s = (string) preg_replace('/^' . self::JS_SPACE . '+|' . self::JS_SPACE . '+$/uD', '', $raw);
        $at = strrpos($s, '@');
        if ($at === false || $at === 0 || $at === \strlen($s) - 1) {
            return null;
        }
        $domain = self::emailDomain(substr($s, $at + 1));
        if ($domain === null) {
            return null;
        }
        $local = self::lower(substr($s, 0, $at));
        $plus = strpos($local, '+');
        if ($plus !== false && $plus > 0) {
            $local = substr($local, 0, $plus);
        }
        $undotted = str_replace('.', '', $local);
        if ($domain === 'gmail.com' && $undotted !== '') {
            $local = $undotted;
        }

        return ["{$local}@{$domain}", $domain];
    }

    /**
     * A number in E.164, its spaces, dashes, dots and brackets taken out; null when that is
     * no "+" and 7 to 15 digits.
     */
    public static function normalPhone(?string $raw): ?string
    {
        if ($raw === null) {
            return null;
        }
        $s = str_replace([' ', '-', '.', '(', ')'], '', $raw);

        return preg_match('/^\+[0-9]{7,15}$/D', $s) === 1 ? $s : null;
    }

    /**
     * The BIN decide() sends of $given, its first six digits; null when it is none.
     * $onCardNumber is told when it had more digits than a BIN.
     *
     * @param callable(): void $onCardNumber
     */
    private static function cardBin(?string $given, callable $onCardNumber): ?string
    {
        if ($given === null || preg_match('/^[0-9]+$/D', $given) !== 1) {
            return null;
        }
        if (\strlen($given) > self::MAX_BIN_GIVEN) {
            $onCardNumber();

            return null;
        }

        return \strlen($given) >= self::BIN_DIGITS ? substr($given, 0, self::BIN_DIGITS) : null;
    }

    /** Whether this PHP can normalise and lower past ASCII: it has ext-intl. */
    public static function unicode(): bool
    {
        return class_exists(\Normalizer::class, false) && class_exists(\IntlChar::class, false);
    }

    /**
     * $s, valid UTF-8, in NFC and in lower case as JavaScript's toLowerCase gives it: the
     * full mapping (U+0130 to "i" and U+0307), a capital sigma at a word's end as the final
     * one, by Unicode's Final_Sigma. Past ASCII it needs ext-intl.
     */
    public static function lower(string $s): string
    {
        if (preg_match('/[\x80-\xff]/', $s) !== 1) {
            return strtolower($s);
        }
        $cps = self::codePoints(self::nfc($s));
        $out = '';
        foreach ($cps as $k => $cp) {
            $out .= match (true) {
                $cp === self::DOTTED_CAPITAL_I => "i\xCC\x87",
                $cp === self::CAPITAL_SIGMA => self::chr(
                    self::finalSigma($cps, $k) ? self::FINAL_SIGMA : self::SMALL_SIGMA,
                ),
                default => self::chr((int) \IntlChar::tolower($cp)),
            };
        }

        return $out;
    }

    /**
     * Whether the capital sigma at $i of $cps is at a word's end, as Unicode's Final_Sigma
     * reads it: a cased letter before it and none after it, case-ignorable ones skipped
     * both ways.
     *
     * @param list<int> $cps
     */
    private static function finalSigma(array $cps, int $i): bool
    {
        $before = $i - 1;
        while ($before >= 0 && \IntlChar::hasBinaryProperty($cps[$before] ?? 0, \IntlChar::PROPERTY_CASE_IGNORABLE)) {
            --$before;
        }
        if ($before < 0 || !\IntlChar::hasBinaryProperty($cps[$before] ?? 0, \IntlChar::PROPERTY_CASED)) {
            return false;
        }
        $after = $i + 1;
        $n = \count($cps);
        while ($after < $n && \IntlChar::hasBinaryProperty($cps[$after] ?? 0, \IntlChar::PROPERTY_CASE_IGNORABLE)) {
            ++$after;
        }

        return $after === $n || !\IntlChar::hasBinaryProperty($cps[$after] ?? 0, \IntlChar::PROPERTY_CASED);
    }

    /**
     * An email's domain as an A-label, lower case, without its trailing dot; googlemail.com
     * is gmail.com; null when it is no domain as the API reads it.
     */
    private static function emailDomain(string $host): ?string
    {
        $labels = [];
        foreach (explode('.', $host) as $label) {
            $a = self::aLabel($label);
            if ($a === null) {
                return null;
            }
            $labels[] = $a;
        }
        $domain = implode('.', $labels);
        if (str_ends_with($domain, '.')) {
            $domain = substr($domain, 0, -1);
        }
        if ($domain === 'googlemail.com') {
            $domain = 'gmail.com';
        }

        return self::ldh($domain) && !self::endsInNumber($domain) ? $domain : null;
    }

    /**
     * $label as an A-label, as a URL's host maps it; null when it cannot be mapped here
     * alike (uLabel), or UTS #46 refuses it.
     */
    private static function aLabel(string $label): ?string
    {
        if (preg_match('/[\x80-\xff]/', $label) !== 1) {
            $lower = strtolower($label);
            if (!str_starts_with($lower, self::ACE)) {
                return $lower;
            }
            // An A-label is kept only as it is made here: it decodes to a label that maps
            // to itself, and encodes back to itself.
            $u = self::decode(substr($lower, \strlen(self::ACE)));
            if ($u === null || preg_match('/[\x80-\xff]/', $u) !== 1 || self::uLabel($u) !== $u) {
                return null;
            }

            return $lower === self::ACE . self::encode($u) ? $lower : null;
        }
        $mapped = self::uLabel($label);
        if ($mapped === null || str_starts_with($mapped, self::ACE)) {
            return null;
        }

        return self::ACE . self::encode($mapped);
    }

    /**
     * $label, valid UTF-8, as UTS #46 maps it, lowered and in NFC; null unless every
     * character's mapping is plain (plain()). It needs ext-intl.
     */
    private static function uLabel(string $label): ?string
    {
        $lowered = '';
        foreach (self::codePoints($label) as $cp) {
            if ($cp >= 0x80 && !self::plain($cp)) {
                return null;
            }
            $lowered .= self::chr((int) \IntlChar::tolower($cp));
        }
        $mapped = self::nfc($lowered);
        $cps = self::codePoints($mapped);
        foreach ($cps as $cp) {
            if ($cp >= 0x80 && !(self::plain($cp) && self::letter($cp))) {
                return null;
            }
        }
        if ($cps !== [] && \IntlChar::charType($cps[0]) === \IntlChar::CHAR_CATEGORY_NON_SPACING_MARK) {
            return null;
        }

        return $mapped;
    }

    /**
     * Whether UTS #46 maps $cp as its lower case: one of SCRIPTS, not in UNSURE, that NFKC
     * leaves as it is.
     */
    private static function plain(int $cp): bool
    {
        if (\in_array($cp, self::UNSURE, true)) {
            return false;
        }
        foreach (self::SCRIPTS as [$low, $high]) {
            if ($cp >= $low && $cp <= $high) {
                $ch = self::chr($cp);

                return \Normalizer::normalize($ch, \Normalizer::FORM_KC) === $ch;
            }
        }

        return false;
    }

    /**
     * Whether $cp may be a label's own character, once lowered: a lower-case, other or
     * modifier letter, or a non-spacing mark (never first).
     */
    private static function letter(int $cp): bool
    {
        return \in_array(\IntlChar::charType($cp), [
            \IntlChar::CHAR_CATEGORY_LOWERCASE_LETTER,
            \IntlChar::CHAR_CATEGORY_OTHER_LETTER,
            \IntlChar::CHAR_CATEGORY_MODIFIER_LETTER,
            \IntlChar::CHAR_CATEGORY_NON_SPACING_MARK,
        ], true);
    }

    /**
     * Whether $domain is one as the API reads it: lower-case LDH labels, each 1 to 63
     * bytes, neither starting nor ending with "-", at most 253 bytes in all.
     */
    private static function ldh(string $domain): bool
    {
        if (\strlen($domain) > self::MAX_DOMAIN) {
            return false;
        }
        foreach (explode('.', $domain) as $label) {
            if (\strlen($label) > self::MAX_LABEL || preg_match('/^[a-z0-9-]+$/D', $label) !== 1
                || str_starts_with($label, '-') || str_ends_with($label, '-')) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether $domain's last label is a number as the URL Standard reads one: digits
     * alone, or "0x" and hex digits. A URL's host reads it as an IPv4 address, which no
     * address's domain is.
     */
    private static function endsInNumber(string $domain): bool
    {
        $dot = strrpos($domain, '.');
        $last = $dot === false ? $domain : substr($domain, $dot + 1);
        if (str_starts_with($last, '0x')) {
            return preg_match('/^[0-9a-f]*$/D', substr($last, 2)) === 1;
        }

        return preg_match('/^[0-9]+$/D', $last) === 1;
    }

    /**
     * The code points of $s, valid UTF-8.
     *
     * @return list<int>
     */
    private static function codePoints(string $s): array
    {
        $chars = preg_split('//u', $s, -1, \PREG_SPLIT_NO_EMPTY);

        return array_map(static fn(string $c): int => \IntlChar::ord($c), $chars === false ? [] : $chars);
    }

    /** $cp in UTF-8. */
    private static function chr(int $cp): string
    {
        return \IntlChar::chr($cp);
    }

    /** $s, valid UTF-8, in NFC; Normalizer fails only on invalid UTF-8. */
    private static function nfc(string $s): string
    {
        $nfc = \Normalizer::normalize($s, \Normalizer::FORM_C);

        return \is_string($nfc) ? $nfc : '';
    }

    private static function adapt(int $delta, int $points, bool $first): int
    {
        $delta = intdiv($delta, $first ? 700 : 2); // Punycode's damp
        $delta += intdiv($delta, $points);
        $k = 0;
        while ($delta > intdiv(35 * 26, 2)) {
            $delta = intdiv($delta, 35);
            $k += 36;
        }

        return $k + intdiv(36 * $delta, $delta + 38); // its skew
    }

    private static function threshold(int $k, int $bias): int
    {
        return $k <= $bias ? 1 : ($k >= $bias + 26 ? 26 : $k - $bias);
    }

    private static function digit(int $d): string
    {
        return \chr($d < 26 ? 0x61 + $d : 0x30 + $d - 26);
    }

    /** $s, valid UTF-8, in Punycode (RFC 3492): base 36, tmin 1, tmax 26. It needs ext-intl. */
    private static function encode(string $s): string
    {
        $cps = self::codePoints($s);
        $out = '';
        foreach ($cps as $cp) {
            if ($cp < 0x80) {
                $out .= \chr($cp);
            }
        }
        $basic = \strlen($out);
        $handled = $basic;
        if ($basic > 0) {
            $out .= '-';
        }
        $n = 0x80;
        $delta = 0;
        $bias = 72;
        while ($handled < \count($cps)) {
            $m = \PHP_INT_MAX;
            foreach ($cps as $cp) {
                $m = $cp >= $n ? min($m, $cp) : $m;
            }
            $delta += ($m - $n) * ($handled + 1);
            $n = $m;
            foreach ($cps as $cp) {
                if ($cp < $n) {
                    ++$delta;
                }
                if ($cp !== $n) {
                    continue;
                }
                $q = $delta;
                for ($k = 36;; $k += 36) {
                    $t = self::threshold($k, $bias);
                    if ($q < $t) {
                        break;
                    }
                    $out .= self::digit($t + ($q - $t) % (36 - $t));
                    $q = intdiv($q - $t, 36 - $t);
                }
                $out .= self::digit($q);
                $bias = self::adapt($delta, $handled + 1, $handled === $basic);
                $delta = 0;
                ++$handled;
            }
            ++$delta;
            ++$n;
        }

        return $out;
    }

    /**
     * The UTF-8 that $s, ASCII in lower case, encodes in Punycode; null when it is none. It
     * needs ext-intl.
     */
    private static function decode(string $s): ?string
    {
        $dash = strrpos($s, '-');
        $b = $dash === false ? 0 : $dash;
        $out = [];
        for ($k = 0; $k < $b; ++$k) {
            $out[] = \ord($s[$k]);
        }
        $n = 0x80;
        $i = 0;
        $bias = 72;
        $len = \strlen($s);
        for ($at = $b > 0 ? $b + 1 : 0; $at < $len;) {
            $old = $i;
            $w = 1;
            for ($k = 36;; $k += 36) {
                if ($at >= $len) {
                    return null;
                }
                $c = \ord($s[$at++]);
                $d = match (true) {
                    $c >= 0x61 && $c <= 0x7A => $c - 0x61,
                    $c >= 0x30 && $c <= 0x39 => $c - 0x30 + 26,
                    default => -1,
                };
                if ($d < 0) {
                    return null;
                }
                $i += $d * $w;
                if ($i > 0x7FFFFFFF) {
                    return null;
                }
                $t = self::threshold($k, $bias);
                if ($d < $t) {
                    break;
                }
                $w *= 36 - $t;
            }
            $bias = self::adapt($i - $old, \count($out) + 1, $old === 0);
            $n += intdiv($i, \count($out) + 1);
            $i %= \count($out) + 1;
            if ($n > 0x10FFFF || ($n >= 0xD800 && $n <= 0xDFFF)) {
                return null;
            }
            array_splice($out, $i, 0, [$n]);
            ++$i;
        }

        return implode('', array_map(self::chr(...), $out));
    }
}

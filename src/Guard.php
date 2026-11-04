<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * The middleware's steps, the same in every framework: back from the challenge page, the
 * decision, and what it makes of it.
 *
 * @internal
 */
final class Guard
{
    /**
     * The methods the default decoy answers, as sent (a method is case-sensitive, RFC 9110
     * §9.1). A page load (GET, HEAD) keeps its refusal: a blank page would break the site
     * for a person judged wrong.
     */
    private const ACTIONS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    /**
     * @param string $returnTo the address asked for, to come back to; '' when there is none
     * @param bool   $relative whether the way back from the challenge page is the address's
     *     path and query alone, so a host a request wrote never goes in the Location
     * @param string|null $scheme the scheme the request came on (Ip::schemeOf); none when null
     * @param string $firstParty first-party mode's path, where a challenged page load goes to
     *     Korzen's challenge page (FirstParty::location); '' when the mode is off
     * @param string|null $cdn the CDN named by the cdn option, whose headers are read (Cdn::fields)
     */
    public static function run(
        Client $client,
        Visit $visit,
        ?string $ip,
        ?string $path,
        string $returnTo,
        bool $onBlock,
        bool $onChallenge,
        bool $requireToken = false,
        bool $onDecoy = false,
        bool $relative = false,
        ?string $scheme = null,
        string $firstParty = '',
        ?string $cdn = null,
        ?string $ipFrom = null,
    ): Outcome {
        if ($visit->pageLoad()) {
            $back = Challenge::back($returnTo, $visit->cookie(Cookies::CHALLENGE) !== null, $relative);
            if ($back !== null) {
                return Outcome::seeOther(null, $back['location'], $back['cookies']);
            }
        }
        $request = DecideRequest::fromVisit($visit, $ip, $scheme, $cdn, $ipFrom);
        if ($path !== null && $path !== '') {
            $request = $request->withPath($path);
        }
        // A page load spends no token, so the page that shows a form leaves the form's post its own.
        if ($requireToken && !\in_array($visit->method, ['GET', 'HEAD', 'OPTIONS'], true)) {
            $request = $request->withRequireToken(true);
        }
        $d = $client->decide($request);
        $o = self::answer($d, $visit, $returnTo, $onBlock, $onChallenge, $firstParty);
        $decoyed = $d !== null && $d->decoy
            && \in_array($d->action, [Decision::BLOCK, Decision::CHALLENGE], true);
        if (!$decoyed) {
            return $o;
        }
        // An action refused with a decoy gets the default decoy, before onBlock and
        // onChallenge: 202 with {}, an empty success. A page load keeps its refusal.
        if (\in_array($visit->method, self::ACTIONS, true)) {
            $o = Outcome::accepted($d);
        }

        // A refusal Korzen would rather meet with the customer's decoy goes to it first.
        return $onDecoy ? Outcome::decoy($d, $o) : $o;
    }

    /** What the decision makes of the request, without a decoy. */
    private static function answer(
        ?Decision $d,
        Visit $visit,
        string $returnTo,
        bool $onBlock,
        bool $onChallenge,
        string $firstParty,
    ): Outcome {
        if ($d?->action === Decision::BLOCK) {
            return $onBlock ? Outcome::hook($d, 'block') : Outcome::forbidden($d);
        }
        if ($d?->action === Decision::CHALLENGE) {
            if ($onChallenge) {
                return Outcome::hook($d, 'challenge');
            }
            // A form post or an API call under challenge is refused: the protected action is
            // the post, and a person meets the challenge on the page that holds the form.
            if (!$visit->pageLoad()) {
                return Outcome::forbidden($d);
            }
            $to = Challenge::redirect($d, $returnTo, $firstParty);
            if ($to !== null) {
                return Outcome::seeOther($d, $to['location'], [$to['cookie']]);
            }
        }

        return Outcome::pass($d);
    }
}

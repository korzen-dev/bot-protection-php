<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * The middleware's steps, the same in every framework: the decision, and what it makes of
 * it.
 *
 * @internal
 */
final class Guard
{
    /**
     * @param string|null $scheme the scheme the request came on (Ip::schemeOf); none when null
     * @param string|null $cdn the CDN named by the cdn option, whose headers are read (Cdn::fields)
     * @param list<string> $allowRuleHeaders the headers the custom rules name, sent when the request carries them
     * @param string|null $action the action's name as the custom rules name it; none when null
     */
    public static function run(
        Client $client,
        Visit $visit,
        ?string $ip,
        ?string $path,
        bool $onBlock,
        bool $protectedAction = false,
        ?string $scheme = null,
        ?string $cdn = null,
        ?string $ipFrom = null,
        array $allowRuleHeaders = [],
        ?string $action = null,
    ): Outcome {
        $request = DecideRequest::fromVisit($visit, $ip, $scheme, $cdn, $ipFrom, $allowRuleHeaders)
            ->withAction($action);
        if ($path !== null && $path !== '') {
            $request = $request->withPath($path);
        }
        // A page load spends no token, so the page that shows a form leaves the form's post its own.
        if ($protectedAction && !\in_array($visit->method, ['GET', 'HEAD', 'OPTIONS'], true)) {
            $request = $request->withProtectedAction(true);
        }
        $d = $client->decide($request);
        if ($d?->action === Decision::BLOCK) {
            return $onBlock ? Outcome::hook($d) : Outcome::forbidden($d);
        }

        return Outcome::pass($d);
    }
}

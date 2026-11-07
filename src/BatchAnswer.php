<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/** POST /v1/events' and /v1/feedback's answer. */
final readonly class BatchAnswer
{
    /** @param list<ItemError> $errors */
    public function __construct(
        public int $accepted,
        public int $duplicates,
        public int $rejected,
        public array $errors = [],
    ) {}

    /**
     * The batch's answer in a 200's body; null unless it is one JSON object with accepted,
     * duplicates and rejected as integers and errors as a list of {index, code, detail}.
     */
    public static function fromJson(string $json): ?self
    {
        try {
            $a = json_decode($json, true, 16, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!\is_array($a)) {
            return null;
        }
        $accepted = $a['accepted'] ?? null;
        $duplicates = $a['duplicates'] ?? null;
        $rejected = $a['rejected'] ?? null;
        $list = $a['errors'] ?? null;
        if (
            !\is_int($accepted) || !\is_int($duplicates) || !\is_int($rejected)
            || !\is_array($list) || !array_is_list($list)
        ) {
            return null;
        }
        $errors = [];
        foreach ($list as $e) {
            if (!\is_array($e) || !\is_int($e['index'] ?? null) || !\is_string($e['code'] ?? null)) {
                return null;
            }
            $errors[] = new ItemError($e['index'], $e['code'], \is_string($e['detail'] ?? null) ? $e['detail'] : '');
        }

        return new self($accepted, $duplicates, $rejected, $errors);
    }
}

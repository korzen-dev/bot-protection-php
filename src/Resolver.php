<?php

declare(strict_types=1);

// The WordPress plugin carries this SDK as a library: a DNS socket bounded by the
// deadline, which no lookup of PHP's or WordPress's is. The error handler only silences a
// refused socket's warning.
// phpcs:disable WordPress.WP.AlternativeFunctions
// phpcs:disable WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler

namespace Korzen\BotProtection;

/**
 * Resolves Bot Protection's name within the call's budget. PHP's own lookups (what
 * stream_socket_client and gethostbynamel do) are the system's, outside any PHP timeout:
 * a resolver that drops packets costs about 5 s a try against a budget of 200 ms. This one
 * reads the hosts file, then asks the nameservers resolv.conf names over UDP, all at once,
 * and waits for them only until the deadline: a name it cannot resolve in time is no
 * address, and the call fails open. An address is its own answer. Where the system names
 * no nameserver (no resolv.conf, as on Windows), the name is left to the system's resolver.
 *
 * @internal
 */
final class Resolver
{
    /** Bytes a DNS answer over UDP may take without EDNS. */
    private const MAX_ANSWER = 512;
    /** The nameservers asked, as glibc reads resolv.conf (MAXNS). */
    private const MAX_SERVERS = 3;
    private const TYPE_A = 1;
    private const TYPE_AAAA = 28;
    /** A host name: labels of 1 to 63 letters, digits, hyphens and underscores, 253 bytes at most. */
    private const NAME = '/^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*'
        . '[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/D';

    /**
     * @param string $hosts the hosts file
     * @param string $resolvConf the file that names the nameservers
     * @param int $port the nameservers' port; another than 53 only for a test
     */
    public function __construct(
        private readonly string $hosts = '/etc/hosts',
        private readonly string $resolvConf = '/etc/resolv.conf',
        private readonly int $port = 53,
    ) {}

    /**
     * The addresses of $host (a name, or an IPv4 address or a bracketed IPv6 one), IPv4
     * first, found before $deadline; null when the system is to resolve it (no
     * nameserver named). An exception when it has none, or none came in time.
     *
     * @return list<string>|null
     */
    public function resolve(string $host, float $deadline): ?array
    {
        $bare = trim($host, '[]');
        if (filter_var($bare, \FILTER_VALIDATE_IP) !== false) {
            return [$bare];
        }
        $name = strtolower(rtrim($host, '.'));
        if (preg_match(self::NAME, $name) !== 1) {
            throw new \InvalidArgumentException('korzen: no host name to resolve');
        }
        $listed = $this->listed($name);
        if ($listed !== []) {
            return $listed;
        }
        $servers = $this->servers();
        if ($servers === []) {
            return null;
        }
        // A socket refused comes as a warning, which a framework's error handler may turn
        // into an exception: the failure is the return value here.
        set_error_handler(static fn(): bool => true);
        try {
            return $this->ask($name, $servers, $deadline);
        } finally {
            restore_error_handler();
        }
    }

    /**
     * The addresses the hosts file gives $name, IPv4 first.
     *
     * @return list<string>
     */
    private function listed(string $name): array
    {
        $v4 = [];
        $v6 = [];
        foreach (self::lines($this->hosts) as $fields) {
            $ip = array_shift($fields);
            $names = array_map(strtolower(...), $fields);
            if (filter_var($ip, \FILTER_VALIDATE_IP) === false || !\in_array($name, $names, true)) {
                continue;
            }
            if (filter_var($ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4) !== false) {
                $v4[] = $ip;
            } else {
                $v6[] = $ip;
            }
        }

        return [...$v4, ...$v6];
    }

    /**
     * The nameservers resolv.conf names, the first MAX_SERVERS.
     *
     * @return list<string>
     */
    private function servers(): array
    {
        $servers = [];
        foreach (self::lines($this->resolvConf) as $fields) {
            $server = $fields[1] ?? '';
            if ($fields[0] === 'nameserver' && filter_var(explode('%', $server)[0], \FILTER_VALIDATE_IP) !== false) {
                $servers[] = $server;
            }
        }

        return \array_slice($servers, 0, self::MAX_SERVERS);
    }

    /**
     * The fields of each line of $file, comments left out; none when it cannot be read.
     *
     * @return list<non-empty-list<string>>
     */
    private static function lines(string $file): array
    {
        $text = is_file($file) && is_readable($file) ? file_get_contents($file) : false;
        $out = [];
        foreach (explode("\n", \is_string($text) ? $text : '') as $line) {
            $fields = preg_split('/\s+/', trim(explode('#', $line, 2)[0]), -1, \PREG_SPLIT_NO_EMPTY);
            if (\is_array($fields) && $fields !== []) {
                $out[] = $fields;
            }
        }

        return $out;
    }

    /**
     * Asks every server for $name's A and AAAA records at once, and reads their answers
     * until the deadline: the IPv4 addresses as soon as they come, else every address once
     * both questions are answered or no server is left to answer them.
     *
     * @param list<string> $servers
     *
     * @return list<string>
     */
    private function ask(string $name, array $servers, float $deadline): array
    {
        /** @var array<int, resource> $sockets */
        $sockets = [];
        /** @var array<int, array<int, int>> $asked each socket's questions not answered yet, their type by ID */
        $asked = [];
        foreach ($servers as $i => $server) {
            $address = str_contains($server, ':') ? '[' . $server . ']' : $server;
            $socket = stream_socket_client('udp://' . $address . ':' . $this->port, $code, $message, 1);
            if ($socket === false) {
                continue;
            }
            stream_set_blocking($socket, false);
            $sockets[$i] = $socket;
            foreach ([self::TYPE_A, self::TYPE_AAAA] as $type) {
                $id = random_int(0, 0xFFFF);
                $asked[$i][$id] = $type;
                fwrite($socket, self::question($id, $name, $type));
            }
        }
        /** @var array<int, list<string>> $found the addresses of each type answered */
        $found = [];
        try {
            while (!self::done($found, $asked) && ($left = $deadline - microtime(true)) > 0) {
                $read = array_values($sockets);
                $write = null;
                $except = null;
                // A select that fails reads nothing: the loop goes on to the deadline at most.
                $ready = stream_select($read, $write, $except, (int) $left, (int) (fmod($left, 1) * 1e6));
                $read = $ready === false ? [] : $read;
                foreach ($sockets as $i => $socket) {
                    $packet = \in_array($socket, $read, true) ? fread($socket, self::MAX_ANSWER) : false;
                    $answer = \is_string($packet) ? self::answer($packet, $asked[$i] ?? []) : null;
                    if ($answer === null) {
                        continue;
                    }
                    [$id, $type, $addresses] = $answer;
                    unset($asked[$i][$id]);
                    // The first server to answer a question answers it; a server's failure answers nothing.
                    if ($addresses !== null) {
                        $found[$type] ??= $addresses;
                    }
                }
            }
        } finally {
            foreach ($sockets as $socket) {
                fclose($socket);
            }
        }
        $all = [...$found[self::TYPE_A] ?? [], ...$found[self::TYPE_AAAA] ?? []];
        if ($all === []) {
            throw new \RuntimeException(
                self::done($found, $asked)
                    ? 'korzen: Bot Protection\'s name has no address'
                    : 'korzen: Bot Protection\'s name did not resolve in time',
            );
        }

        return $all;
    }

    /**
     * Whether the lookup is over: IPv4 addresses found, both questions answered, or no
     * question left that a server could still answer.
     *
     * @param array<int, list<string>> $found
     * @param array<int, array<int, int>> $asked
     */
    private static function done(array $found, array $asked): bool
    {
        return ($found[self::TYPE_A] ?? []) !== []
            || \count($found) === 2
            || array_merge(...array_values($asked)) === [];
    }

    /** A DNS question (RFC 1035, 4.1): $name's records of $type, recursion desired. */
    private static function question(int $id, string $name, int $type): string
    {
        $q = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);
        foreach (explode('.', $name) as $label) {
            $q .= \chr(\strlen($label)) . $label;
        }

        return $q . "\0" . pack('nn', $type, 1);
    }

    /**
     * What $packet answers of the questions $asked (by ID, their type): its ID, its type
     * and the addresses of that type it holds, none for a name that does not exist or has
     * no such record, null for a server's failure. Null for a packet that answers none of
     * the questions, or does not read.
     *
     * @param array<int, int> $asked
     *
     * @return array{int, int, list<string>|null}|null
     */
    private static function answer(string $packet, array $asked): ?array
    {
        if (\strlen($packet) < 12) {
            return null;
        }
        /** @var array{id: int, flags: int, qd: int, an: int} $h */
        $h = unpack('nid/nflags/nqd/nan', $packet);
        $type = $asked[$h['id']] ?? null;
        $rcode = $h['flags'] & 0x0F;
        if ($type === null || ($h['flags'] & 0x8000) === 0) {
            return null; // no answer (QR) to a question asked
        }
        if ($rcode !== 0 && $rcode !== 3) {
            return [$h['id'], $type, null]; // the server failed (3 is a name that does not exist)
        }
        $at = 12;
        for ($q = 0; $q < $h['qd']; ++$q) {
            $at = self::skipName($packet, $at) + 4;
        }
        $addresses = [];
        for ($r = 0; $r < $h['an'] && $rcode === 0; ++$r) {
            $at = self::skipName($packet, $at);
            if ($at + 10 > \strlen($packet)) {
                return null;
            }
            /** @var array{type: int, class: int, length: int} $rr */
            $rr = unpack('ntype/nclass/x4/nlength', $packet, $at);
            $at += 10;
            $data = substr($packet, $at, $rr['length']);
            $at += $rr['length'];
            if (\strlen($data) !== $rr['length']) {
                return null;
            }
            $size = $type === self::TYPE_A ? 4 : 16;
            if ($rr['type'] === $type && $rr['class'] === 1 && \strlen($data) === $size) {
                $addresses[] = (string) inet_ntop($data);
            }
        }

        return [$h['id'], $type, $addresses];
    }

    /** Where the name at $at in $packet ends: past its labels, or its pointer (RFC 1035, 4.1.4). */
    private static function skipName(string $packet, int $at): int
    {
        while ($at < \strlen($packet)) {
            $len = \ord($packet[$at]);
            if (($len & 0xC0) === 0xC0) {
                return $at + 2;
            }
            if ($len === 0) {
                return $at + 1;
            }
            $at += $len + 1;
        }

        return $at;
    }
}

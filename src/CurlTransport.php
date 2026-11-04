<?php

declare(strict_types=1);

namespace Korzen\BotProtection;

/**
 * Sends the client's calls with ext-curl, a new connection each time. Measured from PHP 8.5
 * on 2026-10-22, ten calls to korzen.dev: the stream wrapper took 206 ms at the median and
 * once 5.3 s, curl 122 ms and at most 155 ms. A connection kept between calls (PHP 8.5's
 * persistent share) took 72 ms, but libcurl sends a POST again when a kept connection dies
 * before the answer, and a decide sent twice can spend a token the visitor earned once:
 * connections are not kept. The Client uses it when ext-curl is loaded, else StreamTransport.
 * A libcurl built with a threaded or c-ares resolver bounds the name's lookup by the
 * timeout; one with the system's synchronous resolver, which CURLOPT_NOSIGNAL leaves
 * unbounded, gets the name resolved within the time left (Resolver) and pinned.
 */
final class CurlTransport implements Transport, ForwardTransport
{
    /** Whether ext-curl is loaded, so this transport can work. */
    public static function available(): bool
    {
        return \function_exists('curl_init');
    }

    public function post(
        string $url,
        #[\SensitiveParameter]
        array $headers,
        string $body,
        float $deadline,
        int $limit,
    ): Answer {
        return $this->call('POST', $url, $headers, $body, $deadline, $limit, false);
    }

    public function send(
        string $method,
        string $url,
        #[\SensitiveParameter]
        array $headers,
        string $body,
        float $deadline,
        int $limit,
    ): Answer {
        return $this->call($method, $url, $headers, $body, $deadline, $limit, true);
    }

    /**
     * Sends $method to $url: a POST with $body, any other method as a GET.
     *
     * @param array<string, string> $headers
     * @param bool $only whether $headers are all the call sends: curl's own Accept is
     *     taken out when they name none (a forward sends the visitor's alone)
     */
    private function call(
        string $method,
        string $url,
        #[\SensitiveParameter]
        array $headers,
        string $body,
        float $deadline,
        int $limit,
        bool $only,
    ): Answer {
        $left = (int) ceil(($deadline - microtime(true)) * 1000);
        if ($left <= 0) {
            throw new \RuntimeException('korzen: no time left for the call to Bot Protection');
        }
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        // curl sends Expect: 100-continue for a large body and waits for it: never wait.
        $lines[] = 'Expect:';
        if ($only && !\in_array('accept', array_map('strtolower', array_keys($headers)), true)) {
            $lines[] = 'Accept:';
        }
        $post = $method === 'POST';
        $answerHeaders = [];
        $status = 0;
        // Whether the answer's headers reached their blank line: curl takes a connection
        // closed in the middle of them for an answer, which it is not.
        $ended = false;
        $received = '';
        $h = self::init();
        $options = [
            \CURLOPT_URL => $url !== '' ? $url : throw new \InvalidArgumentException('korzen: no URL to call'),
            \CURLOPT_HTTPHEADER => $lines,
            \CURLOPT_FOLLOWLOCATION => false,
            \CURLOPT_TIMEOUT_MS => $left,
            \CURLOPT_CONNECTTIMEOUT_MS => $left,
            \CURLOPT_NOSIGNAL => true,
            \CURLOPT_RESOLVE => self::pinned($url, $deadline, self::asyncDns(), new Resolver()),
            \CURLOPT_FORBID_REUSE => true,
            \CURLOPT_PROTOCOLS => \CURLPROTO_HTTPS | \CURLPROTO_HTTP,
            \CURLOPT_HEADERFUNCTION => static function (
                $_h,
                string $line,
            ) use (
                &$answerHeaders,
                &$status,
                &$ended,
            ): int {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                    [$status, $answerHeaders, $ended] = [(int) $m[1], [], false];
                } elseif (trim($line) === '') {
                    $ended = true;
                } elseif (preg_match('/^([^:\s]+)\s*:\s*(.*?)\s*$/D', $line, $m) === 1) {
                    $name = strtolower($m[1]);
                    $answerHeaders[$name] = isset($answerHeaders[$name]) ? $answerHeaders[$name] . ', ' . $m[2] : $m[2];
                }

                return \strlen($line);
            },
            // Reads at most $limit + 1 bytes, so a longer body is seen as longer and the rest
            // is never read: a short count makes curl stop the transfer there.
            \CURLOPT_WRITEFUNCTION => static function ($_h, string $chunk) use (&$received, $limit): int {
                $room = $limit + 1 - \strlen($received);
                $received .= substr($chunk, 0, max(0, $room));

                return $room >= \strlen($chunk) ? \strlen($chunk) : 0;
            },
        ];
        // A POST with its body; any other method is a GET.
        $options += $post ? [\CURLOPT_POST => true, \CURLOPT_POSTFIELDS => $body] : [\CURLOPT_HTTPGET => true];
        // What curl_setopt_array throws keeps its arguments, the key among them, in its trace:
        // it is replaced by an exception of this frame, whose headers are marked sensitive.
        try {
            $set = curl_setopt_array($h, $options);
        } catch (\Throwable) {
            $set = false;
        }
        $set || throw new \RuntimeException('korzen: curl refused its options');
        $ok = curl_exec($h);
        // A transfer stopped by the write callback after limit + 1 bytes is the answer read
        // as far as it is needed; any other failure is no answer.
        $cut = curl_errno($h) === \CURLE_WRITE_ERROR && \strlen($received) > $limit;
        if (($ok === false && !$cut) || $status === 0 || !$ended) {
            throw new \RuntimeException('korzen: the call to Bot Protection failed: ' . curl_error($h));
        }

        return new Answer($status, $received, $answerHeaders);
    }

    /** Whether libcurl resolves names asynchronously, so its timeout bounds the lookup. */
    private static function asyncDns(): bool
    {
        $v = curl_version();

        $features = \is_array($v) ? $v['features'] ?? 0 : 0;

        return \is_int($features) && ($features & \CURL_VERSION_ASYNCHDNS) !== 0;
    }

    /**
     * What CURLOPT_RESOLVE pins: nothing when libcurl's resolver keeps to the timeout ($async)
     * or $url's host is an address; else the host's addresses, resolved before the deadline.
     *
     * @return list<string>
     */
    private static function pinned(string $url, float $deadline, bool $async, Resolver $resolver): array
    {
        $u = parse_url($url);
        $host = \is_array($u) ? $u['host'] ?? '' : '';
        if ($async || $host === '' || filter_var(trim($host, '[]'), \FILTER_VALIDATE_IP) !== false) {
            return [];
        }
        $addresses = $resolver->resolve($host, $deadline);
        if ($addresses === null) {
            return [];
        }
        $port = $u['port'] ?? (strtolower($u['scheme'] ?? '') === 'https' ? 443 : 80);
        $listed = array_map(static fn(string $a): string => str_contains($a, ':') ? '[' . $a . ']' : $a, $addresses);

        return [$host . ':' . $port . ':' . implode(',', $listed)];
    }

    /** A new curl handle; curl_init fails only when curl itself cannot start. */
    private static function init(): \CurlHandle
    {
        $h = curl_init();

        return $h !== false ? $h : throw new \RuntimeException('korzen: curl could not start');
    }
}

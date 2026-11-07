<?php

declare(strict_types=1);

// The WordPress plugin carries this SDK as a library: a socket bounded by the deadline at
// every read and write is the fail-open promise, which WordPress's HTTP API does not keep
// the same way. The error handler only silences a refused connection's warning.
// phpcs:disable WordPress.WP.AlternativeFunctions
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped
// phpcs:disable WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler

namespace Korzen\BotProtection;

/**
 * The Transport without ext-curl: a socket of PHP's own (https needs openssl, which every
 * PHP build that serves https has) and the HTTP/1.1 the client needs, Connection: close
 * with a Content-Length or a chunked body. It follows no redirect, reads at most the limit
 * and one byte more, and keeps to the deadline: connecting (and the TLS handshake) waits at
 * most the time left, and every write and every read after it, the status line and the
 * headers as well as the body, is given only what is left, so a server that sends its
 * answer a few bytes at a time holds the visitor no longer than the client's timeout.
 * Bot Protection's name is resolved within the time left too (Resolver: the hosts file,
 * then the nameservers resolv.conf names), never by the system's lookup, which no PHP
 * timeout bounds; only where no nameserver is named (Windows) is it the system's. Each call
 * opens its own connection: PHP-FPM shares nothing between requests either.
 */
final class StreamTransport implements Transport, ForwardTransport
{
    private readonly Resolver $resolver;

    /** @param Resolver|null $resolver @internal: another hosts file or nameserver, for a test */
    public function __construct(?Resolver $resolver = null)
    {
        $this->resolver = $resolver ?? new Resolver();
    }

    /** Bytes asked of each read. */
    private const CHUNK = 65536;
    /** Bytes the status line and the headers may take, together. */
    private const MAX_HEAD = 65536;
    /** Bytes a chunk's size line may take. */
    private const MAX_CHUNK_LINE = 1024;
    /** Headers the transport writes itself, so the caller's are not sent twice. */
    private const OWN = ['host', 'content-length', 'connection', 'transfer-encoding'];

    public function post(
        string $url,
        #[\SensitiveParameter]
        array $headers,
        string $body,
        float $deadline,
        int $limit,
    ): Answer {
        return $this->send('POST', $url, $headers, $body, $deadline, $limit);
    }

    /** A POST with its body and its length; any other method is a GET, without either. */
    public function send(
        string $method,
        string $url,
        #[\SensitiveParameter]
        array $headers,
        string $body,
        float $deadline,
        int $limit,
    ): Answer {
        [$scheme, $host, $port, $authority, $name, $target] = self::target($url);
        $post = $method === 'POST';
        $request = ($post ? 'POST ' : 'GET ') . $target . " HTTP/1.1\r\nHost: " . $authority . "\r\n";
        foreach ($headers as $header => $value) {
            if (!\in_array(strtolower($header), self::OWN, true)) {
                $request .= $header . ': ' . $value . "\r\n";
            }
        }
        $request .= ($post ? 'Content-Length: ' . \strlen($body) . "\r\n" : '') . "Connection: close\r\n\r\n"
            . ($post ? $body : '');
        $context = stream_context_create([
            'ssl' => ['peer_name' => $name, 'SNI_enabled' => true, 'verify_peer' => true, 'verify_peer_name' => true],
        ]);
        // A refused or reset connection comes as a warning, which a framework's error
        // handler may turn into an exception: the failure is the return value here.
        set_error_handler(static fn(): bool => true);
        try {
            $stream = $this->connect($scheme, $host, $port, $deadline, $context);
            try {
                self::write($stream, $request, $deadline);
                $in = '';
                [$status, $answerHeaders] = self::head($stream, $deadline, $in);
                // A 204 and a redirect have no body worth reading: a decision, a batch's
                // answer and a problem come with another status.
                if ($status === 204 || ($status >= 300 && $status < 400)) {
                    return new Answer($status, '', $answerHeaders);
                }

                return new Answer($status, self::body($stream, $deadline, $limit, $in, $answerHeaders), $answerHeaders);
            } finally {
                fclose($stream);
            }
        } finally {
            restore_error_handler();
        }
    }

    /**
     * A connection to $host's first address that takes one before the deadline, its name
     * resolved within it; the system resolves it only when the Resolver says so.
     *
     * @param resource $context
     *
     * @return resource
     */
    private function connect(string $scheme, string $host, int $port, float $deadline, $context)
    {
        $addresses = $this->resolver->resolve($host, $deadline) ?? [$host];
        foreach ($addresses as $address) {
            $remote = str_contains($address, ':') && !str_starts_with($address, '[') ? '[' . $address . ']' : $address;
            $stream = stream_socket_client(
                $scheme . '://' . $remote . ':' . $port,
                $code,
                $message,
                self::left($deadline),
                \STREAM_CLIENT_CONNECT,
                $context,
            );
            if ($stream !== false) {
                return $stream;
            }
        }
        throw new \RuntimeException('korzen: the call to Bot Protection failed');
    }

    /**
     * Where $url points: the socket's scheme, its host and port, the Host header, the name
     * its certificate must carry, and the request target.
     *
     * @return array{string, string, int, string, string, string}
     */
    private static function target(string $url): array
    {
        $u = parse_url($url);
        $scheme = strtolower(\is_array($u) ? $u['scheme'] ?? '' : '');
        if (!\is_array($u) || ($u['host'] ?? '') === '' || ($scheme !== 'https' && $scheme !== 'http')) {
            throw new \InvalidArgumentException('korzen: no http(s) URL to call');
        }
        $host = $u['host'];
        $port = $u['port'] ?? ($scheme === 'https' ? 443 : 80);
        $path = ($u['path'] ?? '') === '' ? '/' : $u['path'];

        return [
            $scheme === 'https' ? 'ssl' : 'tcp',
            $host,
            $port,
            $host . (isset($u['port']) ? ':' . $port : ''),
            trim($host, '[]'),
            $path . (isset($u['query']) ? '?' . $u['query'] : ''),
        ];
    }

    /**
     * Writes all of $request before the deadline.
     *
     * @param resource $stream
     */
    private static function write($stream, #[\SensitiveParameter] string $request, float $deadline): void
    {
        while ($request !== '') {
            self::wait($stream, $deadline);
            $written = fwrite($stream, $request);
            if (!\is_int($written) || $written <= 0) {
                throw new \RuntimeException('korzen: the call to Bot Protection failed');
            }
            $request = substr($request, $written);
        }
    }

    /**
     * The answer's status and headers, past any interim answer (a 100 Continue); names
     * lower-cased, a repeated one joined with ", ". What came after them stays in $in.
     *
     * @param resource $stream
     *
     * @return array{int, array<string, string>}
     */
    private static function head($stream, float $deadline, string &$in): array
    {
        do {
            $end = self::find($stream, $deadline, $in, "\r\n\r\n", self::MAX_HEAD, 'headers');
            $lines = explode("\r\n", substr($in, 0, $end));
            $in = substr($in, $end + 4);
            if (preg_match('#^HTTP/1\.[01] (\d{3})(?: |$)#', $lines[0], $m) !== 1) {
                throw new \RuntimeException('korzen: the answer is not HTTP/1.1');
            }
            $status = (int) $m[1];
        } while ($status < 200);
        $headers = [];
        foreach (\array_slice($lines, 1) as $line) {
            if (preg_match('/^([^:\s]+)\s*:\s*(.*?)\s*$/D', $line, $m) === 1) {
                $name = strtolower($m[1]);
                $headers[$name] = isset($headers[$name]) ? $headers[$name] . ', ' . $m[2] : $m[2];
            }
        }

        return [$status, $headers];
    }

    /**
     * The body, up to $limit + 1 bytes, read before the deadline: its Content-Length,
     * its chunks, or up to the end of the connection.
     *
     * @param resource $stream
     * @param array<string, string> $headers
     */
    private static function body($stream, float $deadline, int $limit, string $in, array $headers): string
    {
        if (str_contains(strtolower($headers['transfer-encoding'] ?? ''), 'chunked')) {
            return self::chunks($stream, $deadline, $limit, $in);
        }
        $length = $headers['content-length'] ?? '';
        $want = ctype_digit($length) ? min((int) $length, $limit + 1) : $limit + 1;
        while (\strlen($in) < $want && self::fill($stream, $deadline, $in)) {
            // Read on: each fill adds a piece to $in.
        }

        return substr($in, 0, $want);
    }

    /**
     * A chunked body, up to $limit + 1 bytes, read before the deadline; the trailer, if
     * any, is not read.
     *
     * @param resource $stream
     */
    private static function chunks($stream, float $deadline, int $limit, string $in): string
    {
        $body = '';
        while (\strlen($body) <= $limit) {
            $eol = self::find($stream, $deadline, $in, "\r\n", self::MAX_CHUNK_LINE, 'chunks');
            if (preg_match('/^([0-9a-fA-F]{1,8})(?:;.*)?$/D', substr($in, 0, $eol), $m) !== 1) {
                throw new \RuntimeException('korzen: the answer\'s chunks are not HTTP/1.1');
            }
            $size = (int) hexdec($m[1]);
            $in = substr($in, $eol + 2);
            if ($size === 0) {
                break;
            }
            $room = $limit + 1 - \strlen($body);
            // The chunk and the line's end after it, or only what is left of the limit.
            $need = $size < $room ? $size + 2 : $room;
            while (\strlen($in) < $need) {
                if (!self::fill($stream, $deadline, $in)) {
                    throw new \RuntimeException('korzen: the answer\'s chunks did not come whole');
                }
            }
            $body .= substr($in, 0, min($size, $room));
            $in = substr($in, $need);
        }

        return $body;
    }

    /**
     * Where $needle starts in $in, read on until it comes; an exception once $in holds more
     * than $max bytes without it, or the answer ends before it.
     *
     * @param resource $stream
     */
    private static function find($stream, float $deadline, string &$in, string $needle, int $max, string $what): int
    {
        for (;;) {
            $at = strpos($in, $needle);
            if ($at !== false) {
                return $at;
            }
            if (\strlen($in) > $max || !self::fill($stream, $deadline, $in)) {
                throw new \RuntimeException('korzen: the answer\'s ' . $what . ' did not come whole');
            }
        }
    }

    /**
     * One more piece of the answer onto $in, read before the deadline: false once the
     * answer has ended.
     *
     * @param resource $stream
     */
    private static function fill($stream, float $deadline, string &$in): bool
    {
        self::wait($stream, $deadline);
        $chunk = fread($stream, self::CHUNK);
        if ($chunk === false || ($chunk === '' && stream_get_meta_data($stream)['timed_out'])) {
            throw new \RuntimeException('korzen: the answer did not come in time');
        }
        $in .= $chunk;

        // A TLS record that holds no data (a session ticket) reads as nothing: only the
        // end of the stream ends the answer.
        return $chunk !== '' || !feof($stream);
    }

    /**
     * Gives the next read or write on $stream only the time left.
     *
     * @param resource $stream
     */
    private static function wait($stream, float $deadline): void
    {
        $left = self::left($deadline);
        stream_set_timeout($stream, (int) $left, (int) (fmod($left, 1) * 1e6));
    }

    /** Seconds until $deadline; an exception once it has passed. */
    private static function left(float $deadline): float
    {
        $left = $deadline - microtime(true);
        if ($left <= 0) {
            throw new \RuntimeException('korzen: the call to Bot Protection timed out');
        }

        return $left;
    }
}

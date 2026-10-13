<?php

/** Shared, bounded pre-auth login failure counters for SHCP webmail. */
final class ShcpLoginLimiter
{
    private const WINDOW = 300;
    private const LIMIT = 10;
    private const MAX_KEYS = 50000;

    public function __construct(private string $path)
    {
    }

    public function client(array $server, array $proxies, string $secret): string
    {
        $peer = $server['REMOTE_ADDR'] ?? '';
        if (!filter_var($peer, FILTER_VALIDATE_IP)
            || $secret === ''
            || !$this->isTrustedPeer($peer, $proxies)
            || !hash_equals($secret, $server['HTTP_X_SHCP_WEBMAIL_PROXY_AUTH'] ?? '')
        ) {
            return $peer;
        }

        if (empty($server['HTTP_X_FORWARDED_FOR'])) {
            return $peer;
        }

        $chain = array_map('trim', explode(',', $server['HTTP_X_FORWARDED_FOR']));
        if (count($chain) > 16) {
            return $peer;
        }
        foreach ($chain as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return $peer;
            }
        }
        foreach (array_reverse($chain) as $ip) {
            if (!$this->isTrustedPeer($ip, $proxies)) {
                return $ip;
            }
        }

        return $peer;
    }

    private function isTrustedPeer(string $ip, array $proxies): bool
    {
        $address = inet_pton($ip);
        if ($address === false) {
            return false;
        }
        $mapped = str_repeat("\0", 10) . "\xff\xff";
        if (strlen($address) === 16 && str_starts_with($address, $mapped)) {
            $address = substr($address, 12);
        }

        foreach ($proxies as $entry) {
            if (!is_string($entry)) {
                continue;
            }
            $parts = explode('/', $entry);
            if (count($parts) > 2 || !filter_var($parts[0], FILTER_VALIDATE_IP)) {
                continue;
            }
            $network = inet_pton($parts[0]);
            $bits = strlen($network) * 8;
            if (count($parts) === 2) {
                if (!preg_match('/^(0|[1-9][0-9]*)$/D', $parts[1]) || strlen($parts[1]) > 3) {
                    continue;
                }
                $bits = (int) $parts[1];
                if ($bits > strlen($network) * 8) {
                    continue;
                }
            }
            if (strlen($network) === 16 && str_starts_with($network, $mapped)) {
                // Prefixes below /96 include addresses outside the mapped IPv4 space.
                if ($bits < 96) {
                    continue;
                }
                $network = substr($network, 12);
                $bits -= 96;
            }
            if (strlen($address) !== strlen($network)) {
                continue;
            }
            $whole = intdiv($bits, 8);
            $remaining = $bits % 8;
            if (substr($address, 0, $whole) !== substr($network, 0, $whole)) {
                continue;
            }
            if ($remaining === 0
                || (ord($address[$whole]) & (0xff << (8 - $remaining)))
                    === (ord($network[$whole]) & (0xff << (8 - $remaining)))
            ) {
                return true;
            }
        }

        return false;
    }

    public function allowed(string $client, string $account): bool
    {
        if (!filter_var($client, FILTER_VALIDATE_IP)) {
            return false;
        }

        try {
            $db = $this->open();
            $db->exec('BEGIN IMMEDIATE');
            $db->prepare('DELETE FROM attempts WHERE expires <= ?')->execute([time()]);
            foreach ($this->keys($client, $account) as $key) {
                $query = $db->prepare('SELECT failures, expires FROM attempts WHERE bucket = ?');
                $query->execute([$key]);
                $row = $query->fetch(PDO::FETCH_ASSOC);
                if ($row && $row['expires'] > time() && $row['failures'] >= self::LIMIT) {
                    $db->rollBack();
                    return false;
                }
                if (!$row && (int) $db->query('SELECT count(*) FROM attempts')->fetchColumn() >= self::MAX_KEYS) {
                    $db->rollBack();
                    return false;
                }
            }
            $db->rollBack();
            return true;
        } catch (Throwable $e) {
            if (isset($db) && $db->inTransaction()) {
                $db->rollBack();
            }
            return false;
        }
    }

    public function failed(string $client, string $account): bool
    {
        if (!filter_var($client, FILTER_VALIDATE_IP)) {
            return false;
        }

        try {
            $db = $this->open();
            $db->exec('BEGIN IMMEDIATE');
            $now = time();
            $db->prepare('DELETE FROM attempts WHERE expires <= ?')->execute([$now]);
            foreach ($this->keys($client, $account) as $key) {
                $query = $db->prepare('UPDATE attempts SET failures = failures + 1 WHERE bucket = ?');
                $query->execute([$key]);
                if ($query->rowCount() === 0) {
                    if ((int) $db->query('SELECT count(*) FROM attempts')->fetchColumn() >= self::MAX_KEYS) {
                        throw new RuntimeException('Login limiter capacity reached');
                    }
                    $db->prepare('INSERT INTO attempts (bucket, failures, expires) VALUES (?, 1, ?)')
                        ->execute([$key, $now + self::WINDOW]);
                }
            }
            $db->commit();
            return true;
        } catch (Throwable $e) {
            if (isset($db) && $db->inTransaction()) {
                $db->rollBack();
            }
            return false;
        }
    }

    private function keys(string $client, string $account): array
    {
        $keys = [hash('sha256', 'client:' . $client)];
        $account = mb_strtolower(trim($account));
        if ($account !== '') {
            $keys[] = hash('sha256', 'account:' . substr($account, 0, 256));
        }
        return $keys;
    }

    private function open(): PDO
    {
        $db = new PDO('sqlite:' . $this->path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $db->exec('PRAGMA busy_timeout = 2000');
        $db->exec('PRAGMA max_page_count = 8192');
        $db->exec('CREATE TABLE IF NOT EXISTS attempts (bucket TEXT PRIMARY KEY, failures INTEGER NOT NULL, expires INTEGER NOT NULL)');
        return $db;
    }
}

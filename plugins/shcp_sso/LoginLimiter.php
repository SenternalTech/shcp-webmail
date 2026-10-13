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
            || !in_array($peer, $proxies, true)
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
            if (!in_array($ip, $proxies, true)) {
                return $ip;
            }
        }

        return $peer;
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

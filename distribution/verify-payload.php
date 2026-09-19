#!/usr/bin/env php
<?php
declare(strict_types=1);
require_once __DIR__ . '/assemble.php';
try {
    if ($argc !== 3) { throw new RuntimeException('Expected payload and manifest'); }
    $manifest = wm_json($argv[2]);
    if (($manifest['format'] ?? null) !== 1 || wm_inventory($argv[1]) !== $manifest['files']) {
        throw new RuntimeException('Payload differs from manifest');
    }
} catch (Throwable $error) {
    fwrite(STDERR, $error->getMessage() . "\n");
    exit(1);
}

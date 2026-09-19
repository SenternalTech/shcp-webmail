#!/usr/bin/env php
<?php
declare(strict_types=1);
require_once __DIR__ . '/assemble.php';

function wm_components(string $payload): array
{
    $components = ['roundcube/roundcubemail@1.6.19' => ['GPL-3.0-or-later'],
        'mstilkerich/rcmcarddav@5.1.3' => ['GPL-2.0-or-later']];
    foreach (array_keys(wm_inventory($payload)) as $file) {
        if (!str_ends_with($file, 'vendor/composer/installed.json')) { continue; }
        $metadata = wm_json("$payload/$file");
        foreach ($metadata['packages'] ?? $metadata as $package) {
            $id = $package['name'] . '@' . $package['version'];
            $licenses = $package['license'] ?? [];
            if (!$licenses || (isset($components[$id]) && $components[$id] !== $licenses)) {
                throw new RuntimeException('Missing or conflicting dependency license: ' . $id);
            }
            $components[$id] = $licenses;
        }
    }
    foreach (wm_json(dirname(__DIR__) . '/jsdeps.json')['dependencies'] as $asset) {
        $components['asset/' . $asset['lib'] . '@' . $asset['version']] = [$asset['license'] ?? 'UNDECLARED'];
    }
    foreach (['shcp_sso', 'shcp_password', 'shcp_dav'] as $plugin) {
        $components['shcp/' . $plugin . '@1'] = ['MIT'];
    }
    ksort($components);
    return $components;
}

function wm_source_audit(string $payload, string $lockfile, string $sources, string $output): void
{
    $observed = wm_components($payload);
    $lock = wm_json($lockfile);
    $classified = $lock['components'] ?? [];
    ksort($classified);
    if (($lock['format'] ?? null) !== 1 || array_keys($observed) !== array_keys($classified)) {
        throw new RuntimeException('Source classification does not cover the exact payload component set');
    }
    $records = [];
    foreach ($observed as $identity => $licenses) {
        $entry = $classified[$identity];
        if (($entry['declared_licenses'] ?? null) !== $licenses || empty($entry['license_expression'])
            || empty($entry['review']) || ($entry['preferred_source'] ?? null) !== true) {
            throw new RuntimeException('Preferred-source and license review absent: ' . $identity);
        }
        foreach (['source', 'notice'] as $kind) {
            $input = $entry[$kind] ?? [];
            $name = $input['file'] ?? '';
            if (!preg_match('/^[A-Za-z0-9_.+-]+$/D', $name) || basename($name) !== $name
                || !str_starts_with($input['url'] ?? '', 'https://') || is_link("$sources/$name")
                || !is_file("$sources/$name") || hash_file('sha256', "$sources/$name") !== ($input['sha256'] ?? null)) {
                throw new RuntimeException('Missing or modified ' . $kind . ': ' . $identity);
            }
        }
        $records[] = ['component' => $identity] + $entry;
    }
    wm_write_json($output, ['format' => 1, 'components' => $records]);
}

if (realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    try {
        if ($argc === 3 && $argv[1] === '--inventory') {
            echo json_encode(wm_components($argv[2]), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
        } elseif ($argc === 5) {
            wm_source_audit($argv[1], $argv[2], $argv[3], $argv[4]);
        } else {
            throw new RuntimeException('usage: source-audit.php PAYLOAD SOURCE_LOCK SOURCES OUTPUT');
        }
    } catch (Throwable $error) {
        fwrite(STDERR, 'Source audit refused: ' . $error->getMessage() . "\n");
        exit(1);
    }
}

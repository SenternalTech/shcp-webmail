#!/usr/bin/env php
<?php
declare(strict_types=1);
require_once __DIR__ . '/source-audit.php';

const WM_SOURCE_ORIGIN = 'https://repo.shcp.dev/sources/shcp-webmail';

function wm_safe_release_id(string $releaseId): string
{
    if (!preg_match('/^webmail-[0-9]+\.[0-9]+\.[0-9]+-shcp\.[1-9][0-9]*$/D', $releaseId)) {
        throw new RuntimeException('Invalid full downstream release id');
    }
    return $releaseId;
}

function wm_source_filename(string $releaseId): string
{
    return wm_safe_release_id($releaseId) . '-source.tar.gz';
}

function wm_assert_regular_tree(string $root): array
{
    if (is_link($root) || !is_dir($root)) {
        throw new RuntimeException('Source input root is not a real directory');
    }
    $files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $entry) {
        if ($entry->isLink() || (!$entry->isDir() && !$entry->isFile())) {
            throw new RuntimeException('Source input contains a link or special file');
        }
        if ($entry->isFile()) {
            $relative = substr($entry->getPathname(), strlen($root) + 1);
            if ($relative === '' || str_contains($relative, "\\") || in_array('..', explode('/', $relative), true)) {
                throw new RuntimeException('Unsafe source input path');
            }
            $files[$relative] = $entry->getPathname();
        }
    }
    ksort($files, SORT_STRING);
    return $files;
}

function wm_reviewed_git_files(string $repository, array $paths): array
{
    $repository = realpath($repository) ?: '';
    $inside = [];
    $insideCode = 0;
    exec('git -C ' . escapeshellarg($repository) . ' rev-parse --is-inside-work-tree 2>/dev/null', $inside, $insideCode);
    if ($repository === '' || $insideCode !== 0 || ($inside[0] ?? '') !== 'true') {
        throw new RuntimeException('Corresponding source must be built from a Git checkout');
    }
    $quoted = array_map('escapeshellarg', $paths);
    $scope = implode(' ', $quoted);
    $status = [];
    $statusCode = 0;
    exec('git -C ' . escapeshellarg($repository) . ' status --porcelain=v1 --untracked-files=all -- ' . $scope, $status, $statusCode);
    if ($statusCode !== 0 || $status !== []) {
        throw new RuntimeException('Reviewed distribution/plugin inputs are dirty or untracked');
    }
    $listed = [];
    $listCode = 0;
    exec('git -C ' . escapeshellarg($repository) . ' ls-files -- ' . $scope, $listed, $listCode);
    if ($listCode !== 0 || $listed === []) {
        throw new RuntimeException('Cannot enumerate reviewed Git inputs');
    }
    $files = [];
    foreach ($listed as $relative) {
        if ($relative === '' || str_contains($relative, "\n") || str_contains($relative, "\\")
            || in_array('..', explode('/', $relative), true)) {
            throw new RuntimeException('Unsafe reviewed Git path');
        }
        $path = "$repository/$relative";
        if (is_link($path) || !is_file($path)) {
            throw new RuntimeException('Reviewed Git input is not a regular file: ' . $relative);
        }
        $files[$relative] = $path;
    }
    ksort($files, SORT_STRING);
    return $files;
}

function wm_tar_header(string $name, int $size, int $mode, int $mtime): string
{
    if (strlen($name) > 255 || $name === '' || $name[0] === '/' || str_contains($name, "\\")
        || in_array('..', explode('/', $name), true)) {
        throw new RuntimeException('Unsafe or overlong source archive path: ' . $name);
    }
    $prefix = '';
    if (strlen($name) > 100) {
        $split = null;
        for ($at = strlen($name) - 1; $at > 0; --$at) {
            if ($name[$at] === '/' && $at <= 155 && strlen($name) - $at - 1 <= 100) { $split = $at; break; }
        }
        if ($split === null) { throw new RuntimeException('Source archive path cannot be represented'); }
        $prefix = substr($name, 0, $split);
        $name = substr($name, $split + 1);
    }
    $octal = static fn(int $value, int $length): string => str_pad(decoct($value), $length - 1, '0', STR_PAD_LEFT) . "\0";
    $header = str_pad($name, 100, "\0") . $octal($mode, 8) . $octal(0, 8) . $octal(0, 8)
        . $octal($size, 12) . $octal($mtime, 12) . str_repeat(' ', 8) . '0'
        . str_repeat("\0", 100) . "ustar\00000" . str_repeat("\0", 32) . str_repeat("\0", 32)
        . str_repeat("\0", 8) . str_repeat("\0", 8) . str_pad($prefix, 155, "\0") . str_repeat("\0", 12);
    if (strlen($header) !== 512) { throw new RuntimeException('Internal tar header error'); }
    $checksum = array_sum(unpack('C*', $header));
    return substr_replace($header, sprintf("%06o\0 ", $checksum), 148, 8);
}

function wm_write_source_archive(string $path, array $files, int $epoch): void
{
    ksort($files, SORT_STRING);
    $gzip = gzopen($path, 'wb9');
    if ($gzip === false) { throw new RuntimeException('Cannot open corresponding source archive'); }
    try {
        foreach ($files as $name => $source) {
            if (is_link($source) || !is_file($source)) { throw new RuntimeException('Source archive member is not a regular file'); }
            $size = filesize($source);
            $input = fopen($source, 'rb');
            if ($size === false || $input === false || gzwrite($gzip, wm_tar_header($name, $size, 0644, $epoch)) !== 512) {
                throw new RuntimeException('Cannot stream source archive member');
            }
            while (!feof($input)) {
                $chunk = fread($input, 1024 * 1024);
                if ($chunk === false || ($chunk !== '' && gzwrite($gzip, $chunk) !== strlen($chunk))) {
                    throw new RuntimeException('Cannot stream source archive member');
                }
            }
            fclose($input);
            $padding = (512 - $size % 512) % 512;
            if ($padding && gzwrite($gzip, str_repeat("\0", $padding)) !== $padding) {
                throw new RuntimeException('Cannot write source archive padding');
            }
        }
        if (gzwrite($gzip, str_repeat("\0", 1024)) !== 1024) { throw new RuntimeException('Cannot finish source archive'); }
    } finally {
        gzclose($gzip);
    }
}

function wm_build_corresponding_source(string $assembled, string $sourceLock, string $sources, string $signature, string $output): array
{
    if (posix_geteuid() === 0) { throw new RuntimeException('Build as an unprivileged user'); }
    $inputs = wm_json(__DIR__ . '/inputs.json');
    $releaseId = wm_safe_release_id((string)($inputs['release_id'] ?? ''));
    $manifest = wm_json("$assembled/payload-manifest.json");
    if (($manifest['release_id'] ?? null) !== $releaseId) { throw new RuntimeException('Payload release id mismatch'); }
    $auditPath = $output . '.audit.json';
    wm_source_audit("$assembled/payload", $sourceLock, $sources, $auditPath);
    $audit = wm_json($auditPath);
    $sourceInventorySha256 = hash_file('sha256', $auditPath);
    if (is_link($signature) || !is_file($signature)) { throw new RuntimeException('Payload manifest signature is absent'); }
    $gitCommit = trim((string)shell_exec('git -C ' . escapeshellarg(dirname(__DIR__)) . ' rev-parse HEAD 2>/dev/null'));
    if (!preg_match('/^[a-f0-9]{40}$/D', $gitCommit)) { throw new RuntimeException('Cannot identify source revision'); }

    $prefix = $releaseId;
    $files = [];
    foreach (wm_assert_regular_tree("$assembled/payload") as $name => $path) { $files["$prefix/assembled/payload/$name"] = $path; }
    $files["$prefix/assembled/payload-manifest.json"] = "$assembled/payload-manifest.json";
    $files["$prefix/assembled/payload-manifest.json.asc"] = $signature;
    $repository = dirname(__DIR__);
    $reviewed = wm_reviewed_git_files($repository, ['distribution', 'plugins/shcp_sso', 'plugins/shcp_password', 'plugins/shcp_dav', 'jsdeps.json']);
    foreach ($reviewed as $name => $path) {
        $files["$prefix/$name"] = $path;
    }
    $files["$prefix/source-lock.json"] = $sourceLock;
    $files["$prefix/source-inventory.json"] = $auditPath;
    $provenancePath = $output . '.provenance.json';
    wm_write_json($provenancePath, ['format' => 1, 'release_id' => $releaseId,
        'version' => (string)$inputs['version'], 'revision' => (int)$inputs['revision'],
        'source_date_epoch' => (int)$inputs['source_date_epoch'], 'git_commit' => $gitCommit,
        'payload_manifest_sha256' => hash_file('sha256', "$assembled/payload-manifest.json"),
        'source_inventory_sha256' => $sourceInventorySha256,
        'source_lock_sha256' => hash_file('sha256', $sourceLock)]);
    $files["$prefix/archive-provenance.json"] = $provenancePath;
    foreach ($audit['components'] ?? [] as $component) {
        foreach (['source', 'notice'] as $kind) {
            $name = $component[$kind]['file'] ?? '';
            if (!preg_match('/^[A-Za-z0-9_.+-]+$/D', $name)) {
                throw new RuntimeException('Unsafe audited source input');
            }
            $files["$prefix/inputs/$name"] = "$sources/$name";
        }
    }
    $inventory = [];
    foreach ($files as $name => $path) { $inventory[$name] = ['sha256' => hash_file('sha256', $path), 'size' => filesize($path)]; }
    $inventoryPath = $output . '.inventory.json';
    wm_write_json($inventoryPath, ['format' => 1, 'release_id' => $releaseId, 'files' => $inventory]);
    $files["$prefix/archive-inventory.json"] = $inventoryPath;
    wm_write_source_archive($output, $files, (int)$inputs['source_date_epoch']);
    unlink($auditPath);
    unlink($inventoryPath);
    unlink($provenancePath);
    return ['format' => 1, 'release_id' => $releaseId, 'package_name' => 'shcp-webmail',
        'version' => (string)$inputs['version'], 'revision' => (int)$inputs['revision'],
        'source_date_epoch' => (int)$inputs['source_date_epoch'],
        'source' => ['url' => WM_SOURCE_ORIGIN . '/' . rawurlencode($releaseId) . '/' . rawurlencode(basename($output)),
            'filename' => basename($output), 'sha256' => hash_file('sha256', $output), 'size' => filesize($output)],
        'payload_manifest_sha256' => hash_file('sha256', "$assembled/payload-manifest.json"),
        'source_inventory_sha256' => $sourceInventorySha256, 'source_lock_sha256' => hash_file('sha256', $sourceLock),
        'git_commit' => $gitCommit, 'packages' => []];
}

function wm_validate_locator(array $locator): void
{
    $topLevelKeys = ['format', 'release_id', 'package_name', 'version', 'revision', 'source_date_epoch',
        'source', 'payload_manifest_sha256', 'source_inventory_sha256', 'source_lock_sha256', 'git_commit', 'packages'];
    $sourceKeys = ['url', 'filename', 'sha256', 'size'];
    $actualTopLevelKeys = array_keys($locator);
    $actualSourceKeys = array_keys(is_array($locator['source'] ?? null) ? $locator['source'] : []);
    sort($topLevelKeys, SORT_STRING);
    sort($sourceKeys, SORT_STRING);
    sort($actualTopLevelKeys, SORT_STRING);
    sort($actualSourceKeys, SORT_STRING);
    if ($actualTopLevelKeys !== $topLevelKeys || $actualSourceKeys !== $sourceKeys) {
        throw new RuntimeException('Unknown or missing corresponding source metadata key');
    }
    $releaseId = wm_safe_release_id((string)($locator['release_id'] ?? ''));
    $filename = wm_source_filename($releaseId);
    $expected = WM_SOURCE_ORIGIN . '/' . $releaseId . '/' . $filename;
    $source = $locator['source'] ?? [];
    $identityMatches = $releaseId === 'webmail-' . ($locator['version'] ?? '') . '-shcp.' . ($locator['revision'] ?? '');
    $hashFields = ['payload_manifest_sha256', 'source_inventory_sha256', 'source_lock_sha256'];
    $hashesValid = true;
    foreach ($hashFields as $field) { $hashesValid = $hashesValid && preg_match('/^[a-f0-9]{64}$/D', (string)($locator[$field] ?? '')) === 1; }
    if (($locator['format'] ?? null) !== 1 || ($locator['package_name'] ?? null) !== 'shcp-webmail'
        || !preg_match('/^[0-9]+\.[0-9]+\.[0-9]+$/D', (string)($locator['version'] ?? ''))
        || !is_int($locator['revision'] ?? null) || $locator['revision'] < 1 || !$identityMatches
        || !is_int($locator['source_date_epoch'] ?? null) || $locator['source_date_epoch'] < 1
        || !preg_match('/^[a-f0-9]{40}$/D', (string)($locator['git_commit'] ?? '')) || !$hashesValid
        || !is_array($locator['packages'] ?? null) || ($source['filename'] ?? null) !== $filename
        || ($source['url'] ?? null) !== $expected || !preg_match('/^[a-f0-9]{64}$/D', (string)($source['sha256'] ?? ''))
        || !is_int($source['size'] ?? null) || $source['size'] < 1) {
        throw new RuntimeException('Noncanonical corresponding source locator');
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    try {
        if ($argc !== 7 || !($assembled = realpath($argv[1])) || !($lock = realpath($argv[2]))
            || !($sources = realpath($argv[3])) || !($signature = realpath($argv[4]))
            || $argv[5] !== '--output' || $argv[6][0] !== '/') {
            throw new RuntimeException('usage: corresponding-source.php ASSEMBLED SOURCE_LOCK SOURCES SIGNATURE --output ABSOLUTE_ARCHIVE');
        }
        $expected = wm_source_filename((string)wm_json(__DIR__ . '/inputs.json')['release_id']);
        if (basename($argv[6]) !== $expected || file_exists($argv[6]) || is_link($argv[6])) {
            throw new RuntimeException('Source output name is noncanonical or already exists');
        }
        $locator = wm_build_corresponding_source($assembled, $lock, $sources, $signature, $argv[6]);
        wm_validate_locator($locator);
        echo json_encode($locator, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
    } catch (Throwable $error) {
        fwrite(STDERR, 'Corresponding source refused: ' . $error->getMessage() . "\n");
        exit(1);
    }
}

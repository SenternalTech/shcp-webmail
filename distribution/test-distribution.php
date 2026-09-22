#!/usr/bin/env php
<?php
declare(strict_types=1);
require __DIR__ . '/source-audit.php';
require __DIR__ . '/corresponding-source.php';

function check(bool $condition, string $message): void
{
    if (!$condition) { throw new RuntimeException($message); }
    echo "PASS $message\n";
}
function rejected(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable $error) { echo "PASS $message\n"; return; }
    throw new RuntimeException('Unexpected acceptance: ' . $message);
}

$tmp = sys_get_temp_dir() . '/shcp-distribution-test-' . bin2hex(random_bytes(8));
mkdir($tmp, 0700);
try {
    $archive = new PharData("$tmp/input.tar");
    $archive->addFromString('release/index.php', '<?php echo "fixture";');
    $archive->compress(Phar::GZ);
    unset($archive);
    $input = ['prefix' => 'release', 'sha256' => hash_file('sha256', "$tmp/input.tar.gz")];
    mkdir("$tmp/payload");
    rejected(fn() => wm_unpack("$tmp/input.tar.gz", "$tmp/payload", ['prefix' => 'release', 'sha256' => str_repeat('0', 64)]), 'changed input digest is rejected');
    check(count(scandir("$tmp/payload")) === 2, 'digest rejection precedes extraction');
    wm_unpack("$tmp/input.tar.gz", "$tmp/payload", $input);
    $before = wm_inventory("$tmp/payload");
    check(array_keys($before) === ['index.php'], 'valid archive produces only expected member');
    file_put_contents("$tmp/payload/index.php", 'changed bytes');
    check(wm_inventory("$tmp/payload") !== $before, 'payload inventory detects changed content');
    symlink("$tmp/input.tar", "$tmp/payload/link");
    rejected(fn() => wm_inventory("$tmp/payload"), 'payload links are rejected');
    unlink("$tmp/payload/link");
    wm_write_json("$tmp/source-lock.json", ['format' => 1, 'components' => []]);
    rejected(fn() => wm_source_audit("$tmp/payload", "$tmp/source-lock.json", $tmp, "$tmp/sources.json"), 'missing component classification blocks source audit');
    check(!file_exists("$tmp/sources.json"), 'failed audit emits no success inventory');

    file_put_contents("$tmp/member", "deterministic bytes\n");
    $members = ['webmail-1.6.19-shcp.1/member' => "$tmp/member"];
    wm_write_source_archive("$tmp/one.tar.gz", $members, 1789776000);
    wm_write_source_archive("$tmp/two.tar.gz", $members, 1789776000);
    check(hash_file('sha256', "$tmp/one.tar.gz") === hash_file('sha256', "$tmp/two.tar.gz"), 'source archive is reproducible');
    $source = new PharData("$tmp/one.tar.gz");
    check((string)$source['webmail-1.6.19-shcp.1/member']->getContent() === "deterministic bytes\n", 'source archive contains exact bytes');
    rejected(fn() => wm_write_source_archive("$tmp/unsafe.tar.gz", ['../escape' => "$tmp/member"], 1789776000), 'source archive rejects unsafe paths');
    symlink("$tmp/member", "$tmp/source-link");
    rejected(fn() => wm_write_source_archive("$tmp/link.tar.gz", ['release/link' => "$tmp/source-link"], 1789776000), 'source archive rejects links');
    unlink("$tmp/source-link");

    $releaseId = 'webmail-1.6.19-shcp.1';
    $filename = wm_source_filename($releaseId);
    check($filename === 'webmail-1.6.19-shcp.1-source.tar.gz', 'source filename uses the full downstream release id');
    $locator = ['format' => 1, 'release_id' => $releaseId, 'package_name' => 'shcp-webmail',
        'version' => '1.6.19', 'revision' => 1, 'source_date_epoch' => 1789776000,
        'payload_manifest_sha256' => str_repeat('b', 64), 'source_inventory_sha256' => str_repeat('c', 64),
        'source_lock_sha256' => str_repeat('d', 64), 'git_commit' => str_repeat('e', 40), 'packages' => [], 'source' => [
        'url' => WM_SOURCE_ORIGIN . "/$releaseId/$filename", 'filename' => $filename,
        'sha256' => str_repeat('a', 64), 'size' => 1]];
    wm_validate_locator($locator);
    check(true, 'canonical source locator is accepted');
    $locator['source']['url'] = 'https://example.invalid/' . $filename;
    rejected(fn() => wm_validate_locator($locator), 'noncanonical source URL is rejected');
    $locator['source']['url'] = WM_SOURCE_ORIGIN . "/$releaseId/$filename";
    $locator['release_id'] = 'webmail-1.6.19-shcp.2';
    rejected(fn() => wm_validate_locator($locator), 'release mismatch is rejected');
    $locator['release_id'] = $releaseId;
    $locator['revision'] = '1';
    rejected(fn() => wm_validate_locator($locator), 'non-integer revision is rejected');
    $locator['revision'] = 1;
    $locator['unexpected'] = true;
    rejected(fn() => wm_validate_locator($locator), 'unknown top-level release metadata is rejected');
    unset($locator['unexpected']);
    $locator['source']['unexpected'] = true;
    rejected(fn() => wm_validate_locator($locator), 'unknown source metadata is rejected');
} finally {
    $entries = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($tmp, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($entries as $entry) {
        $entry->isDir() && !$entry->isLink() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
    }
    rmdir($tmp);
}

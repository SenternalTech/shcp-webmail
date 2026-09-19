#!/usr/bin/env php
<?php
declare(strict_types=1);
require __DIR__ . '/source-audit.php';

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
} finally {
    $entries = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($tmp, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($entries as $entry) {
        $entry->isDir() && !$entry->isLink() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
    }
    rmdir($tmp);
}

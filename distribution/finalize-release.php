#!/usr/bin/env php
<?php
declare(strict_types=1);
require_once __DIR__ . '/corresponding-source.php';

function wm_command(array $arguments): string
{
    $command = implode(' ', array_map('escapeshellarg', $arguments));
    $output = [];
    $code = 0;
    exec($command, $output, $code);
    if ($code !== 0) { throw new RuntimeException('Package identity inspection failed'); }
    return trim(implode("\n", $output));
}

function wm_package_record(string $path, string $format, string $expectedVersion, string $architecture): array
{
    if (is_link($path) || !is_file($path)) { throw new RuntimeException("Missing regular $format package"); }
    $actualVersion = $format === 'deb'
        ? wm_command(['dpkg-deb', '-f', $path, 'Version'])
        : wm_command(['rpm', '-qp', '--qf', '%{VERSION}-%{RELEASE}', $path]);
    $actualArchitecture = $format === 'deb'
        ? wm_command(['dpkg-deb', '-f', $path, 'Architecture'])
        : wm_command(['rpm', '-qp', '--qf', '%{ARCH}', $path]);
    if ($actualVersion !== $expectedVersion || $actualArchitecture !== $architecture) {
        throw new RuntimeException("$format package identity mismatch");
    }
    return ['format' => $format, 'filename' => basename($path), 'sha256' => hash_file('sha256', $path),
        'size' => filesize($path), 'architecture' => $architecture];
}

try {
    if ($argc !== 4 || $argv[2] !== '--output' || $argv[3][0] !== '/') {
        throw new RuntimeException('usage: finalize-release.php RELEASE_DIRECTORY --output ABSOLUTE_RELEASE_SET');
    }
    $directory = realpath($argv[1]);
    if ($directory === false || is_link($argv[1]) || !is_dir($directory)) { throw new RuntimeException('Invalid release directory'); }
    $inputs = wm_json(__DIR__ . '/inputs.json');
    $releaseId = wm_safe_release_id((string)$inputs['release_id']);
    $basePath = "$directory/$releaseId-release-set.base.json";
    $sourcePath = "$directory/$releaseId-source.tar.gz";
    if (is_link($basePath) || !is_file($basePath) || is_link($sourcePath) || !is_file($sourcePath)) {
        throw new RuntimeException('Base release metadata or source archive is absent');
    }
    $release = wm_json($basePath);
    wm_validate_locator($release);
    if ($release['packages'] !== []) { throw new RuntimeException('Base release metadata already contains package records'); }
    if (hash_file('sha256', $sourcePath) !== $release['source']['sha256'] || filesize($sourcePath) !== $release['source']['size']) {
        throw new RuntimeException('Source archive no longer matches base release metadata');
    }
    $version = (string)$inputs['version'];
    $revision = (int)$inputs['revision'];
    $deb = "shcp-webmail_{$version}+shcp.{$revision}_all.deb";
    $rpm = "shcp-webmail-{$version}-{$revision}.shcp.noarch.rpm";
    $release['packages'] = [
        wm_package_record("$directory/$deb", 'deb', "$version+shcp.$revision", 'all'),
        wm_package_record("$directory/$rpm", 'rpm', "$version-$revision.shcp", 'noarch'),
    ];
    wm_validate_locator($release);
    $output = $argv[3];
    if (realpath(dirname($output)) !== $directory || basename($output) !== "$releaseId-release-set.json") {
        throw new RuntimeException('Final release-set output path is noncanonical');
    }
    if (file_exists($output) || is_link($output)) { throw new RuntimeException('Final release set already exists'); }
    $temporary = tempnam(dirname($output), '.release-set.');
    if ($temporary === false) { throw new RuntimeException('Cannot stage final release set'); }
    wm_write_json($temporary, $release);
    chmod($temporary, 0644);
    if (!link($temporary, $output)) { unlink($temporary); throw new RuntimeException('Cannot publish final release set'); }
    unlink($temporary);
    echo hash_file('sha256', $output), "  ", basename($output), "\n";
} catch (Throwable $error) {
    fwrite(STDERR, 'Release finalization refused: ' . $error->getMessage() . "\n");
    exit(1);
}

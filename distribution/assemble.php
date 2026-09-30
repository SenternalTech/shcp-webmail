#!/usr/bin/env php
<?php
declare(strict_types=1);

// Offline assembly only. Packaging additionally requires the source audit and
// a manifest signature from the separate release authority.
function wm_json(string $path): array
{
    return json_decode(file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
}

function wm_write_json(string $path, array $data): void
{
    if (file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n") === false) {
        throw new RuntimeException('Cannot write build metadata');
    }
}

function wm_directory(string $path): void
{
    if (!is_dir($path) && !mkdir($path, 0755, true)) {
        throw new RuntimeException('Cannot create build directory');
    }
}

function wm_unpack(string $archive, string $destination, array $input): void
{
    if (hash_file('sha256', $archive) !== $input['sha256']) {
        throw new RuntimeException('Input digest mismatch: ' . basename($archive));
    }
    $tar = new PharData($archive);
    $resolvedArchive = realpath($archive);
    if ($resolvedArchive === false || is_link($archive)) {
        throw new RuntimeException('Archive input is not a regular resolved file');
    }
    $base = 'phar://' . $resolvedArchive . '/';
    $members = new RecursiveIteratorIterator($tar, RecursiveIteratorIterator::SELF_FIRST);
    foreach ($members as $entry) {
        $path = $entry->getPathname();
        if (!str_starts_with($path, $base)) {
            throw new RuntimeException('Archive member identity mismatch');
        }
        $name = substr($path, strlen($base));
        $parts = explode('/', $name);
        // This release deliberately retains the existing 1.6 document-root
        // routing. The optional alternate public_html tree consists largely
        // of symlinks and is neither served nor packaged (SC-723).
        if ($input['prefix'] === 'roundcubemail-1.6.19'
            && $parts[0] === $input['prefix'] && ($parts[1] ?? '') === 'public_html') {
            continue;
        }
        if ($parts[0] !== $input['prefix'] || in_array('..', $parts, true)
            || in_array('.', $parts, true) || str_contains($name, '\\')
            || $entry->isLink() || (!$entry->isFile() && !$entry->isDir())) {
            throw new RuntimeException('Unsafe archive member');
        }
        array_shift($parts);
        if (!$parts) {
            if (!$entry->isDir()) {
                throw new RuntimeException('Archive root is not a directory');
            }
            continue;
        }
        $target = $destination . '/' . implode('/', $parts);
        if ($entry->isDir()) {
            wm_directory($target);
            continue;
        }
        wm_directory(dirname($target));
        $source = fopen($path, 'rb');
        $output = fopen($target, 'xb');
        if (!$source || !$output || stream_copy_to_stream($source, $output) === false) {
            throw new RuntimeException('Archive extraction failed');
        }
        fclose($source);
        fclose($output);
        chmod($target, $entry->getPerms() & 0111 ? 0755 : 0644);
    }
}

function wm_inventory(string $directory): array
{
    $result = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $entry) {
        if ($entry->isLink() || (!$entry->isDir() && !$entry->isFile())) {
            throw new RuntimeException('Payload contains a link or special file');
        }
        if ($entry->isFile()) {
            $name = substr($entry->getPathname(), strlen($directory) + 1);
            $result[$name] = ['sha256' => hash_file('sha256', $entry->getPathname()),
                'mode' => sprintf('%04o', $entry->getPerms() & 0777), 'size' => $entry->getSize()];
        }
    }
    ksort($result);
    return $result;
}

function wm_copy_plugin(string $root, string $name, string $destination): void
{
    $source = "$root/plugins/$name";
    if (!is_file("$source/LICENSE")) {
        throw new RuntimeException('Plugin license absent: ' . $name);
    }
    foreach (wm_inventory($source) as $file => $metadata) {
        if (preg_match('~(^|/)\.|(^|/)(vendor|node_modules)(/|$)~', $file)
            || (!in_array(pathinfo($file, PATHINFO_EXTENSION), ['php', 'inc', 'json', 'sql', 'js', 'css', 'md'], true) && $file !== 'LICENSE')) {
            throw new RuntimeException('Unclassified plugin input: ' . $file);
        }
        wm_directory(dirname("$destination/$name/$file"));
        if (!copy("$source/$file", "$destination/$name/$file")) {
            throw new RuntimeException('Plugin copy failed');
        }
        chmod("$destination/$name/$file", 0644);
    }
}

function wm_process(array $command, string $cwd): void
{
    $process = proc_open($command, [STDIN, STDOUT, STDERR], $pipes, $cwd);
    if (!is_resource($process) || proc_close($process) !== 0) {
        throw new RuntimeException('Build command failed');
    }
}

// Removes ordinary files only; the verified extraction rejected links and
// special entries.
function wm_remove_tree(string $path): void
{
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $entry) {
        $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
    }
    rmdir($path);
}

// Rewrites the payload's Composer metadata, which the source audit reads to
// decide what ships. Exactly one entry must match, or the input set changed.
function wm_installed_package(string $payload, string $package, ?callable $edit): void
{
    $path = "$payload/vendor/composer/installed.json";
    $installed = wm_json($path);
    $matches = array_keys(array_filter($installed['packages'], fn($entry) => $entry['name'] === $package));
    if (count($matches) !== 1) {
        throw new RuntimeException('Composer metadata does not identify ' . $package);
    }
    if ($edit === null) {
        array_splice($installed['packages'], $matches[0], 1);
    } else {
        $installed['packages'][$matches[0]] = $edit($installed['packages'][$matches[0]]);
    }
    wm_write_json($path, $installed);
}

function wm_substitute_package(string $inputs, string $output, string $payload, array $input): void
{
    $target = "$payload/{$input['path']}";
    wm_installed_package($payload, $input['package'], function (array $entry) use ($input): array {
        if ($entry['version'] !== $input['replaces']) {
            throw new RuntimeException('Substitution no longer matches upstream: ' . $input['package'] . '@' . $entry['version']);
        }
        $entry['version'] = $input['version'];
        $entry['version_normalized'] = ltrim($input['version'], 'v') . '.0';
        $entry['dist']['url'] = str_replace($entry['dist']['reference'], $input['reference'], $entry['dist']['url']);
        $entry['source']['reference'] = $entry['dist']['reference'] = $input['reference'];
        $entry['time'] = $input['time'];
        $entry['license'] = $input['license'];
        return $entry;
    });
    $scratch = "$output/substitute";
    wm_directory($scratch);
    wm_unpack("$inputs/{$input['file']}", $scratch, $input);
    wm_remove_tree($target);
    foreach ($input['files'] as $file) {
        wm_directory(dirname("$target/$file"));
        if (!is_file("$scratch/$file") || !copy("$scratch/$file", "$target/$file")) {
            throw new RuntimeException('Substitute file absent: ' . $file);
        }
        chmod("$target/$file", 0644);
    }
    wm_remove_tree($scratch);
}

function wm_omit(string $payload, string $component, array $omission): void
{
    if (!is_dir("$payload/{$omission['path']}")) {
        throw new RuntimeException('Omitted component is not in the upstream payload: ' . $component);
    }
    wm_remove_tree("$payload/{$omission['path']}");
    if (isset($omission['package'])) {
        wm_installed_package($payload, $omission['package'], null);
    }
}

function wm_assemble(string $inputs, string $output): void
{
    if (posix_geteuid() === 0) {
        throw new RuntimeException('Build as an unprivileged user');
    }
    $root = dirname(__DIR__);
    $lock = wm_json(__DIR__ . '/inputs.json');
    if (file_exists($output) || is_link($output)) {
        throw new RuntimeException('Output must not already exist');
    }
    wm_directory($output);
    $payload = "$output/payload";
    wm_directory($payload);
    wm_unpack("$inputs/{$lock['roundcube']['file']}", $payload, $lock['roundcube']);
    wm_directory("$payload/plugins/carddav");
    wm_unpack("$inputs/{$lock['carddav']['file']}", "$payload/plugins/carddav", $lock['carddav']);
    if (!is_file(__DIR__ . '/patches/series')) {
        throw new RuntimeException('Reviewed CardDAV patch series is absent');
    }
    foreach (file(__DIR__ . '/patches/series', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $patch) {
        if (str_starts_with($patch, '#')) { continue; }
        if (!preg_match('/^[A-Za-z0-9_.-]+\.patch$/D', $patch)) {
            throw new RuntimeException('Invalid patch series');
        }
        wm_process(['git', 'apply', '--check', __DIR__ . '/patches/' . $patch], "$payload/plugins/carddav");
        wm_process(['git', 'apply', __DIR__ . '/patches/' . $patch], "$payload/plugins/carddav");
    }
    wm_substitute_package($inputs, $output, $payload, $lock['net_socket']);
    foreach ($lock['omit'] as $component => $omission) {
        wm_omit($payload, $component, $omission);
    }
    foreach (['shcp_sso', 'shcp_password', 'shcp_dav'] as $plugin) {
        wm_copy_plugin($root, $plugin, "$payload/plugins");
    }
    copy("$payload/plugins/shcp_password/shcp.php", "$payload/plugins/password/drivers/shcp.php");
    copy("$payload/plugins/shcp_password/LICENSE", "$payload/plugins/password/drivers/shcp.LICENSE");
    $loaders = ['config/config.inc.php' => 'config.inc.php'];
    foreach (['carddav', 'shcp_dav', 'password', 'enigma', 'managesieve'] as $plugin) {
        $loaders["plugins/$plugin/config.inc.php"] = "plugins/$plugin.inc.php";
    }
    foreach ($loaders as $file => $external) {
        file_put_contents("$payload/$file", "<?php\nrequire '/etc/shcp-roundcube/$external';\n");
    }
    // The upstream installer is not served.
    wm_remove_tree("$payload/installer");
    wm_write_json("$output/payload-manifest.json", ['format' => 1, 'release_id' => $lock['release_id'],
        'roundcube_version' => $lock['version'], 'carddav_version' => '5.1.3',
        'protocols' => ['panel_dav' => 1, 'installer_webmail' => 1, 'updater_webmail' => 1],
        'php' => ['minimum' => '8.5', 'extensions' => ['ctype', 'dom', 'fileinfo', 'filter', 'gd', 'iconv', 'intl', 'json', 'mbstring', 'openssl', 'pdo_sqlite', 'session', 'sodium', 'xml', 'zip']],
        'files' => wm_inventory($payload)]);
}

if (realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    try {
        if ($argc !== 3 || !($inputs = realpath($argv[1])) || $argv[2][0] !== '/') {
            throw new RuntimeException('usage: assemble.php INPUT_DIRECTORY ABSOLUTE_OUTPUT_DIRECTORY');
        }
        wm_assemble($inputs, $argv[2]);
    } catch (Throwable $error) {
        fwrite(STDERR, 'Assembly refused: ' . $error->getMessage() . "\n");
        exit(1);
    }
}

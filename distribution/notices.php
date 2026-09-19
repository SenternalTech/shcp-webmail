#!/usr/bin/env php
<?php
declare(strict_types=1);
require_once __DIR__ . '/assemble.php';
if ($argc !== 3) { exit(2); }
echo "shcp-webmail third-party notices\n\n";
foreach (wm_json($argv[1])['components'] as $component) {
    $name = $component['notice']['file'];
    if (basename($name) !== $name || !preg_match('/^[A-Za-z0-9_.+-]+$/D', $name)) { exit(1); }
    echo $component['component'], "\n", $component['license_expression'], "\nSource: ",
        $component['source']['url'], "\n", file_get_contents($argv[2] . '/' . $name), "\n\n";
}

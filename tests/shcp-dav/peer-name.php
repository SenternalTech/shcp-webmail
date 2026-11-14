<?php
// SPDX-License-Identifier: MIT
// Driven by peer-name.sh: argv = <pinned cafile> <port> <loop|other>.
require dirname(__DIR__,2).'/plugins/shcp_dav/lib/Transport.php';
use Shcp\Webmail\Dav\Transport;
[, $ca, $port, $mode] = $argv;
$origin = 'https://panel.example.test:'.$port;
function fails(callable $f): bool { try { $f(); } catch (Throwable $e) { return true; } return false; }
$pinned = new Transport($origin, $ca, 'shcpd.loopback.invalid');
if ($mode === 'other') {
    if (!fails(fn() => $pinned->request('GET', $origin.'/dav/host'))) throw new RuntimeException('another certificate for the same names was accepted');
    echo "SHCP_DAV_PEER_NAME_OK another certificate refused\n";
    exit(0);
}
$r = $pinned->request('GET', $origin.'/dav/host');
if ((json_decode($r['body'], true)['host'] ?? null) !== 'panel.example.test:'.$port) throw new RuntimeException('the Host header is not the origin\'s');
if (!fails(fn() => (new Transport($origin, $ca))->request('GET', $origin.'/dav/host'))) throw new RuntimeException('the origin host verified against a certificate not named for it');
if (!fails(fn() => new Transport($origin, null, 'shcpd.loopback.invalid'))) throw new RuntimeException('a pinned peer name without a cafile was accepted');
if (!fails(fn() => new Transport($origin, $ca, "bad name\r\n"))) throw new RuntimeException('a malformed peer name was accepted');
echo "SHCP_DAV_PEER_NAME_OK pinned name verified, origin Host kept, unpinned and malformed refused\n";

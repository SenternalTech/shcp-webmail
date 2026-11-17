<?php
// SPDX-License-Identifier: MIT
// Driven by tls.sh: argv = <pinned cafile> <port> <panel|other>.
require dirname(__DIR__, 2).'/plugins/shcp_password/shcp.php';
[, $ca, $port, $mode] = $argv;
function need(bool $ok, string $why): void { if (!$ok) { throw new RuntimeException($why); } }
function dial(?array $tls, string $port): bool {
    $fp = @stream_socket_client('ssl://127.0.0.1:'.$port, $e, $s, 5, STREAM_CLIENT_CONNECT, stream_context_create(['ssl' => $tls]));
    if (!is_resource($fp)) { return false; }
    fclose($fp); return true;
}
$byIp = rcube_shcp_password::tls_options($ca, null, '127.0.0.1', 'ssl');
$byName = rcube_shcp_password::tls_options($ca, 'shcpd.loopback.invalid', '127.0.0.1', 'ssl');
if ($mode === 'other') {
    need(!dial($byIp, $port) && !dial($byName, $port), 'another certificate for the same names was accepted');
    echo "SHCP_PASSWORD_TLS_OK another certificate refused\n"; exit(0);
}
need(dial($byIp, $port), 'the pinned anchor did not verify by IP');
need(dial($byName, $port), 'the pinned anchor did not verify by peer name');
need(($byIp['SNI_enabled'] ?? null) === false && ($byName['SNI_enabled'] ?? null) === true, 'SNI must be off for an IP and on for a name');
need(rcube_shcp_password::tls_options($ca, 'wrong.invalid', '127.0.0.1', 'ssl') !== null
    && !dial(rcube_shcp_password::tls_options($ca, 'wrong.invalid', '127.0.0.1', 'ssl'), $port), 'a name the certificate does not carry verified');
need(rcube_shcp_password::tls_options('/nonexistent/ca.pem', null, '127.0.0.1', 'ssl') === null, 'an unreadable cafile did not fail closed');
need(rcube_shcp_password::tls_options('', null, '127.0.0.1', 'ssl') === null, 'an empty cafile did not fail closed');
need(rcube_shcp_password::tls_options($ca, null, '127.0.0.1', 'tcp') === null, 'a pinned cafile on a plain-http endpoint did not fail closed');
need(rcube_shcp_password::tls_options(null, 'shcpd.loopback.invalid', '127.0.0.1', 'ssl') === null, 'a peer name without a cafile did not fail closed');
need(rcube_shcp_password::tls_options($ca, "bad\r\nname", '127.0.0.1', 'ssl') === null, 'a malformed peer name was accepted');
$transport = (new ReflectionMethod(rcube_shcp_password::class, 'tls_options'))->getParameters()[3];
need(!$transport->isOptional(), '$transport has a default again: a caller that omits it skips the plain-http refusal (shcp-webmail#22)');
$legacy = rcube_shcp_password::tls_options(null, null, '127.0.0.1', 'ssl');
need(($legacy['verify_peer'] ?? null) === false, 'unset no longer keeps the historical call');
echo "SHCP_PASSWORD_TLS_OK pinned by IP and by name, wrong name refused, misconfiguration fails closed, unset unchanged\n";

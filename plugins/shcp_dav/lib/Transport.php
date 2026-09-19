<?php
// SPDX-License-Identifier: MIT
namespace Shcp\Webmail\Dav;

/** Fixed-origin transport. Errors deliberately exclude response bodies and credentials. */
final class Transport
{
    private string $origin;
    public function __construct(string $origin, private ?string $caFile = null)
    {
        $p = parse_url($origin);
        if (!is_array($p) || ($p['scheme'] ?? '') !== 'https' || empty($p['host'])
            || isset($p['user'], $p['pass']) || isset($p['user']) || isset($p['query']) || isset($p['fragment'])
            || !in_array($p['path'] ?? '', ['', '/'], true) || preg_match('/[\x00-\x20\\\\]/', $origin)) {
            throw new \RuntimeException('Invalid DAV service origin');
        }
        $this->origin = 'https://' . strtolower($p['host']) . (isset($p['port']) && $p['port'] !== 443 ? ':' . $p['port'] : '');
        if ($caFile !== null && (!is_file($caFile) || !is_readable($caFile))) {
            throw new \RuntimeException('DAV trust store unavailable');
        }
    }
    public function origin(): string { return $this->origin; }
    public function assertDavUrl(string $url): void { $this->validate($url, '/dav/'); }
    private function validate(string $url, string $prefix): void
    {
        $p = parse_url($url);
        if (!is_array($p) || isset($p['user']) || isset($p['pass']) || isset($p['query']) || isset($p['fragment'])
            || ($p['scheme'] ?? '') !== 'https' || empty($p['host']) || preg_match('/[\x00-\x20\\\\]/', $url)) {
            throw new \RuntimeException('Refused DAV request target');
        }
        $origin = 'https://' . strtolower($p['host']) . (isset($p['port']) && $p['port'] !== 443 ? ':' . $p['port'] : '');
        $path = $p['path'] ?? '';
        // Reject ambiguous nested percent encoding, encoded delimiters and dot segments.
        if ($origin !== $this->origin || !str_starts_with($path, $prefix)
            || preg_match('/%(?:2f|5c|2e|25|0[0-9a-f]|1[0-9a-f]|7f)/i', $path)
            || preg_match('#(?:^|/)\.{1,2}(?:/|$)#', $path)) {
            throw new \RuntimeException('Refused DAV request target');
        }
    }
    /** @return array{status:int,headers:array<string,list<string>>,body:string} */
    public function request(string $method, string $url, array $headers = [], string $body = '', ?array $auth = null): array
    {
        $prefix = str_starts_with($url, $this->origin . '/dav/') ? '/dav/' : '/api/internal/webmail/dav/';
        $this->validate($url, $prefix);
        if ($prefix !== '/dav/' && !in_array($url, array_map(fn($s) => $this->origin . '/api/internal/webmail/dav/' . $s, ['exchange','renew','revoke']), true)) {
            throw new \RuntimeException('Refused DAV endpoint');
        }
        if (!in_array($method, ['POST','PROPFIND','REPORT','GET','PUT','DELETE','OPTIONS','PROPPATCH','MKCOL'], true)) {
            throw new \RuntimeException('Refused DAV method');
        }
        $originParts = parse_url($this->origin);
        $host = $originParts['host'];
        $port = $originParts['port'] ?? 443;
        // Validate canonical URLs first; only the dial target is loopback. TLS authenticates the canonical name.
        $connectUrl = 'https://127.0.0.1:' . $port . substr($url, strlen($this->origin));
        $lines = ['Host: ' . $host . ($port === 443 ? '' : ':' . $port), 'Connection: close', 'Cache-Control: no-store'];
        foreach ($headers as $name => $value) {
            if (!preg_match('/\A[A-Za-z0-9-]+\z/', $name) || in_array(strtolower($name), ['authorization','host','connection','content-length'], true)) {
                throw new \RuntimeException('Refused DAV header');
            }
            foreach ((array)$value as $v) {
                if (!is_string($v) || preg_match('/[\r\n\x00]/', $v)) throw new \RuntimeException('Refused DAV header');
                $lines[] = $name . ': ' . $v;
            }
        }
        if ($auth !== null) {
            if (count($auth) !== 2 || str_contains($auth[0], ':') || preg_match('/[\r\n\x00]/', implode('', $auth))) throw new \RuntimeException('Invalid DAV identity');
            $lines[] = 'Authorization: Basic ' . base64_encode($auth[0] . ':' . $auth[1]);
        }
        $ssl = ['verify_peer'=>true,'verify_peer_name'=>true,'allow_self_signed'=>false,'peer_name'=>$host,'SNI_enabled'=>true];
        if ($this->caFile !== null) $ssl['cafile'] = $this->caFile;
        $context = stream_context_create(['ssl'=>$ssl,'http'=>[
            'method'=>$method,'header'=>implode("\r\n",$lines),'content'=>$body,'timeout'=>10,
            'ignore_errors'=>true,'follow_location'=>0,'max_redirects'=>0,'protocol_version'=>1.1,
        ]]);
        $stream = @fopen($connectUrl, 'rb', false, $context);
        if ($stream === false) throw new \RuntimeException('DAV service unavailable');
        try {
            $data = stream_get_contents($stream, 16 * 1024 * 1024 + 1);
            $meta = stream_get_meta_data($stream);
            if ($data === false || strlen($data) > 16 * 1024 * 1024 || ($meta['timed_out'] ?? false)) throw new \RuntimeException('Invalid DAV service response');
            $status = 0; $responseHeaders = [];
            foreach ((array)($meta['wrapper_data'] ?? []) as $line) {
                if (preg_match('#^HTTP/\S+ (\d{3})#', $line, $m)) { $status=(int)$m[1]; $responseHeaders=[]; }
                elseif (str_contains($line, ':')) { [$n,$v]=explode(':',$line,2); $responseHeaders[strtolower(trim($n))][]=trim($v); }
            }
            if ($status < 200 || ($status >= 300 && $status < 400)) throw new \RuntimeException('Refused DAV redirect or response');
            return ['status'=>$status,'headers'=>$responseHeaders,'body'=>$data];
        } finally { fclose($stream); }
    }
    public function api(string $operation, array $payload): array
    {
        $r=$this->request('POST',$this->origin.'/api/internal/webmail/dav/'.$operation,['Content-Type'=>'application/json'],json_encode($payload,JSON_THROW_ON_ERROR));
        if ($r['status'] < 200 || $r['status'] >= 300) throw new \RuntimeException('DAV session unavailable');
        $data=json_decode($r['body'],true,16,JSON_THROW_ON_ERROR);
        if (!is_array($data)) throw new \RuntimeException('Invalid DAV session response');
        return $data;
    }
}
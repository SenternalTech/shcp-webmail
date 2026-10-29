<?php
// SPDX-License-Identifier: MIT

require __DIR__ . '/../plugins/shcp_sso/LoginLimiter.php';

class rcube_plugin
{
    public array $hooks = [];

    public function add_hook(string $name, array $callback): void
    {
        $this->hooks[$name] = $callback;
    }
}

class rcube
{
    public static array $logs = [];

    public static function write_log(string $name, string $message): void
    {
        self::$logs[] = [$name, $message];
    }

    public static array $errors = [];

    public static function raise_error(array $error, bool $log = false, bool $terminate = false): void
    {
        self::$errors[] = $error['message'] ?? '';
    }
}

class TestConfig
{
    public function __construct(public array $values)
    {
    }

    public function get(string $name, mixed $default = null): mixed
    {
        return $this->values[$name] ?? $default;
    }
}

class rcmail
{
    public string $task = 'login';
    public static self $instance;

    public function __construct(public TestConfig $config)
    {
        self::$instance = $this;
    }

    public static function get_instance(): self
    {
        return self::$instance;
    }
}

require __DIR__ . '/../plugins/shcp_sso/shcp_sso.php';

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$dir = sys_get_temp_dir() . '/shcp-login-' . bin2hex(random_bytes(8));
mkdir($dir, 0700);
$db = $dir . '/attempts.sqlite';
try {
    $limiter = new ShcpLoginLimiter($db);
    $server = ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.4', 'HTTP_X_SHCP_WEBMAIL_PROXY_AUTH' => 'correct'];
    check($limiter->client($server, ['127.0.0.1'], 'correct') === '198.51.100.4', 'authenticated edge IP');
    check($limiter->client($server, ['127.0.0.1'], 'wrong') === '127.0.0.1', 'wrong edge secret');
    check($limiter->client($server, [], 'correct') === '127.0.0.1', 'undeclared proxy');
    check($limiter->client($server + ['HTTP_FORWARDED' => 'for=203.0.113.2'], ['127.0.0.1'], 'correct') === '198.51.100.4', 'XFF precedence');
    $server['HTTP_X_FORWARDED_FOR'] = '203.0.113.7, bad-ip';
    check($limiter->client($server, ['127.0.0.1'], 'correct') === '127.0.0.1', 'malformed chain');
    $server['HTTP_X_FORWARDED_FOR'] = '198.51.100.4, 192.0.2.3';
    check($limiter->client($server, ['127.0.0.1', '192.0.2.3'], 'correct') === '198.51.100.4', 'trusted chain');

    $server['REMOTE_ADDR'] = '192.0.2.10';
    $server['HTTP_X_FORWARDED_FOR'] = '198.51.100.4';
    check($limiter->client($server, ['192.0.2.0/24'], 'correct') === '198.51.100.4', 'IPv4 CIDR peer');
    check($limiter->client($server, ['192.0.2.0/24'], 'wrong') === '192.0.2.10', 'CIDR peer still requires secret');
    check($limiter->client($server, ['192.0.2.0/29'], 'correct') === '192.0.2.10', 'IPv4 CIDR outside range');
    check($limiter->client($server, ['192.0.2.10/32'], 'correct') === '198.51.100.4', 'IPv4 host CIDR');
    $server['HTTP_X_FORWARDED_FOR'] = '2001:db8::4';
    check($limiter->client($server, ['192.0.2.0/0'], 'correct') === '2001:db8::4', 'explicit IPv4 default range');
    $server['HTTP_X_FORWARDED_FOR'] = '198.51.100.4';
    check($limiter->client($server, ['192.0.2.11'], 'correct') === '192.0.2.10', 'bare IPv4 is exact');
    foreach (['192.0.2.0/', '192.0.2.0/33', '192.0.2.0/-1', '192.0.2.0/24junk', '192.0.2.0/024', '192.0.2.0//24', 'bad/0'] as $bad) {
        check($limiter->client($server, [$bad], 'correct') === '192.0.2.10', 'malformed IPv4 declaration: ' . $bad);
    }

    $server['REMOTE_ADDR'] = '2001:db8:1::a';
    check($limiter->client($server, ['2001:db8:1::/64'], 'correct') === '198.51.100.4', 'IPv6 CIDR peer');
    check($limiter->client($server, ['2001:db8:2::/64'], 'correct') === '2001:db8:1::a', 'IPv6 CIDR outside range');
    check($limiter->client($server, ['2001:db8:1::a/128'], 'correct') === '198.51.100.4', 'IPv6 host CIDR');
    check($limiter->client($server, ['2001:db8:1::b'], 'correct') === '2001:db8:1::a', 'bare IPv6 is exact');
    foreach (['2001:db8::/129', '2001:db8::/64extra', '2001:db8::/-1'] as $bad) {
        check($limiter->client($server, [$bad], 'correct') === '2001:db8:1::a', 'malformed IPv6 declaration: ' . $bad);
    }

    $server['REMOTE_ADDR'] = '::ffff:192.0.2.10';
    check($limiter->client($server, ['192.0.2.0/24'], 'correct') === '198.51.100.4', 'mapped peer matches IPv4 CIDR');
    check($limiter->client($server, ['::ffff:192.0.2.0/120'], 'correct') === '198.51.100.4', 'mapped IPv6 CIDR');
    check($limiter->client($server, ['::ffff:192.0.2.0/95'], 'correct') === '::ffff:192.0.2.10', 'mapped CIDR outside mapped space rejected');
    $server['REMOTE_ADDR'] = '192.0.2.10';
    check($limiter->client($server, ['::ffff:192.0.2.0/120'], 'correct') === '198.51.100.4', 'IPv4 peer matches mapped CIDR');
    $server['HTTP_X_FORWARDED_FOR'] = '198.51.100.4, 192.0.2.3';
    check($limiter->client($server, ['192.0.2.0/24'], 'correct') === '198.51.100.4', 'CIDR trusted chain');
    $server['HTTP_X_FORWARDED_FOR'] = '198.51.100.4, ::ffff:192.0.2.3';
    check($limiter->client($server, ['192.0.2.0/24'], 'correct') === '198.51.100.4', 'mapped trusted chain');

    check($limiter->allowed('198.51.100.4', 'alice@example.test'), 'initial login');
    for ($i = 0; $i < 10; $i++) {
        $limiter->failed('198.51.100.4', 'alice@example.test');
    }
    check(!$limiter->allowed('198.51.100.4', 'alice@example.test'), 'limit after failures');
    check($limiter->allowed('203.0.113.9', 'ALICE@example.test'), 'account signal never locks a new client');
    check($limiter->delay('203.0.113.9', 'ALICE@example.test') > 0, 'account signal delays new client');
    check($limiter->delay('203.0.113.9', 'ALICE@example.test', true) === 0, 'recent successful client bypasses account delay');
    check($limiter->allowed('203.0.113.9', 'bob@example.test'), 'other account and client');
    check(!$limiter->allowed('198.51.100.4', 'bob@example.test'), 'client bucket across accounts');
    $limiter2 = new ShcpLoginLimiter($db);
    check(!$limiter2->allowed('198.51.100.4', 'alice@example.test'), 'persistent shared limit');
    (new PDO('sqlite:' . $db))->exec('UPDATE attempts SET expires = 1');
    check($limiter2->allowed('198.51.100.4', 'alice@example.test'), 'expired failures cleared');
    check((int) (new PDO('sqlite:' . $db))->query('SELECT count(*) FROM attempts')->fetchColumn() === 0, 'allowed check commits expiry cleanup');
    for ($i = 0; $i < 10; $i++) {
        $limiter2->failed('198.51.100.' . ($i + 10), 'victim@example.test');
    }
    check($limiter2->allowed('203.0.113.77', 'victim@example.test'), 'distributed guesses cannot lock victim');
    check($limiter2->delay('203.0.113.77', 'victim@example.test') > 0, 'distributed guesses signal delay');
    $cookie = $limiter2->successCookie('203.0.113.77', 'victim@example.test', 'cookie-key', 1000000000);
    check($limiter2->recentSuccess($cookie, '203.0.113.77', 'VICTIM@example.test', 'cookie-key', 1000000001), 'signed recent success');
    check(!$limiter2->recentSuccess($cookie, '203.0.113.78', 'victim@example.test', 'cookie-key', 1000000001), 'cookie bound to client');
    check(!$limiter2->recentSuccess($cookie, '203.0.113.77', 'other@example.test', 'cookie-key', 1000000001), 'cookie bound to account');
    check(!$limiter2->recentSuccess($cookie, '203.0.113.77', 'victim@example.test', 'other-key', 1000000001), 'cookie signature');
    check(!$limiter2->recentSuccess($cookie, '203.0.113.77', 'victim@example.test', 'cookie-key', 1000086401), 'cookie expiry');
    check($limiter2->successCookie('203.0.113.77', 'victim@example.test', '') === '', 'no unsigned bypass cookie');
    for ($i = 0; $i < 10; $i++) {
        $limiter2->failed('203.0.113.88', 'pair@example.test');
    }
    check(!$limiter2->allowed('203.0.113.88', 'pair@example.test'), 'account client pair hard limit');
    check(!(new ShcpLoginLimiter($dir . '/missing/attempts.sqlite'))->allowed('198.51.100.4', 'alice@example.test'), 'storage error fails closed');

    new rcmail(new TestConfig(['temp_dir' => $dir, 'shcp_login_trusted_proxies' => ['127.0.0.1'], 'shcp_login_proxy_secret' => 'correct']));
    $plugin = new shcp_sso();
    $plugin->init();
    check(isset($plugin->hooks['authenticate'], $plugin->hooks['login_failed'], $plugin->hooks['login_after']), 'login hooks registered');
    $_SERVER = ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.22', 'HTTP_X_SHCP_WEBMAIL_PROXY_AUTH' => 'correct'];
    for ($i = 0; $i < 10; $i++) {
        $args = $plugin->limit_login(['valid' => true, 'user' => 'target@example.test']);
        check(empty($args['abort']), 'login allowed before limit');
        $plugin->mark_login_failed(['user' => 'target@example.test']);
    }
    $args = $plugin->limit_login(['valid' => true, 'user' => 'target@example.test']);
    check(!empty($args['abort']) && str_contains($args['error'], 'Too many'), 'login hook blocks with message');
    check(str_contains(rcube::$logs[count(rcube::$logs) - 1][1], '203.0.113.22'), 'block logs client');
    echo "PASS SHCP login limiter\n";

    // SC-707: the verifier key comes only from the fixed root-owned file. A key
    // planted in Roundcube config (a second $config line wins in PHP) must not
    // verify a token its holder signed.
    $attacker = sodium_crypto_sign_keypair();
    new rcmail(new TestConfig(['temp_dir' => $dir, 'shcp_sso_public_key' => base64_encode(sodium_crypto_sign_publickey($attacker))]));
    $payload = base64_encode(json_encode(['email' => 'victim@example.test', 'exp' => time() + 60, 'nonce' => bin2hex(random_bytes(16))]));
    $token = $payload . '.' . bin2hex(sodium_crypto_sign_detached('shcp-webmail-sso-v1.' . $payload, sodium_crypto_sign_secretkey($attacker)));
    rcube::$errors = [];
    try {
        $result = (new ReflectionMethod(shcp_sso::class, 'validate_token'))->invoke(new shcp_sso(), $token);
    } catch (Throwable $e) {
        throw new RuntimeException('config-planted key got past the signature check: ' . $e->getMessage());
    }
    check($result === null, 'config-planted key verifies no token');
    check(array_intersect(rcube::$errors, ['SSO: public-key file missing or malformed', 'SSO: Invalid token signature']) !== [], 'refused at the key or the signature, not later');
    echo "PASS SHCP SSO trust root\n";

    // SC-682 as amended (tool hosts): the hand-off POST's origin check, before
    // and after the cutover. Before it, today's same-origin rule; after it, the
    // exact panel Origin with same-origin, same-site or no Sec-Fetch-Site.
    $origin = new ReflectionMethod(shcp_sso::class, 'request_is_same_origin');
    $from = static function (array $config, array $server) use ($origin): bool {
        new rcmail(new TestConfig($config));
        $_SERVER = $server;

        return $origin->invoke(new shcp_sso());
    };
    $before = ['shcp_sso_panel_hosts' => ['panel.example.test']];
    check($from($before, ['HTTP_SEC_FETCH_SITE' => 'same-origin']), 'before cutover: same-origin accepted');
    check(!$from($before, ['HTTP_SEC_FETCH_SITE' => 'same-site', 'HTTP_ORIGIN' => 'https://panel.example.test']), 'before cutover: same-site refused');
    check($from($before, ['HTTP_ORIGIN' => 'https://panel.example.test']), 'before cutover: no Sec-Fetch-Site, listed host accepted');

    $after = $before + ['shcp_sso_panel_origin' => 'https://panel.example.test'];
    $panel = 'https://panel.example.test';
    check($from($after, ['HTTP_SEC_FETCH_SITE' => 'same-site', 'HTTP_ORIGIN' => $panel]), 'after cutover: panel Origin, same-site accepted');
    check($from($after, ['HTTP_ORIGIN' => $panel]), 'after cutover: panel Origin, no Sec-Fetch-Site accepted');
    $refused = [
        'sibling Origin' => ['HTTP_SEC_FETCH_SITE' => 'same-site', 'HTTP_ORIGIN' => 'https://shop.example.test'],
        'Origin null' => ['HTTP_SEC_FETCH_SITE' => 'same-site', 'HTTP_ORIGIN' => 'null'],
        'missing Origin' => ['HTTP_SEC_FETCH_SITE' => 'same-site'],
        'missing Origin, same-origin' => ['HTTP_SEC_FETCH_SITE' => 'same-origin'],
        'cross-site with panel Origin' => ['HTTP_SEC_FETCH_SITE' => 'cross-site', 'HTTP_ORIGIN' => $panel],
        'none with panel Origin' => ['HTTP_SEC_FETCH_SITE' => 'none', 'HTTP_ORIGIN' => $panel],
        'panel Origin with a port' => ['HTTP_SEC_FETCH_SITE' => 'same-site', 'HTTP_ORIGIN' => $panel . ':8443'],
        'http panel Origin' => ['HTTP_SEC_FETCH_SITE' => 'same-site', 'HTTP_ORIGIN' => 'http://panel.example.test'],
        'panel suffix' => ['HTTP_SEC_FETCH_SITE' => 'same-site', 'HTTP_ORIGIN' => $panel . '.evil.test'],
    ];
    foreach ($refused as $case => $server) {
        check(!$from($after, $server), 'after cutover: refused, ' . $case);
    }
    foreach (['', 'panel.example.test', 'https://panel.example.test/', ['https://panel.example.test'], 'https://PANEL.example.test'] as $bad) {
        check(!$from(['shcp_sso_panel_origin' => $bad], ['HTTP_SEC_FETCH_SITE' => 'same-site', 'HTTP_ORIGIN' => $panel]), 'malformed panel origin refuses: ' . json_encode($bad));
    }
    echo "PASS SHCP SSO hand-off origin\n";
} finally {
    foreach (glob($dir . '/*') as $file) {
        unlink($file);
    }
    rmdir($dir);
}

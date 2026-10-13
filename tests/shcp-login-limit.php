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

    check($limiter->allowed('198.51.100.4', 'alice@example.test'), 'initial login');
    for ($i = 0; $i < 10; $i++) {
        $limiter->failed('198.51.100.4', 'alice@example.test');
    }
    check(!$limiter->allowed('198.51.100.4', 'alice@example.test'), 'limit after failures');
    check(!$limiter->allowed('203.0.113.9', 'ALICE@example.test'), 'account bucket across clients');
    check($limiter->allowed('203.0.113.9', 'bob@example.test'), 'other account and client');
    check(!$limiter->allowed('198.51.100.4', 'bob@example.test'), 'client bucket across accounts');
    $limiter2 = new ShcpLoginLimiter($db);
    check(!$limiter2->allowed('198.51.100.4', 'alice@example.test'), 'persistent shared limit');
    (new PDO('sqlite:' . $db))->exec('UPDATE attempts SET expires = 1');
    check($limiter2->allowed('198.51.100.4', 'alice@example.test'), 'expired failures cleared');
    check(!(new ShcpLoginLimiter($dir . '/missing/attempts.sqlite'))->allowed('198.51.100.4', 'alice@example.test'), 'storage error fails closed');

    new rcmail(new TestConfig(['temp_dir' => $dir, 'shcp_login_trusted_proxies' => ['127.0.0.1'], 'shcp_login_proxy_secret' => 'correct']));
    $plugin = new shcp_sso();
    $plugin->init();
    check(isset($plugin->hooks['authenticate'], $plugin->hooks['login_failed']), 'login hooks registered');
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
} finally {
    foreach (glob($dir . '/*') as $file) {
        unlink($file);
    }
    rmdir($dir);
}

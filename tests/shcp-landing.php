<?php
// SPDX-License-Identifier: MIT
//
// shcp_sso's panel mail landing redirect (shcp-master#3897, plan AD7/AD10/R9):
// a bare GET of the login page with no session goes to shcp_landing_url; the
// login POST, _shcp_direct=1, AJAX/framed requests, an authenticated session,
// an unset URL and a malformed URL leave Roundcube's own form in place; logout
// goes to the landing's signed-out page only when the URL is set. Run as
// `php tests/shcp-landing.php`; exits non-zero on the first failed check.

class rcube_plugin
{
    public array $hooks = [];

    public function add_hook(string $name, array $callback): void
    {
        $this->hooks[$name][] = $callback;
    }
}

class rcube
{
    public static array $errors = [];

    public static function write_log(string $name, string $message): void
    {
    }

    public static function raise_error(array $error, bool $log = false, bool $terminate = false): void
    {
        self::$errors[] = $error['message'] ?? '';
    }
}

class rcube_utils
{
    public const INPUT_GET = 1;
    public const INPUT_POST = 2;
    public const INPUT_GP = 3;

    public static function get_input_string(string $name, int $source): string
    {
        $value = null;
        if ($source & self::INPUT_GET) {
            $value = $_GET[$name] ?? null;
        }
        if ($value === null && ($source & self::INPUT_POST)) {
            $value = $_POST[$name] ?? null;
        }

        return is_string($value) ? $value : '';
    }
}

class RedirectIssued extends Exception
{
}

class TestOutput
{
    public ?string $location = null;

    public function redirect(mixed $p, int $delay = 0, bool $secure = false): never
    {
        // rcmail::url() returns an absolute https URL unchanged; the stub pins that contract.
        if (!is_string($p) || !preg_match('#^https?://#', $p)) {
            throw new RuntimeException('redirect() was handed something other than an absolute URL');
        }
        $this->location = $p;
        throw new RedirectIssued($p);
    }
}

class TestConfig
{
    public function __construct(public array $values)
    {
    }

    public function get(string $name, mixed $default = null): mixed
    {
        return array_key_exists($name, $this->values) ? $this->values[$name] : $default;
    }
}

class rcmail
{
    public string $task = 'login';
    public string $action = '';
    public object $user;
    public TestOutput $output;
    public static self $instance;

    public function __construct(public TestConfig $config, ?int $userId = null)
    {
        $this->user = (object) ['ID' => $userId];
        $this->output = new TestOutput();
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

/**
 * Runs the startup hook the way index.php does and reports where it sent the browser, if anywhere.
 *
 * @param array<string, mixed> $config
 * @param array<string, string> $get
 */
function landing_redirect(array $config, string $method = 'GET', array $get = [], string $task = 'login', string $action = '', ?int $userId = null): ?string
{
    $_GET = $get;
    $_POST = [];
    $_SERVER['REQUEST_METHOD'] = $method;
    rcube::$errors = [];
    $rcmail = new rcmail(new TestConfig($config), $userId);
    $rcmail->task = $task;
    $rcmail->action = $action;
    $plugin = new shcp_sso();
    $plugin->init();
    try {
        foreach ($plugin->hooks['startup'] ?? [] as $callback) {
            $callback(['task' => $task, 'action' => $action]);
        }
    } catch (RedirectIssued $redirect) {
        return $redirect->getMessage();
    }

    return null;
}

/** @param array<string, mixed> $config */
function logout_redirect(array $config): ?string
{
    rcube::$errors = [];
    $rcmail = new rcmail(new TestConfig($config), 7);
    $rcmail->task = 'logout';
    $plugin = new shcp_sso();
    $plugin->init();
    try {
        foreach ($plugin->hooks['logout_after'] ?? [] as $callback) {
            $callback(['user' => 'alice@example.test', 'host' => 'localhost', 'lang' => 'en_US']);
        }
    } catch (RedirectIssued $redirect) {
        return $redirect->getMessage();
    }

    return null;
}

$landing = ['shcp_landing_url' => 'https://panel.example.com/mail-account'];

try {
    // Hook wiring: the startup redirect is registered on the login task only; logout_after always.
    new rcmail(new TestConfig($landing));
    $plugin = new shcp_sso();
    $plugin->init();
    $startup = array_map(static fn (array $cb): string => $cb[1], $plugin->hooks['startup']);
    check($startup === ['check_sso_token', 'redirect_to_landing'], 'startup hooks: the token check runs before the landing redirect');
    check(($plugin->hooks['logout_after'][0][1] ?? null) === 'redirect_after_logout', 'logout_after hook registered');
    $mail = new rcmail(new TestConfig($landing));
    $mail->task = 'mail';
    $plugin = new shcp_sso();
    $plugin->init();
    check(!isset($plugin->hooks['startup']), 'no startup hook outside the login task');
    check(isset($plugin->hooks['logout_after']), 'logout_after registered on every task');

    // The bare GET of the form moves; a trailing slash on the configured URL is dropped.
    check(landing_redirect($landing) === 'https://panel.example.com/mail-account', 'bare login GET goes to the landing');
    check(landing_redirect(['shcp_landing_url' => 'https://panel.example.com/mail-account/']) === 'https://panel.example.com/mail-account', 'trailing slash normalised');
    check(landing_redirect($landing, 'GET', ['_task' => 'login']) === 'https://panel.example.com/mail-account', 'explicit _task=login GET goes too');
    // A logout clicked after the Roundcube session expired is a session-less GET of the login task
    // (set_task() forces 'login'), so it never reaches logout_after: it still ends the landing session.
    check(landing_redirect($landing, 'GET', ['_task' => 'logout', '_token' => 'abc']) === 'https://panel.example.com/mail-account/webmail-signed-out', 'a session-less logout GET goes to the signed-out page');
    check(landing_redirect($landing, 'GET', ['_task' => 'login', '_err' => 'session']) === 'https://panel.example.com/mail-account', 'an expired session goes to the landing, not signed-out');

    // Untouched paths: Roundcube's own form stays reachable.
    check(landing_redirect($landing, 'GET', ['_shcp_direct' => '1']) === null, '_shcp_direct=1 is the escape');
    check(landing_redirect($landing, 'GET', ['_shcp_direct' => '0']) === 'https://panel.example.com/mail-account', 'only the value 1 escapes');
    check(landing_redirect($landing, 'POST', [], 'login', 'login') === null, 'the login POST is untouched');
    check(landing_redirect($landing, 'GET', [], 'login', 'login') === null, 'a GET of the login action is untouched');
    check(landing_redirect($landing, 'GET', [], 'login', 'oauth') === null, 'the OAuth action is untouched');
    check(landing_redirect($landing, 'POST') === null, 'a POST with no action is untouched');
    check(landing_redirect($landing, 'GET', ['_remote' => '1']) === null, 'an AJAX request gets session_error, not a redirect');
    check(landing_redirect($landing, 'GET', ['_framed' => '1']) === null, 'a framed request gets session_error, not a redirect');
    check(landing_redirect($landing, 'GET', [], 'login', '', 42) === null, 'an authenticated session is untouched');
    check(landing_redirect($landing, 'GET', [], 'mail') === null, 'another task is untouched');

    // Unset means nothing changes; a malformed URL disables the redirect and is logged.
    check(landing_redirect([]) === null, 'unset URL: no redirect');
    check(landing_redirect(['shcp_landing_url' => null]) === null, 'null URL: no redirect');
    check(landing_redirect(['shcp_landing_url' => '']) === null, 'empty URL: no redirect');
    check(rcube::$errors === [], 'unset, null and empty are not errors');
    foreach ([
        'http://panel.example.com/mail-account',
        'https://panel.example.com/mail-account?next=webmail',
        'https://panel.example.com/mail-account#x',
        'https://user:pw@panel.example.com/mail-account',
        'https://panel.example.com/mail account',
        "https://panel.example.com/mail-account\n",
        "\nhttps://panel.example.com/mail-account",
        'https://PANEL.example.com/mail-account',
        'https://panel.example.com?x=1',
        'javascript:alert(1)',
        '//panel.example.com/mail-account',
        'panel.example.com/mail-account',
        ['https://panel.example.com/mail-account'],
    ] as $bad) {
        check(landing_redirect(['shcp_landing_url' => $bad]) === null, 'malformed URL disables the redirect: ' . json_encode($bad));
        check(count(rcube::$errors) === 1 && str_contains(rcube::$errors[0], 'shcp_landing_url'), 'malformed URL is logged: ' . json_encode($bad));
    }

    // Logout ends the landing session only when the landing is configured.
    check(logout_redirect($landing) === 'https://panel.example.com/mail-account/webmail-signed-out', 'logout goes to the signed-out page');
    check(logout_redirect([]) === null, 'logout without a landing is untouched');
    check(logout_redirect(['shcp_landing_url' => 'http://panel.example.com/mail-account']) === null, 'logout with a malformed landing is untouched');
} catch (RuntimeException $e) {
    fwrite(STDERR, 'FAIL: ' . $e->getMessage() . "\n");
    exit(1);
}

echo "shcp-landing: ok\n";

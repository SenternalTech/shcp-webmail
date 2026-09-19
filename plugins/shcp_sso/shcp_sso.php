<?php

/**
 * SHCP SSO Plugin for Roundcube
 *
 * Enables single sign-on from the SHCP panel to Roundcube webmail.
 * Users click "Open Webmail" in the panel and land directly in their inbox.
 *
 * The panel does not know the mailbox password, so this plugin authenticates
 * Roundcube against Dovecot with a dedicated SSO master credential (SASL PLAIN
 * proxy auth): the mailbox user is the authorization identity (authzid) and the
 * master user/password is the authentication identity. The credential is
 * injected per connection and ONLY for a request that passed SSO token
 * validation — never as a global imap_auth_cid, which would make every login
 * passwordless into any mailbox.
 *
 * Configuration (config.inc.php):
 *   $config['plugins'][] = 'shcp_sso';
 *   // base64 of the panel's 32-byte Ed25519 PUBLIC key (verify only).
 *   $config['shcp_sso_public_key'] = 'base64-public-key';
 *   $config['shcp_sso_cache'] = 'db';
 *   // Root-owned sidecar (0640 root:<apache group>) holding two lines:
 *   //   <sso master user>\n<sso master password>
 *   $config['shcp_sso_master_file'] = '/etc/shcp-roundcube/sso-master';
 *   // Host names the panel vhost answers to (no loopback, IPv6 bracketed).
 *   // Only consulted for a browser that sends no Sec-Fetch-Site header.
 *   $config['shcp_sso_panel_hosts'] = ['panel.example.com', '203.0.113.10'];
 *
 * Token format: base64(json_payload).hex(ed25519_signature)
 * Payload: {"email": "user@domain.com", "exp": unix_timestamp, "nonce": "random_hex"}
 * Delivery: POST field _sso_token (the panel auto-submits a form). A token in
 * the query string is ignored.
 *
 * @author SHCP
 * @license MIT
 */
class shcp_sso extends rcube_plugin
{
    /**
     * Prefixed to the payload before the panel signs it, so a signature made with
     * the same key for anything else is never a webmail login. Identical to
     * shcp-base RoundcubeSsoService::SIGNATURE_CONTEXT.
     */
    private const SIGNATURE_CONTEXT = 'shcp-webmail-sso-v1.';

    /**
     * In-request marker that this request passed SSO token validation.
     *
     * The first storage_connect fires inside login(), before the session write
     * is durable, so the session flag alone cannot gate that first connection.
     * This instance flag covers the login request; subsequent requests (the
     * 'mail' task reconnect) rely on $_SESSION['shcp_sso_active'].
     */
    private bool $sso_active = false;

    private ?string $dav_ticket = null;

    /**
     * Initialize the plugin.
     *
     * No $task restriction: the injection hooks must run on EVERY task. After
     * the SSO redirect the 'mail' task reconnects to IMAP/SMTP with the empty
     * session password, so the master credential has to be re-injected on each
     * request. Declaring $task = 'login' (the previous behaviour) makes
     * rcube_plugin_api::filter() skip this plugin on 'mail', so storage_connect
     * never fires there and the reconnect fails with "Empty password".
     */
    public function init(): void
    {
        $this->add_hook('storage_connect', [$this, 'inject_imap_auth']);
        $this->add_hook('smtp_connect', [$this, 'inject_smtp_auth']);
        // ManageSieve (Settings -> Filters) opens its own connection using the
        // session password, which is empty for an SSO session; proxy-auth it the
        // same way. The managesieve plugin is enabled in the shipped config.
        $this->add_hook('managesieve_connect', [$this, 'inject_sieve_auth']);
        // Every failed login must leave a countable trace (see mark_login_failed).
        $this->add_hook('login_failed', [$this, 'mark_login_failed']);

        // The SSO token is only ever presented to the login task. rcmail forces
        // task 'login' whenever there is no authenticated user, so the initial
        // token request always lands there; keep the token-consuming path off
        // every other task.
        if (rcmail::get_instance()->task === 'login') {
            $this->add_hook('startup', [$this, 'check_sso_token']);
        }
    }

    /**
     * Answer every failed login with HTTP 401, whatever the output mode.
     *
     * The host's webmail brute-force ban counts POSTs to Roundcube answered 401
     * (it reads the web server's own log; it cannot see Roundcube's). Roundcube
     * sends 401 for a failed login only on the plain page path: a login sent with
     * _framed=1 or _remote=1 is still password-checked, but that output path
     * exits with 200 before the 401 is set, so those guesses were never counted.
     * The login_failed hook fires on every failed login, before any output, so
     * setting the status here makes all of them count the same way.
     *
     * Only the status changes; the response body is Roundcube's own.
     */
    public function mark_login_failed(array $args): array
    {
        if (!headers_sent()) {
            http_response_code(401);
        }

        return $args;
    }

    /**
     * Check for an SSO token in the request and authenticate if it is valid.
     */
    public function check_sso_token(array $args): array
    {
        $rcmail = rcmail::get_instance();

        // The token is read from the POST body ONLY, never the query string
        // (installer#929). A request URI is copied into logs this plugin cannot
        // scrub: the edge Apache access log records the request line, and
        // rcube::raise_error() appends REQUEST_URI to every error it logs,
        // including the ones below. A token rejected before its nonce is
        // reserved (e.g. a database error in reserve_nonce()) stays valid until
        // it expires, so a logged copy is a replayable login. Neither log
        // records a POST body. Do not widen this to INPUT_GET/INPUT_GP.
        // Roundcube's own request-token check (request_security_check()) runs in
        // index.php after this startup hook, so the POST needs no Roundcube
        // form token; the Ed25519 signature and single-use nonce authenticate the
        // token, and request_is_same_origin() stands in for the CSRF check
        // Roundcube never gets to run.
        // get_input_string, not get_input_value: an array-valued _sso_token[]
        // must read as '' rather than reach validate_token(string) as an array.
        $token = rcube_utils::get_input_string('_sso_token', rcube_utils::INPUT_POST);

        // Skip if no token or already logged in
        if (empty($token) || !empty($rcmail->user->ID)) {
            return $args;
        }

        // SC-682: refuse a token the browser did not submit from the
        // panel's own origin, and do it BEFORE validate_token(), so a refused
        // submission never reserves (burns) the nonce. See request_is_same_origin().
        if (!$this->request_is_same_origin()) {
            rcube::raise_error([
                'code' => 403,
                'message' => 'SSO: token submission rejected, request is not same-origin',
            ], true, false);
            return $args;
        }

        // Validate the token (single-use nonce enforced in reserve_nonce()).
        $email = $this->validate_token($token);
        if ($email === null) {
            rcube::raise_error([
                'code' => 403,
                'message' => 'SSO: Invalid or expired token',
            ], true, false);
            return $args;
        }

        // Only a validated token reaches this point. Arm both flags BEFORE
        // login(), because the first storage_connect fires inside login().
        $this->sso_active = true;
        $_SESSION['shcp_sso_active'] = true;

        // Roundcube 1.6 exposes the IMAP host as 'imap_host'. 'default_host'
        // does not exist in 1.6 and returns null.
        $host = $rcmail->config->get('imap_host');
        if (is_array($host)) {
            $host = array_key_first($host);
        }

        // Authenticate. The password is empty; the storage_connect hook injects
        // the master credential (SASL PLAIN, authzid = $email).
        if ($rcmail->login($email, '', $host)) {
            // Mirror the post-login sequence of Roundcube's own login paths
            // (index.php, program/actions/login/oauth.php), in the same order
            // and only AFTER login() succeeded: drop the pre-auth 'temp' marker,
            // rotate the session id, and set the roundcube_sessauth cookie.
            // Two reasons, both load-bearing:
            //   - Session fixation: a planted anonymous roundcube_sessid must
            //     not survive the move to an authenticated session. Rotating
            //     before login() would leave the id that becomes authenticated
            //     unrotated.
            //   - Without set_auth_cookie() the redirected 'mail' request has no
            //     roundcube_sessauth cookie, so rcube_session::check_auth()
            //     fails, kill_session() fires, and the user is bounced to login.
            $rcmail->session->remove('temp');
            $rcmail->session->regenerate_id(false);
            $rcmail->session->set_auth_cookie();

            // Record the login in the userlogins log (log_logins) like a form
            // login, so SSO sessions are not invisible to the operator.
            $rcmail->log_login();

            // Only a signature-verified, nonce-consumed parent handoff and successful mail login reach this hook.
            $rcmail->plugins->exec_hook('shcp_sso_authenticated', ['email'=>$email, 'dav_ticket'=>$this->dav_ticket]);
            $this->dav_ticket = null;

            // Let plugins adjust the post-login target (e.g. password's
            // forced-change redirect), exactly as index.php/oauth.php do.
            $redir = $rcmail->plugins->exec_hook('login_after', ['_task' => 'mail']);
            unset($redir['abort'], $redir['_err']);

            $rcmail->output->redirect($redir, 0, true);
            exit;
        }

        // Login failed: disarm so no later hook in this request injects into a
        // non-SSO context.
        $this->sso_active = false;
        unset($_SESSION['shcp_sso_active']);

        rcube::raise_error([
            'code' => 403,
            'message' => 'SSO: Authentication failed for ' . $email,
        ], true, false);

        return $args;
    }

    /**
     * SC-682: true only when the browser says this POST came from the
     * panel's own origin.
     *
     * This startup hook runs before Roundcube's request_security_check(), so
     * Roundcube's CSRF token never covers it. Without this check a page on any
     * other site can auto-submit a token the attacker minted for THEIR OWN
     * mailbox, and the victim's browser ends up logged into the attacker's
     * mailbox (login CSRF): whatever the victim writes or files there, the
     * attacker reads. The signature and the nonce cannot tell the two apart; they
     * prove the token is genuine, not who submitted it.
     *
     *   1. Sec-Fetch-Site present: it must be "same-origin". Every current
     *      browser sends it, and page script cannot set or forge it.
     *   2. Sec-Fetch-Site absent (older browsers): Origin must be https on the
     *      default port, with a host the panel vhost answers to. The panel sends
     *      Referrer-Policy strict-origin-when-cross-origin, and a browser sends
     *      Origin on every POST under that policy.
     *   3. Neither header: reject. A browser always sends one of them on a form
     *      POST, so a request with neither is not the panel's hand-off form.
     *
     * The host cannot be read off this request. Roundcube is two proxies deep
     * (Apache :443, then shcpd on loopback), and shcpd rewrites Host and
     * X-Forwarded-Host to its own loopback listener before PHP sees them. So the
     * installer writes the panel's names into $config['shcp_sso_panel_hosts'].
     */
    private function request_is_same_origin(): bool
    {
        $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null;
        if (is_string($site) && $site !== '') {
            return $site === 'same-origin';
        }

        $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
        if (!is_string($origin) || $origin === '') {
            return false;
        }

        // A serialized origin is scheme://host[:port] and nothing else. "null"
        // (opaque origin) has no scheme and fails here.
        $parts = parse_url($origin);
        if (!is_array($parts)
            || strtolower($parts['scheme'] ?? '') !== 'https'
            || !isset($parts['host']) || $parts['host'] === ''
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['path']) || isset($parts['query']) || isset($parts['fragment'])
            || (isset($parts['port']) && $parts['port'] !== 443)) {
            return false;
        }

        // parse_url() keeps the brackets on an IPv6 literal, matching how the
        // installer writes one.
        $host = strtolower($parts['host']);
        $allowed = rcmail::get_instance()->config->get('shcp_sso_panel_hosts');
        if (!is_array($allowed)) {
            return false;
        }

        foreach ($allowed as $name) {
            if (is_string($name) && $name !== '' && strtolower($name) === $host) {
                return true;
            }
        }

        return false;
    }

    /**
     * storage_connect hook: inject the Dovecot master credential for a
     * validated SSO session so IMAP authenticates as authzid = the mailbox user.
     */
    public function inject_imap_auth(array $args): array
    {
        if (!$this->sso_session_active()) {
            return $args;
        }

        $cred = $this->read_master_credential();
        if ($cred === null) {
            return $args;
        }

        [$master_user, $master_pass] = $cred;

        // auth_type = PLAIN is load-bearing: only the PLAIN branch of
        // rcube_imap_generic::authenticate() carries the authzid. LOGIN and the
        // auto-selected CRAM-MD5 drop it. auth_cid/auth_pw become the master
        // identity; 'user' stays the mailbox user (the authzid). 'pass' is
        // overridden too, or rcube_imap_generic::connect() rejects the empty
        // session password before authentication ("Empty password").
        $args['auth_type'] = 'PLAIN';
        $args['auth_cid']  = $master_user;
        $args['auth_pw']   = $master_pass;
        $args['pass']      = $master_pass;

        return $args;
    }

    /**
     * smtp_connect hook: inject the master credential for a validated SSO
     * session so submission authenticates as authzid = the mailbox user.
     */
    public function inject_smtp_auth(array $args): array
    {
        if (!$this->sso_session_active()) {
            return $args;
        }

        $cred = $this->read_master_credential();
        if ($cred === null) {
            return $args;
        }

        [$master_user, $master_pass] = $cred;

        // smtp_user stays '%u' (rcube_smtp resolves it to the session user and
        // uses it as the authzid); auth_cid/auth_pw are the master. PLAIN again:
        // Net_SMTP only carries the authzid on PLAIN.
        $args['smtp_auth_type'] = 'PLAIN';
        $args['smtp_auth_cid']  = $master_user;
        $args['smtp_auth_pw']   = $master_pass;

        return $args;
    }

    /**
     * managesieve_connect hook: inject the master credential for a validated
     * SSO session so Settings -> Filters authenticates as authzid = the mailbox
     * user. rcube_sieve swaps username<->auth_cid and uses auth_pw in place of
     * the (empty) session password; PLAIN is what carries the authzid.
     */
    public function inject_sieve_auth(array $args): array
    {
        if (!$this->sso_session_active()) {
            return $args;
        }

        $cred = $this->read_master_credential();
        if ($cred === null) {
            return $args;
        }

        [$master_user, $master_pass] = $cred;

        $args['auth_type'] = 'PLAIN';
        $args['auth_cid']  = $master_user;
        $args['auth_pw']   = $master_pass;

        return $args;
    }

    /**
     * True only when the current request or session passed SSO validation.
     */
    private function sso_session_active(): bool
    {
        return $this->sso_active || !empty($_SESSION['shcp_sso_active']);
    }

    /**
     * Read the SSO master user and password from the root-owned sidecar named
     * by $config['shcp_sso_master_file'] (two lines: user, then password).
     *
     * The master password is never stored in the session or in config.inc.php;
     * it is read from the sidecar at request time. Any failure returns null and
     * injects nothing, so a missing credential fails the SSO login closed
     * rather than silently connecting without proxy auth.
     *
     * @return array{0: string, 1: string}|null
     */
    private function read_master_credential(): ?array
    {
        $rcmail = rcmail::get_instance();
        $file = $rcmail->config->get('shcp_sso_master_file');

        if (empty($file) || !is_readable($file)) {
            rcube::raise_error([
                'code' => 500,
                'message' => 'SSO: master credential sidecar unavailable',
            ], true, false);
            return null;
        }

        $raw = file_get_contents($file);
        if ($raw === false) {
            rcube::raise_error([
                'code' => 500,
                'message' => 'SSO: master credential sidecar unreadable',
            ], true, false);
            return null;
        }

        $lines = explode("\n", trim($raw));
        $user = isset($lines[0]) ? trim($lines[0]) : '';
        $pass = isset($lines[1]) ? trim($lines[1]) : '';

        if ($user === '' || $pass === '') {
            rcube::raise_error([
                'code' => 500,
                'message' => 'SSO: master credential sidecar malformed',
            ], true, false);
            return null;
        }

        return [$user, $pass];
    }

    /**
     * Validate SSO token and return email address if valid.
     *
     * Token format: base64(json_payload) "." hex(ed25519_signature), where the
     * signature covers SIGNATURE_CONTEXT . base64(json_payload).
     *
     * installer#914: this plugin holds only the panel's PUBLIC key and can only
     * verify. There is deliberately no other way in: no shared secret, no HMAC
     * fallback. Anyone who reads this config can check a token but never make one.
     */
    private function validate_token(string $token): ?string
    {
        $rcmail = rcmail::get_instance();

        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            rcube::raise_error([
                'code' => 500,
                'message' => 'SSO: PHP sodium extension not loaded, cannot verify tokens',
            ], true, false);
            return null;
        }

        $configured = $rcmail->config->get('shcp_sso_public_key');
        $public_key = is_string($configured) ? base64_decode($configured, true) : false;
        if ($public_key === false || strlen($public_key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            rcube::raise_error([
                'code' => 500,
                'message' => 'SSO: shcp_sso_public_key not configured or malformed',
            ], true, false);
            return null;
        }

        // Split token into payload and signature
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            return null;
        }

        [$encoded_payload, $signature] = $parts;

        // Exactly one 64-byte signature in lowercase hex, checked before hex2bin
        // and sodium see it: both throw on malformed input, and a thrown error
        // here would be a 500, not a rejection.
        $valid = false;
        if ($encoded_payload !== '' && preg_match('/\A[0-9a-f]{128}\z/', $signature) === 1) {
            try {
                $valid = sodium_crypto_sign_verify_detached(
                    (string) hex2bin($signature),
                    self::SIGNATURE_CONTEXT . $encoded_payload,
                    $public_key
                );
            } catch (SodiumException $e) {
                $valid = false;
            }
        }
        if (!$valid) {
            rcube::raise_error([
                'code' => 403,
                'message' => 'SSO: Invalid token signature',
            ], true, false);
            return null;
        }

        // Decode payload
        $payload = base64_decode($encoded_payload, true);
        if ($payload === false) {
            return null;
        }

        // Parse JSON payload
        $data = json_decode($payload, true);
        if (!is_array($data)) {
            return null;
        }

        // Validate required fields
        if (empty($data['email']) || empty($data['exp']) || empty($data['nonce'])) {
            return null;
        }

        // Validate nonce format (32 hex characters = 16 random bytes)
        if (!preg_match('/^[a-f0-9]{32}$/', $data['nonce'])) {
            return null;
        }

        // Check expiration
        if ($data['exp'] < time()) {
            rcube::raise_error([
                'code' => 403,
                'message' => 'SSO: Token expired',
            ], true, false);
            return null;
        }

        // Validate email format
        $email = $data['email'];
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return null;
        }

        // SC-241/SC-569: reserve the nonce with one database INSERT. Roundcube's
        // non-indexed cache defers set() until shutdown, so get()+set() — even under
        // flock — lets two PHP processes accept the same token before either cache
        // record reaches cache_shared. The table's cache_key primary key is the lock:
        // exactly one concurrent INSERT can affect a row.
        if (!$this->reserve_nonce($data['nonce'], (int) $data['exp'])) {
            return null;
        }

        // Optional child capability is independently verified/redeemed by the panel; never read it from POST directly.
        $this->dav_ticket = isset($data['dav_ticket']) && is_string($data['dav_ticket']) && strlen($data['dav_ticket']) <= 8192 ? $data['dav_ticket'] : null;
        return $email;
    }

    /**
     * Atomically reserve a token nonce in Roundcube's shared-cache table.
     *
     * Any database/configuration failure rejects authentication. A replay guard
     * cannot safely degrade to accepting the token it failed to record.
     */
    private function reserve_nonce(string $nonce, int $expires): bool
    {
        $rcmail = rcmail::get_instance();
        $db = $rcmail->get_dbh();

        if (!$db) {
            rcube::raise_error([
                'code' => 500,
                'message' => 'SSO: nonce reservation database unavailable',
            ], true, false);
            return false;
        }

        $table = $db->table_name('cache_shared', true);
        $provider = $db->db_provider ?? '';

        // Roundcube supports several SQL drivers. Each statement has identical
        // insert-if-absent semantics and leaves affected_rows() at zero when the
        // cache_key primary key already exists.
        if ($provider === 'sqlite') {
            $sql = "INSERT OR IGNORE INTO {$table} (`cache_key`, `expires`, `data`) VALUES (?, ?, ?)";
        } elseif ($provider === 'mysql') {
            $sql = "INSERT IGNORE INTO {$table} (`cache_key`, `expires`, `data`) VALUES (?, ?, ?)";
        } elseif ($provider === 'postgres') {
            // Emit native PostgreSQL identifiers here. Do not depend on a test
            // adapter (or a future DB wrapper) rewriting MySQL-style backticks.
            $sql = "INSERT INTO {$table} (\"cache_key\", \"expires\", \"data\") VALUES (?, ?, ?) ON CONFLICT (\"cache_key\") DO NOTHING";
        } else {
            rcube::raise_error([
                'code' => 500,
                'message' => 'SSO: nonce reservation unsupported database provider',
            ], true, false);
            return false;
        }

        $nonce_key = 'shcp_sso.n_' . $nonce;
        $encoded = $db->encode(true, true);
        // SQLite/MySQL store a timezone-less datetime and compare it with their
        // own UTC/current-time expressions. PostgreSQL's cache_shared.expires is
        // timestamptz: give it an explicit offset so a non-UTC database session
        // cannot reinterpret the nonce deadline and garbage-collect it early.
        $expires_at = $provider === 'postgres'
            ? gmdate('Y-m-d H:i:s+00:00', $expires)
            : gmdate('Y-m-d H:i:s', $expires);
        $result = $db->query($sql, $nonce_key, $expires_at, $encoded);

        if ($result === false || $db->is_error($result)) {
            rcube::raise_error([
                'code' => 500,
                'message' => 'SSO: nonce reservation database write failed',
            ], true, false);
            return false;
        }

        if ($db->affected_rows($result) !== 1) {
            rcube::raise_error([
                'code' => 403,
                'message' => 'SSO: token replay rejected (nonce already used)',
            ], true, false);
            return false;
        }

        return true;
    }
}

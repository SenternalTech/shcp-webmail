<?php

/**
 * SHCP password driver for Roundcube's bundled `password` plugin.
 *
 * Roundcube resolves a driver as plugins/password/drivers/<password_driver>.php
 * holding a class named rcube_<password_driver>_password. The installer links
 * this file in as drivers/shcp.php and sets $config['password_driver'] = 'shcp'.
 *
 * The driver owns no password storage of its own. It POSTs the change to the
 * panel's loopback internal API, which is the only component that knows how
 * mailbox credentials are stored:
 *
 *   POST /api/internal/mail/password
 *   X-Internal-Token: <shared secret>
 *   {"username": "...", "curpass": "...", "newpass": "..."}
 *   -> 200 {"success": true,  "message": "..."}
 *   -> 400 {"success": false, "message": "..."}  bad credentials / policy / malformed
 *   -> 403 {"success": false, "message": "..."}  forbidden / disabled / suspended
 *
 * This replaces a much worse arrangement: the pre-migration driver ran an
 * UPDATE straight against the panel's database. Keeping the write behind the
 * panel means Roundcube never needs credentials for, or a path to, the panel's
 * datastore.
 *
 * Two deliberate implementation choices, both non-obvious:
 *
 *  1. No curl. The PHP-FPM pool that serves Roundcube sets
 *     php_admin_value[disable_functions] with curl_exec and curl_multi_exec in
 *     it, and php_admin_value cannot be lifted at runtime. Anything built on
 *     curl — including Roundcube's bundled Guzzle when it picks the curl
 *     handler — is simply unavailable here. The request is therefore spoken
 *     directly over a socket. HTTP/1.0 is used on purpose: it forbids chunked
 *     transfer-encoding, so reading to EOF is guaranteed to yield the whole
 *     body with no de-chunking code to get wrong.
 *
 *  2. The shared secret is read from a root-owned file at request time, never
 *     from Roundcube's config. Roundcube's config.inc.php is owned by the web
 *     user; a secret placed there is readable AND rewritable by anything that
 *     compromises Roundcube. The sidecar is root-owned and group-readable by
 *     the web group only, so the web user can read the token but cannot alter
 *     it, relax its mode, or swap the file.
 *
 * @author Senternal LLC
 * @license MIT
 */
class rcube_shcp_password
{
    /**
     * Fallbacks only. The installer writes the real values into
     * config.inc.php (shcp_password_endpoint / shcp_password_token_file) so
     * that config.sh stays the single source of truth for both.
     */
    private const DEFAULT_ENDPOINT = 'https://127.0.0.1:4650/api/internal/mail/password';
    private const DEFAULT_TOKEN_FILE = '/etc/shcp-roundcube/internal-token';

    /**
     * Bounded end to end: at most CONNECT_TIMEOUT to establish the connection
     * (TLS handshake included, since stream_socket_client does it inline) and
     * at most READ_TIMEOUT for the whole response, enforced against a deadline
     * rather than per-read so a trickling peer cannot extend it indefinitely.
     * A panel that is down or wedged therefore fails fast and visibly instead
     * of hanging a webmail request until FPM's request_terminate_timeout.
     */
    private const CONNECT_TIMEOUT = 5;
    private const READ_TIMEOUT = 15;

    /** Don't buffer a runaway response; the real one is a few hundred bytes. */
    private const MAX_RESPONSE_BYTES = 65536;

    /** Panel-side policy, mirrored for fast local feedback. See check_strength(). */
    private const MIN_LENGTH = 8;
    private const MAX_LENGTH = 128;

    /**
     * Strength hook. The `password` plugin calls this before save() when
     * password_minimum_score is set, and shows our reason next to its own
     * "too weak" text.
     *
     * This mirrors the panel's policy rather than deferring to it, for one
     * concrete reason: the endpoint is rate-limited to 10 requests per 5
     * minutes. Without a local check, a user fumbling the rules a few times
     * burns the whole budget and then gets a generic failure for five minutes.
     * The panel stays authoritative — this only shortcuts the obvious cases.
     *
     * @param string $passwd Proposed new password
     *
     * @return array{0:int,1:string} [score, reason]
     */
    public function check_strength($passwd)
    {
        $reason = $this->policy_violation((string) $passwd);

        if ($reason !== null) {
            return [1, $reason];
        }

        return [5, ''];
    }

    /**
     * Password comparison hook. Defining this method overrides the `password`
     * plugin's own comparisons, and it exists for exactly one reason.
     *
     * Roundcube checks the submitted current password by string-comparing it
     * against the password it stashed in the session at login. After an SSO
     * login (see the shcp_sso plugin, which authenticates with an empty
     * password) nothing was stashed, so that comparison can only ever fail —
     * every SSO session would be told "current password is incorrect" and
     * could never change its password at all. Since "Open Webmail" in the
     * panel is the normal way users arrive here, that is not an edge case.
     *
     * When there IS a stashed password this reproduces upstream's behaviour
     * exactly, localised text included: catching a typo locally is worth
     * keeping, because the endpoint's rate limit is 10 requests / 5 minutes and
     * a user who fumbles their current password should not burn that budget.
     * When there is not, the check is skipped rather than faked — the panel
     * verifies the current password server-side on every request regardless, so
     * nothing is actually being trusted here that the panel does not re-check.
     *
     * @param string $curpass Session password (may be empty), or the current
     *                        password when checking the new one
     * @param string $newpass Password to compare against
     * @param int    $type    PASSWORD_COMPARE_CURRENT or PASSWORD_COMPARE_NEW
     *
     * @return string|null Error message, or null when the comparison passes
     */
    public function compare($curpass, $newpass, $type)
    {
        if ($type === PASSWORD_COMPARE_CURRENT) {
            if ((string) $curpass === '') {
                return null;
            }

            return $curpass !== $newpass
                ? $this->text('passwordincorrect', 'The current password is incorrect.')
                : null;
        }

        if ($type === PASSWORD_COMPARE_NEW) {
            return $curpass === $newpass
                ? $this->text('samepasswd', 'The new password must differ from the current one.')
                : null;
        }

        return $this->text('internalerror', 'Could not save the new password.');
    }

    /**
     * Change the mailbox password via the panel.
     *
     * @param string $curpass  Current password (already verified against the
     *                         session password by the password plugin)
     * @param string $newpass  New password
     * @param string $username Mailbox login (full email address for SHCP)
     *
     * @return int|array PASSWORD_* constant, or ['code' => PASSWORD_*, 'message' => string]
     */
    public function save($curpass, $newpass, $username = '')
    {
        if ($username === null || $username === '') {
            $username = isset($_SESSION['username']) ? $_SESSION['username'] : '';
        }

        if ($username === '') {
            $this->log_error('no mailbox username available for the password change');

            return PASSWORD_ERROR;
        }

        $rcmail = rcmail::get_instance();

        $token = $this->read_token((string) $rcmail->config->get('shcp_password_token_file', self::DEFAULT_TOKEN_FILE));
        if ($token === null) {
            return [
                'code' => PASSWORD_ERROR,
                'message' => 'Password changes are not configured on this server. Please contact your administrator.',
            ];
        }

        $target = $this->parse_endpoint((string) $rcmail->config->get('shcp_password_endpoint', self::DEFAULT_ENDPOINT));
        if ($target === null) {
            return [
                'code' => PASSWORD_ERROR,
                'message' => 'Password changes are misconfigured on this server. Please contact your administrator.',
            ];
        }

        // JSON, not form encoding: json_encode escapes every control character
        // and quote, so no password can break out of the body and forge extra
        // headers or a second request.
        $payload = json_encode([
            'username' => (string) $username,
            'curpass' => (string) $curpass,
            'newpass' => (string) $newpass,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if (!is_string($payload)) {
            $this->log_error('could not encode the password-change request body');

            return PASSWORD_ERROR;
        }

        $raw = $this->post($target, $token, $payload);

        // Unreachable, wedged, or timed out. PASSWORD_CONNECT_ERROR is the
        // point of this branch: Roundcube renders it as a connection failure,
        // so the user is told to retry instead of being told their current
        // password was wrong.
        if ($raw === null) {
            return [
                'code' => PASSWORD_CONNECT_ERROR,
                'message' => 'The control panel did not respond. Please try again in a few minutes.',
            ];
        }

        return $this->interpret($raw);
    }

    /**
     * Map the panel's HTTP response onto the plugin's result codes.
     *
     * @param string $raw Full response (status line, headers, body)
     *
     * @return int|array
     */
    private function interpret($raw)
    {
        $split = explode("\r\n\r\n", $raw, 2);
        $head = $split[0];
        $body = isset($split[1]) ? $split[1] : '';

        if (!preg_match('#^HTTP/\d(?:\.\d)?[ \t]+(\d{3})#', $head, $m)) {
            $this->log_error('unparseable response from the panel password endpoint');

            return [
                'code' => PASSWORD_CONNECT_ERROR,
                'message' => 'The control panel returned an unexpected response. Please try again in a few minutes.',
            ];
        }

        $status = (int) $m[1];
        $data = json_decode($body, true);
        $message = '';

        if (is_array($data) && isset($data['message']) && is_string($data['message'])) {
            $message = $this->sanitize_message($data['message']);
        }

        if ($status === 200 && is_array($data) && !empty($data['success'])) {
            return PASSWORD_SUCCESS;
        }

        // 400 and 403 both carry an actionable, panel-authored explanation
        // (which rule was broken, or that the mailbox is disabled/suspended).
        // Both map to PASSWORD_ERROR rather than PASSWORD_CONSTRAINT_VIOLATION
        // on purpose: the contract has no machine-readable error code, so a 400
        // could be a policy rejection OR a stale current password (the session
        // password can go stale if the mailbox was changed elsewhere after
        // login). Claiming "does not comply with the password policy" in the
        // second case would be a confident lie; PASSWORD_ERROR's neutral prefix
        // plus the panel's own sentence is true in both. Add the constraint
        // mapping here if the endpoint ever grows an error-code field.
        if ($status === 400 || $status === 403) {
            return [
                'code' => PASSWORD_ERROR,
                'message' => $message !== '' ? $message : 'The control panel rejected the password change.',
            ];
        }

        if ($status === 429) {
            return [
                'code' => PASSWORD_ERROR,
                'message' => $message !== ''
                    ? $message
                    : 'Too many password-change attempts. Please wait a few minutes and try again.',
            ];
        }

        $this->log_error(sprintf('panel password endpoint returned HTTP %d', $status));

        return [
            'code' => PASSWORD_CONNECT_ERROR,
            'message' => 'The control panel could not process the request. Please try again in a few minutes.',
        ];
    }

    /**
     * Speak one HTTP/1.0 request over a socket and return the raw response.
     *
     * @param array  $target  Output of parse_endpoint()
     * @param string $token   Shared secret for X-Internal-Token
     * @param string $payload JSON request body
     *
     * @return string|null null on connect failure, write failure, or timeout
     */
    private function post(array $target, $token, $payload)
    {
        $context = stream_context_create([
            'ssl' => [
                // The panel is addressed over loopback by IP and presents its
                // own self-signed certificate, so peer verification can never
                // succeed and is not what protects this call — the loopback
                // interface and the shared secret are. Same posture the
                // installer already uses for the panel's DAV endpoint.
                'verify_peer' => false,
                'verify_peer_name' => false,
                // An IP literal is not a legal SNI value; omit the extension
                // (this is what curl does for IP hosts).
                'SNI_enabled' => false,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $remote = $target['transport'] . '://' . $target['host'] . ':' . $target['port'];

        $fp = @stream_socket_client(
            $remote,
            $errno,
            $errstr,
            self::CONNECT_TIMEOUT,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!is_resource($fp)) {
            $this->log_error(sprintf('cannot reach the panel at %s: %s (%d)', $remote, $errstr, $errno));

            return null;
        }

        $request = 'POST ' . $target['path'] . " HTTP/1.0\r\n"
            . 'Host: ' . $target['host'] . ':' . $target['port'] . "\r\n"
            . "User-Agent: shcp-roundcube-password\r\n"
            . "Accept: application/json\r\n"
            . "Content-Type: application/json\r\n"
            . 'Content-Length: ' . strlen($payload) . "\r\n"
            . 'X-Internal-Token: ' . $token . "\r\n"
            . "Connection: close\r\n"
            . "\r\n"
            . $payload;

        stream_set_timeout($fp, self::CONNECT_TIMEOUT);

        if (fwrite($fp, $request) === false) {
            fclose($fp);
            $this->log_error('failed to send the password-change request to the panel');

            return null;
        }

        // Deadline-bounded read. stream_set_timeout applies per read, so a peer
        // that dribbles one byte per timeout window would otherwise keep the
        // request alive forever.
        $deadline = microtime(true) + self::READ_TIMEOUT;
        $raw = '';
        $timed_out = false;

        while (!feof($fp)) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                $timed_out = true;
                break;
            }

            stream_set_timeout($fp, (int) max(1, ceil($remaining)));
            $chunk = fread($fp, 8192);

            if ($chunk === false) {
                break;
            }

            $meta = stream_get_meta_data($fp);
            if (!empty($meta['timed_out'])) {
                $timed_out = true;
                break;
            }

            $raw .= $chunk;

            if (strlen($raw) >= self::MAX_RESPONSE_BYTES) {
                break;
            }
        }

        fclose($fp);

        if ($timed_out || $raw === '') {
            $this->log_error(sprintf('no usable response from the panel at %s within %ds', $remote, self::READ_TIMEOUT));

            return null;
        }

        return $raw;
    }

    /**
     * Read the internal-API shared secret from its root-owned sidecar.
     *
     * @param string $path Absolute path to the token file
     *
     * @return string|null null when absent, unreadable, or implausible
     */
    private function read_token($path)
    {
        if ($path === '' || !is_readable($path)) {
            $this->log_error(sprintf('internal-API token file is missing or unreadable: %s', $path));

            return null;
        }

        $token = file_get_contents($path);
        if (!is_string($token)) {
            $this->log_error(sprintf('could not read the internal-API token file: %s', $path));

            return null;
        }

        // The installer writes the secret with a trailing newline.
        $token = trim($token);

        // The token goes into a request header verbatim, so anything that could
        // terminate a header line must be refused rather than sanitised: a
        // CR/LF in here would let a corrupted secret file forge headers or a
        // second request. Printable ASCII with no whitespace is what a valid
        // header value looks like, and is a superset of what the credential
        // store generates (32 alphanumerics).
        if (!preg_match('/\A[\x21-\x7e]{16,512}\z/', $token)) {
            $this->log_error(sprintf('internal-API token in %s is empty or malformed; refusing to use it', $path));

            return null;
        }

        return $token;
    }

    /**
     * Split the configured endpoint into socket-level parts.
     *
     * @param string $url Configured endpoint URL
     *
     * @return array|null null when the URL is unusable
     */
    private function parse_endpoint($url)
    {
        $parts = parse_url($url);

        if (!is_array($parts) || empty($parts['host'])) {
            $this->log_error(sprintf('password endpoint is not a usable URL: %s', $url));

            return null;
        }

        $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : 'https';

        if ($scheme === 'https') {
            $transport = 'ssl';
            $port = 443;
        } elseif ($scheme === 'http') {
            $transport = 'tcp';
            $port = 80;
        } else {
            $this->log_error(sprintf('password endpoint scheme is not http(s): %s', $url));

            return null;
        }

        if (!empty($parts['port'])) {
            $port = (int) $parts['port'];
        }

        $path = (isset($parts['path']) && $parts['path'] !== '') ? $parts['path'] : '/';
        if (isset($parts['query']) && $parts['query'] !== '') {
            $path .= '?' . $parts['query'];
        }

        // Host and path are pasted into the request line and the Host header.
        // parse_url already rejects most junk, but a config file is editable by
        // the web user, so re-check rather than trust it.
        if (preg_match('/[^A-Za-z0-9._:\[\]-]/', $parts['host']) || preg_match('/[^\x21-\x7e]/', $path)) {
            $this->log_error(sprintf('password endpoint has illegal characters: %s', $url));

            return null;
        }

        return [
            'transport' => $transport,
            'host' => $parts['host'],
            'port' => $port,
            'path' => $path,
        ];
    }

    /**
     * Local mirror of the panel's password policy.
     *
     * The character-class rules are Unicode-aware on purpose. Being LAXER than
     * the panel is harmless — the panel rejects and its own message is shown.
     * Being STRICTER would refuse a password the panel would have accepted,
     * with no way for the user to tell who was wrong.
     *
     * @param string $passwd Proposed new password
     *
     * @return string|null Human-readable reason, or null when compliant
     */
    private function policy_violation($passwd)
    {
        if (preg_match('/[\x00-\x1f\x7f]/', $passwd)) {
            return 'Control characters are not allowed.';
        }

        $length = function_exists('mb_strlen') ? mb_strlen($passwd, 'UTF-8') : strlen($passwd);

        if ($length < self::MIN_LENGTH) {
            return sprintf('Use at least %d characters.', self::MIN_LENGTH);
        }

        if ($length > self::MAX_LENGTH) {
            return sprintf('Use at most %d characters.', self::MAX_LENGTH);
        }

        // preg_match with /u returns false on invalid UTF-8; in that case defer
        // to the panel instead of guessing at the character classes.
        if (preg_match('//u', $passwd) !== 1) {
            return null;
        }

        if (!preg_match('/\p{Lu}/u', $passwd)) {
            return 'Include at least one uppercase letter.';
        }

        if (!preg_match('/\p{Ll}/u', $passwd)) {
            return 'Include at least one lowercase letter.';
        }

        if (!preg_match('/\p{Nd}/u', $passwd)) {
            return 'Include at least one digit.';
        }

        return null;
    }

    /**
     * Make a panel-authored message safe to hand back to the UI.
     *
     * The panel is trusted, but its message may quote user input, and it is
     * appended to a string Roundcube may render as HTML. Tags are stripped
     * rather than entity-encoded so the text reads correctly whether Roundcube
     * treats it as markup or as plain text.
     *
     * @param string $message Message from the panel
     *
     * @return string
     */
    private function sanitize_message($message)
    {
        $message = strip_tags($message);
        $message = preg_replace('/[\x00-\x1f\x7f]+/', ' ', $message);
        $message = trim((string) $message);

        if (function_exists('mb_substr')) {
            return mb_substr($message, 0, 300, 'UTF-8');
        }

        return substr($message, 0, 300);
    }

    /**
     * Resolve one of the `password` plugin's own localised labels, so an
     * overridden comparison still speaks the user's language.
     *
     * rcube::gettext answers "[key]" for a label it doesn't know, which would
     * be a visible regression on the common "you mistyped it" path — fall back
     * to plain English rather than showing brackets.
     *
     * @param string $key      Label name within the password plugin's domain
     * @param string $fallback Text to use when the label is unavailable
     *
     * @return string
     */
    private function text($key, $fallback)
    {
        $text = (string) rcmail::get_instance()->gettext('password.' . $key);

        if ($text === '' || $text[0] === '[') {
            return $fallback;
        }

        return $text;
    }

    /**
     * Log to Roundcube's error log. Never include the request body, the
     * password material, or the token in these messages.
     *
     * @param string $message What went wrong
     */
    private function log_error($message)
    {
        rcube::raise_error([
            'code' => 600,
            'file' => __FILE__,
            'line' => __LINE__,
            'message' => 'shcp password driver: ' . $message,
        ], true, false);
    }
}

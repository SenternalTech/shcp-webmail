# SHCP webmail login limiter

Password login failures are counted for five minutes in `shcp-login-attempts.sqlite` under Roundcube's `temp_dir`. The plugin hard limits ten failures from one client and ten failures for one account/client pair. A global account count adds one second of delay for each three failures, capped at three seconds; it never refuses a correct password from a new client. Expired counters are removed on checks and failures. If storage cannot be used or its bounded capacity is reached, password login fails closed.

The client is the immediate peer unless it matches `shcp_login_trusted_proxies` and supplies the configured `shcp_login_proxy_secret`. Only then does the plugin parse X-Forwarded-For, walking from the nearest proxy to the first untrusted address. Proxy declarations accept exact IPv4/IPv6 addresses or CIDRs.

After a successful password login, the plugin issues an HMAC-signed `shcp_login_success` cookie for that account and client, valid for one day. It is Secure, HttpOnly, SameSite=Lax, and scoped to the webmail script directory. The cookie skips only the global account delay; client and account/client hard limits still apply. The proxy secret is also the HMAC key, with a separate signing context. If no secret is configured, no bypass cookie is issued. Rotating the secret invalidates existing cookies.

SSO token logins do not use the password limiter. Throttle and storage failures are logged with the resolved client address.

## SSO hand-off origin (SC-682)

A token is accepted only from a POST the panel's hand-off page made. Which POSTs count depends on whether webmail still shares the panel's host:

- **Same host (`shcp_sso_panel_origin` absent or null):** `Sec-Fetch-Site` must be `same-origin`. A browser that sends no `Sec-Fetch-Site` must send an https `Origin` whose host is in `shcp_sso_panel_hosts`.
- **Own host (`shcp_sso_panel_origin` set, e.g. `https://panel.example.com`):** `Sec-Fetch-Site`, when sent, must be `same-origin` or `same-site`, and `Origin` must equal the panel origin exactly. A tenant site on a sibling host is also `same-site`, so the exact `Origin` is what refuses it. A missing `Origin`, `Origin: null`, `cross-site` and `none` are refused.

Write the origin the way a browser serializes it: `https`, a lower-case host, and no `:443`. Any other value, `''` included, means webmail has moved but the origin is malformed, so every hand-off is refused rather than falling back to the same-host rule.

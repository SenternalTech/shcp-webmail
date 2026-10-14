# SHCP webmail login limiter

Password login failures are counted for five minutes in `shcp-login-attempts.sqlite` under Roundcube's `temp_dir`. The plugin hard limits ten failures from one client and ten failures for one account/client pair. A global account count adds one second of delay for each three failures, capped at three seconds; it never refuses a correct password from a new client. Expired counters are removed on checks and failures. If storage cannot be used or its bounded capacity is reached, password login fails closed.

The client is the immediate peer unless it matches `shcp_login_trusted_proxies` and supplies the configured `shcp_login_proxy_secret`. Only then does the plugin parse X-Forwarded-For, walking from the nearest proxy to the first untrusted address. Proxy declarations accept exact IPv4/IPv6 addresses or CIDRs.

After a successful password login, the plugin issues an HMAC-signed `shcp_login_success` cookie for that account and client, valid for one day. It is Secure, HttpOnly, SameSite=Lax, and scoped to the webmail script directory. The cookie skips only the global account delay; client and account/client hard limits still apply. The proxy secret is also the HMAC key, with a separate signing context. If no secret is configured, no bypass cookie is issued. Rotating the secret invalidates existing cookies.

SSO token logins do not use the password limiter. Throttle and storage failures are logged with the resolved client address.

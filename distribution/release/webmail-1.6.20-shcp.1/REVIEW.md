# webmail-1.6.20-shcp.1 source lock — review notes

DRAFT: waiting for the release authority (owner). The nine entries below have an empty `review`, so
`source-audit.php` refuses this lock until they are reviewed. The other 39 entries are byte-identical
to the approved webmail-1.6.19-shcp.1 lock (same source, notice, sha256 and review); see that
directory's REVIEW.md for their licence readings.

This release takes Roundcube's 1.6.20 security release (shcp-master#3915) and the shcp plugin
fixes merged since 1.6.19 (#11, #12, #13, #16, #17, #20).

## Entries to review

| Component | Was | Expression | Pinned commit |
|---|---|---|---|
| guzzlehttp/guzzle@7.16.0 | 7.15.5 | MIT | `ffb62ec78705` |
| guzzlehttp/promises@2.6.0 | 2.5.3 | MIT | `3d88c829bd5f` |
| guzzlehttp/psr7@2.13.2 | 2.13.1 | MIT | `adee536f9510` |
| mlocati/ip-lib@1.22.1 | 1.22.0 | MIT | `f096c0e9ec8b` |
| roundcube/roundcubemail@1.6.20 | 1.6.19 | GPL-3.0-or-later | `1dd910522e73` |
| shcp/shcp_dav@1 | 1 | MIT | `a5f4ef2648f6` |
| shcp/shcp_password@1 | 1 | MIT | `a5f4ef2648f6` |
| shcp/shcp_sso@1 | 1 | MIT | `a5f4ef2648f6` |
| symfony/polyfill-php80@v1.43.0 | v1.37.0 | MIT | `9c6a5d6b01ca` |

- **Licence expressions are unchanged** for every repinned component. The regeneration refuses
  a declared-licence change. Each notice is the same upstream file (`LICENSE`), taken from the new
  commit.
- **Upstream components:** the source is GitHub's archive of the commit that Composer's
  `installed.json` (or `inputs.json` `source_commit` for Roundcube) records in the 1.6.20 payload,
  never a tag. carddav's bundled guzzle 7.10.0, promises 2.3.0 and psr7 2.9.0 are unchanged.
- **shcp/\*** is pinned to `a5f4ef2648f6` (main on 2026-11-17, carrying shcp-webmail#21 and #22,
  which the installer's loopback-TLS floor `RCM_DAV_LOOPBACK_MIN_RELEASE=webmail-1.6.20-shcp.1`
  requires; shcp-master#4369). The `webmail-1.6.20-shcp.1` tag must be placed on that commit.
  The three source digests were regenerated; the three LICENSE notices are byte-identical to the
  draft's (same sha256), only their URLs moved.
- **kolab/net_ldap3** is unchanged. Its source is
  `git archive --format=tar --prefix=php-net_ldap3-5a319cf437d75aad564ce7fd076cc5423722868b/ 5a319cf4… | gzip -9n`
  of `https://git.kolab.org/diffusion/PNL/php-net_ldap3.git`, which reproduces sha256 `d2ffbf9d…`.
  Its notice is the GPLv3 text, byte-identical to Roundcube's `LICENSE` (`8ceb4b9e…`).

## Checked when drafted (2026-11-14)

- Assembled the pinned 1.6.20 inputs and took the inventory: 48 components, every one in this lock.
- Fetched every `source` and `notice` this lock names, verified each digest, and ran
  `source-audit.php PAYLOAD LOCK SOURCES OUT` with the empty reviews stubbed: it accepts all 48.
- Unstubbed, the audit refuses: `review absent: guzzlehttp/guzzle@7.16.0`. With one digest
  altered, it refuses: `Missing or modified source`.

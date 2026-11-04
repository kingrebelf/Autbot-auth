# Security notes

This is a development preview, not security-audited software. Do not deploy for real accounts until the open work and independent review are complete.

## Trust boundaries and operational requirements

The public HTTPS origin, exact client redirect URIs, SMTP account, signing keys, cookie keys, code HMAC secret, database, and app client secrets are security-sensitive. The database and configuration must be backed up together. The server assumes a single host with local SQLite storage; do not put its database on a network filesystem or scale it horizontally. Never trust arbitrary client-supplied forwarding headers: the included configuration assumes exactly one controlled proxy and no direct internet access to the Node process.

Only verified mailbox control creates an account. Email authentication depends on the security and availability of that mailbox and is not multi-factor authentication. ID tokens already accepted by an app and sessions created by apps cannot be remotely invalidated by the identity server. Disable them in the apps too.

## Remaining work before production

- Independently review OIDC adapter semantics, atomicity under concurrent requests, browser flows, session revocation and account-linking.
- Test the Docker/Caddy deployment and restore end to end on Linux using a real TLS SMTP server.
- Add IPv6-aware network limits, operational monitoring and alerts, request and mail-spend caps that cannot trivially deny service to everyone, and an incident response procedure.
- Add stronger authentication for administrative and sensitive accounts, a tested key rotation and compromise recovery procedure, and an audited migration strategy.
- Add schema migration/versioning and verify backup/restore across releases; current backup snapshots do not coordinate concurrent admin configuration changes.
- Review dependencies and deploy updates promptly; use HTTPS and secure backups.

Report suspected vulnerabilities privately to the repository owner rather than opening a public issue. A dedicated private reporting channel has not been configured yet.

# Security

This is an unreleased MVP; only the current main branch receives fixes. Report vulnerabilities privately through the repository's Security tab / private vulnerability reporting. If private reporting is unavailable, ask a maintainer to enable it without publishing exploit details or secrets.

Never include owner passwords, API tokens, reply tokens, webhook URLs/keys, production config, or database contents in an issue or log. Revoke exposed callers immediately and rotate exposed adapter credentials at the provider. Separate caller tokens from adapter credentials.

Self-hosters must provide HTTPS, restrict filesystem access, patch Node and dependencies, protect backups, and monitor resource usage. Bot text remains untrusted even after authentication. Prompt fencing is not a substitute for the receiving bot enforcing approval rules. An owner who consents to a malicious client grants that client the selected capabilities.

No automatic retention cleanup, distributed deployment, passkeys, or external identity provider integration is included. Do not expose the service until the owner password and bot opt-ins are configured. Put coarse request limits at your proxy; app-level wake budgets protect bot turns, not all forms of network denial of service.

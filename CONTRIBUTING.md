# Contributing

Keep changes small, typed, and boundary-validated. Open a PR with the behavior changed and how you tested it. Run typecheck, lint, isolated tests, build, and gitleaks before pushing. Use only fake secrets and loopback fixtures. Never add production configuration, bot identifiers, webhook credentials, or extra MCP tools.

New adapters implement the core Adapter interface and must preserve teammate-level authority, untrusted text handling, fixed callbacks, no credential forwarding, and no retries. Include a fake HTTP-server test. Do not deploy as part of contributing.
